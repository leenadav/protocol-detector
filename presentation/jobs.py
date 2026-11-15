"""Bounded asynchronous worker jobs with admission control (stage 6, A08).

Analysis and decryption run in short-lived worker subprocesses, as before; what changes is who waits. A
JobRunner admits at most `max_running` jobs at once and `max_queued` behind them, rejects the rest at once
(the caller answers 429), enforces a per-job lifetime, keeps a bounded number of finished outcomes for a
bounded time, and can be cancelled or shut down idempotently. Reading a job's state has no side effect.

States: queued -> running -> done | failed | cancelled | expired. Every terminal state carries a reason, so
an incomplete outcome is explicit rather than a request that never answered.
"""
import json
import secrets
import subprocess
import threading
import time
from collections import OrderedDict

STATES = ("queued", "running", "done", "failed", "cancelled", "expired")


class JobRunner:
    def __init__(self, command_factory, max_running=2, max_queued=4, lifetime=25.0, retain=32, retain_seconds=300.0,
                 clock=time.monotonic):
        if max_running < 1 or max_queued < 0 or lifetime <= 0 or retain < 1:
            raise ValueError("Invalid job runner limits")
        self.command_factory = command_factory      # (kind, payload) -> (argv, stdin bytes)
        self.max_running, self.max_queued = max_running, max_queued
        self.lifetime, self.retain, self.retain_seconds = lifetime, retain, retain_seconds
        self.clock = clock
        self.lock = threading.Condition()
        self.jobs = OrderedDict()                     # id -> job dict (the only copy; views are snapshots)
        self.queue = []                               # ids waiting for a slot
        self.running = {}                             # id -> Popen
        self.closed = False
        self.counts = {"submitted": 0, "rejected": 0, "done": 0, "failed": 0, "cancelled": 0, "expired": 0}

    # ----- admission -------------------------------------------------------------
    def submit(self, kind, payload=b""):
        """Admit a job or raise AdmissionError; never blocks on worker execution."""
        with self.lock:
            if self.closed:
                raise AdmissionError("The server is shutting down.")
            self._expire_retained()
            if len(self.queue) >= self.max_queued and len(self.running) >= self.max_running:
                self.counts["rejected"] += 1
                raise AdmissionError("Too many analyses in progress; retry in a moment.")
            job = {"id": secrets.token_urlsafe(12), "kind": kind, "state": "queued", "submitted": self.clock(),
                   "started": None, "finished": None, "reason": None, "result": None, "_payload": payload}
            self.jobs[job["id"]] = job
            self.queue.append(job["id"])
            self.counts["submitted"] += 1
            self._pump()
            return self.view(job)

    def _pump(self):
        """Start queued jobs while slots are free; the lock is held by the caller."""
        while self.queue and len(self.running) < self.max_running:
            job = self.jobs[self.queue.pop(0)]
            argv, stdin = self.command_factory(job["kind"], job.pop("_payload", b""))
            try:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)  # noqa: S603 - argv is a fixed worker command from worker_command(), never request data
            except OSError as error:
                self._finish(job, "failed", "worker could not start: " + error.__class__.__name__)
                continue
            job["state"], job["started"] = "running", self.clock()
            self.running[job["id"]] = process
            threading.Thread(target=self._run, args=(job["id"], process, stdin), daemon=True).start()

    def _run(self, job_id, process, stdin):
        output, reason, state = b"", None, "done"
        try:
            output, _ = process.communicate(stdin, timeout=self.lifetime)
            if process.returncode:
                state, reason = "failed", "worker exited with status %d" % process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            state, reason = "expired", "worker exceeded its %d second lifetime" % int(self.lifetime)
        with self.lock:
            job = self.jobs.get(job_id)
            self.running.pop(job_id, None)
            if job is not None and job["state"] == "running":
                if state == "done":
                    try:
                        result = json.loads(output)
                        if isinstance(result, dict) and "error" in result:
                            state, reason, result = "failed", str(result["error"])[:512], None
                    except ValueError:
                        state, reason, result = "failed", "worker returned no readable result", None
                    job["result"] = result
                self._finish(job, state, reason)
            self._pump()
            self.lock.notify_all()

    def _finish(self, job, state, reason):
        job["state"], job["reason"], job["finished"] = state, reason, self.clock()
        job.pop("_payload", None)
        self.counts[state] += 1
        while len([j for j in self.jobs.values() if j["state"] in ("done", "failed", "cancelled", "expired")]) > self.retain:
            for key, candidate in list(self.jobs.items()):
                if candidate["state"] not in ("queued", "running"):
                    del self.jobs[key]
                    break

    def _expire_retained(self):
        now = self.clock()
        for key, job in list(self.jobs.items()):
            if job["finished"] is not None and now - job["finished"] > self.retain_seconds:
                del self.jobs[key]

    # ----- reads and control ------------------------------------------------------
    @staticmethod
    def view(job, with_result=True):
        out = {key: job[key] for key in ("id", "kind", "state", "submitted", "started", "finished", "reason")}
        if with_result and job["state"] == "done":
            out["result"] = job["result"]
        return out

    def get(self, job_id, with_result=True):
        """Side-effect free: no lease, no expiry, no scheduling happens on a read."""
        with self.lock:
            job = self.jobs.get(job_id)
            return None if job is None else self.view(job, with_result)

    def wait(self, job_id, timeout):
        deadline = self.clock() + timeout
        with self.lock:
            while True:
                job = self.jobs.get(job_id)
                if job is None or job["state"] not in ("queued", "running"):
                    return None if job is None else self.view(job)
                remaining = deadline - self.clock()
                if remaining <= 0:
                    return self.view(job)
                self.lock.wait(min(remaining, 0.5))

    def cancel(self, job_id):
        """Idempotent: a finished or unknown job is left as it is; a queued or running one is cancelled."""
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None or job["state"] not in ("queued", "running"):
                return None if job is None else self.view(job)
            if job["id"] in self.queue:
                self.queue.remove(job["id"])
            process = self.running.pop(job["id"], None)
            if process is not None and process.poll() is None:
                process.kill()
            self._finish(job, "cancelled", "cancelled by the operator")
            self._pump()
            return self.view(job)

    def status(self):
        with self.lock:
            return {"running": len(self.running), "queued": len(self.queue), "max_running": self.max_running,
                    "max_queued": self.max_queued, "lifetime_seconds": self.lifetime, "counts": dict(self.counts)}

    def shutdown(self):
        """Idempotent: nothing is left running or queued after this returns; outcomes stay explicit."""
        with self.lock:
            self.closed = True
            for job_id in list(self.queue):
                self.queue.remove(job_id)
                self._finish(self.jobs[job_id], "cancelled", "server shut down before the job started")
            for job_id, process in list(self.running.items()):
                if process.poll() is None:
                    process.kill()
                self.running.pop(job_id, None)
                job = self.jobs.get(job_id)
                if job is not None and job["state"] == "running":
                    self._finish(job, "cancelled", "server shut down while the job ran")


class AdmissionError(RuntimeError):
    pass
