"""Counters and histograms for the boundaries between components (stage 7, A15).

One small, dependency-free model shared by the Analyzer, the coordinator, the decoder and the live worker:
`Counter`-like integer counters, fixed-bucket histograms (bounded memory, no sample retention), and a
`Telemetry` registry that renders to a JSON-friendly dict. Nothing here records payload, names or keys:
values are counts, byte totals and durations.

Names (the ones the review asks for are all present):
    bytes.new, bytes.replayed, bytes.decrypted, keys.pending, signatures.candidates,
    decryption.auth_failures, capture.gaps, events.dropped, queue.depth, bytes.retained
Histograms:
    time_to_verdict_seconds   capture time from first packet to the session record
    stage_seconds.<name>      wall time of one bounded work stage (packet, tick, decrypt, report)
"""
import time
from collections import OrderedDict

DEFAULT_BUCKETS = (0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 60.0)
MAX_SERIES = 64


class Histogram:
    """Fixed buckets (upper bounds, cumulative on render), count, sum, min, max; no samples retained."""
    __slots__ = ("buckets", "counts", "count", "total", "minimum", "maximum")

    def __init__(self, buckets=DEFAULT_BUCKETS):
        self.buckets = tuple(sorted(buckets))
        self.counts = [0] * (len(self.buckets) + 1)
        self.count = 0
        self.total = 0.0
        self.minimum = None
        self.maximum = None

    def observe(self, value):
        value = float(value)
        for index, bound in enumerate(self.buckets):
            if value <= bound:
                self.counts[index] += 1
                break
        else:
            self.counts[-1] += 1
        self.count += 1
        self.total += value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)

    def quantile(self, q):
        """Upper bound of the bucket holding the q-quantile (None when empty); +inf bucket reports None."""
        if not self.count:
            return None
        target = max(1, int(round(q * self.count)))
        seen = 0
        for index, bound in enumerate(self.buckets):
            seen += self.counts[index]
            if seen >= target:
                return bound
        return None

    def render(self):
        return {"count": self.count, "sum": round(self.total, 6), "min": self.minimum, "max": self.maximum,
                "p50": self.quantile(0.5), "p95": self.quantile(0.95), "p99": self.quantile(0.99),
                "buckets": [[bound, count] for bound, count in zip(self.buckets, self.counts)] + [["+inf", self.counts[-1]]]}


class Telemetry:
    def __init__(self, clock=time.perf_counter):
        self.counters = OrderedDict()
        self.histograms = OrderedDict()
        self.clock = clock

    def add(self, name, value=1):
        if name not in self.counters and len(self.counters) >= MAX_SERIES:
            raise ValueError("telemetry counter series exhausted")
        self.counters[name] = self.counters.get(name, 0) + value

    def set(self, name, value):
        if name not in self.counters and len(self.counters) >= MAX_SERIES:
            raise ValueError("telemetry counter series exhausted")
        self.counters[name] = value

    def histogram(self, name, buckets=DEFAULT_BUCKETS):
        histogram = self.histograms.get(name)
        if histogram is None:
            if len(self.histograms) >= MAX_SERIES:
                raise ValueError("telemetry histogram series exhausted")
            histogram = self.histograms[name] = Histogram(buckets)
        return histogram

    def observe(self, name, value):
        self.histogram(name).observe(value)

    def stage(self, name):
        """Context manager timing one bounded unit of work into stage_seconds.<name>."""
        return _Stage(self, "stage_seconds." + name)

    def render(self):
        return {"counters": dict(self.counters), "histograms": {name: h.render() for name, h in self.histograms.items()}}

    def merge(self, other):
        for name, value in other.counters.items():
            self.add(name, value)
        for name, histogram in other.histograms.items():
            mine = self.histogram(name, histogram.buckets)
            for index, count in enumerate(histogram.counts):
                mine.counts[index] += count
            mine.count += histogram.count
            mine.total += histogram.total
            if histogram.minimum is not None:
                mine.minimum = histogram.minimum if mine.minimum is None else min(mine.minimum, histogram.minimum)
                mine.maximum = histogram.maximum if mine.maximum is None else max(mine.maximum, histogram.maximum)


class _Stage:
    __slots__ = ("telemetry", "name", "started")

    def __init__(self, telemetry, name):
        self.telemetry, self.name, self.started = telemetry, name, None

    def __enter__(self):
        self.started = self.telemetry.clock()
        return self

    def __exit__(self, *exc):
        self.telemetry.observe(self.name, self.telemetry.clock() - self.started)
        return False
