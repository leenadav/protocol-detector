"""Local microbenchmark, not a production latency or throughput guarantee.

Includes Python call/event overhead, excludes capture, reassembly, TLS decryption,
networking and logging. Legacy baseline has weaker validation than the new parser.
"""
import argparse
import json
import platform
import statistics
import time
from dataclasses import asdict
from detectors import detect_all
from protocol_engine import ApplicationRule, Inspector, RuleIndex
from proxy_demo import client_hello
from protocol_demo import AMQP_091, AMQP_10, HTTP2, MQTT, RESP, SOCKS5


def distribution(samples):
    ordered = sorted(samples)
    return {"p50_us": round(statistics.median(ordered) / 1000, 3),
            "p95_us": round(ordered[int((len(ordered) - 1) * .95)] / 1000, 3),
            "p99_us": round(ordered[int((len(ordered) - 1) * .99)] / 1000, 3)}


def run_case(chunks, iterations, rules, legacy=False):
    flow_times, feed_times = [], []
    final_metrics = None
    for iteration in range(iterations + 20):
        inspector = Inspector(rules=rules)
        buffer = b""
        started = time.perf_counter_ns()
        timings = []
        for chunk in chunks:
            before = time.perf_counter_ns()
            if legacy:
                buffer += chunk
                detect_all(buffer)
            else:
                inspector.feed(chunk)
            timings.append(time.perf_counter_ns() - before)
        elapsed = time.perf_counter_ns() - started
        if iteration >= 20:
            flow_times.append(elapsed)
            feed_times.extend(timings)
        if not legacy:
            final_metrics = asdict(inspector.metrics)
    return {"flow": distribution(flow_times), "feed": distribution(feed_times), "metrics": final_metrics}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200)
    args = parser.parse_args()
    if not 10 <= args.iterations <= 10000:
        parser.error("iterations must be between 10 and 10000")
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    long_headers = (b"GET / HTTP/1.1\r\nHost: example.com\r\n" +
                    b"X-Padding: " + b"a" * 6000 + b"\r\n\r\n")
    cases = {"http_small": [request],
             "http_fragmented": [long_headers[i:i + 32] for i in range(0, len(long_headers), 32)],
             "tls_fragmented": [client_hello()],
             "http_after_identification": [request] + [b"x" * 1024] * 64}
    hello = cases["tls_fragmented"][0]
    cases["tls_fragmented"] = [hello[i:i + 32] for i in range(0, len(hello), 32)]
    empty = RuleIndex()
    result = {"environment": {"python": platform.python_version(), "platform": platform.platform(),
                               "iterations": args.iterations, "warmup_flows": 20}, "cases": {}}
    for name, chunks in cases.items():
        result["cases"][name] = {"incremental": run_case(chunks, args.iterations, empty),
                                 "legacy": run_case(chunks, args.iterations, empty, legacy=True)}
    start = time.perf_counter_ns()
    large = RuleIndex([ApplicationRule("host{}.example".format(i), "App {}".format(i), "http_host")
                       for i in range(30000)])
    result["rule_index_build_ms"] = round((time.perf_counter_ns() - start) / 1000000, 3)
    rule_request = request.replace(b"example.com", b"host29999.example")
    result["rules_30000"] = run_case([rule_request], args.iterations, large)
    result["rules_0_same_request"] = run_case([rule_request], args.iterations, empty)
    result["protocol_extensions"] = {}
    for name, data in (("http2", HTTP2), ("socks5", SOCKS5), ("smtp", b"EHLO client.example.com\r\n"),
                       ("mqtt", MQTT), ("resp", RESP), ("amqp_091", AMQP_091), ("amqp_10", AMQP_10)):
        chunks = [data[offset:offset + 7] for offset in range(0, len(data), 7)]
        result["protocol_extensions"][name] = run_case(chunks, args.iterations, empty)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
