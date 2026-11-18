"""Bounded, privacy-preserving Prometheus service telemetry."""
from collections import Counter, defaultdict
from threading import Lock

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)


def route_group(path):
    if path == "/health":
        return "health"
    if path == "/metrics":
        return "metrics"
    if path.startswith("/auth/"):
        return "auth"
    if path == "/api/v1/runtime/inspect":
        return "runtime"
    if path.startswith("/api/"):
        return "api"
    return "web"


class Telemetry:
    def __init__(self):
        self.lock = Lock()
        self.requests = Counter()
        self.duration_counts = defaultdict(lambda: [0] * len(BUCKETS))
        self.duration_sum = Counter()
        self.duration_total = Counter()
        self.in_flight = 0
        self.rejected = 0

    def connection(self, delta):
        with self.lock:
            self.in_flight += delta

    def reject(self):
        with self.lock:
            self.rejected += 1

    def record(self, route, status, seconds):
        with self.lock:
            self.requests[route, f"{status // 100}xx"] += 1
            self.duration_total[route] += 1
            self.duration_sum[route] += seconds
            for index, bucket in enumerate(BUCKETS):
                if seconds <= bucket:
                    self.duration_counts[route][index] += 1

    def render(self):
        with self.lock:
            lines = [
                "# HELP doofusai_http_connections Current accepted HTTP connections.",
                "# TYPE doofusai_http_connections gauge",
                f"doofusai_http_connections {self.in_flight}",
                "# HELP doofusai_http_connections_rejected_total Connections rejected at capacity.",
                "# TYPE doofusai_http_connections_rejected_total counter",
                f"doofusai_http_connections_rejected_total {self.rejected}",
                "# HELP doofusai_http_requests_total Completed HTTP responses by bounded route and status class.",
                "# TYPE doofusai_http_requests_total counter",
            ]
            for (route, status), value in sorted(self.requests.items()):
                lines.append(f'doofusai_http_requests_total{{route="{route}",status_class="{status}"}} {value}')
            lines.extend((
                "# HELP doofusai_http_request_duration_seconds Server processing latency before response headers.",
                "# TYPE doofusai_http_request_duration_seconds histogram",
            ))
            for route, count in sorted(self.duration_total.items()):
                for bucket, value in zip(BUCKETS, self.duration_counts[route]):
                    lines.append(f'doofusai_http_request_duration_seconds_bucket{{route="{route}",le="{bucket}"}} {value}')
                lines.append(f'doofusai_http_request_duration_seconds_bucket{{route="{route}",le="+Inf"}} {count}')
                lines.append(f'doofusai_http_request_duration_seconds_sum{{route="{route}"}} {self.duration_sum[route]:.9f}')
                lines.append(f'doofusai_http_request_duration_seconds_count{{route="{route}"}} {count}')
            return ("\n".join(lines) + "\n").encode("ascii")
