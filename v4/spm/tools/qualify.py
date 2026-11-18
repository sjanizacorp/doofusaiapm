"""Run bounded HTTP qualification and an isolated cold-recovery rehearsal."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter, sleep
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin(value):
    url = urlsplit(value)
    if (not url.hostname or url.path not in ("", "/") or url.username or url.password
            or url.query or url.fragment or
            (url.scheme != "https" and not (url.scheme == "http" and url.hostname in
                                            ("127.0.0.1", "::1", "localhost")))):
        raise argparse.ArgumentTypeError("Use a verified HTTPS origin or a local loopback HTTP origin.")
    return value.rstrip("/")


def request(base, path, token=None, body=None, timeout=5):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body).encode()
    req = Request(base + path, headers=headers, data=body)
    with build_opener(NoRedirect()).open(req, timeout=timeout) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Oversized qualification response")
    return json.loads(raw)


def latency_run(base, token, count, workers, max_p95_ms):
    paths = ("/health", "/api/v1/me", "/api/v1/issues")

    def one(index):
        started = perf_counter()
        try:
            endpoint = index % len(paths)
            reply = request(base, paths[endpoint], token)
            valid = isinstance(reply, dict) and (
                reply.get("status") == "ok" if endpoint == 0 else
                {"principal", "project", "role"} <= reply.keys() if endpoint == 1 else
                isinstance(reply.get("issues"), list)
            )
        except (OSError, ValueError):
            valid = False
        return valid, (perf_counter() - started) * 1000

    started = perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        observations = list(pool.map(one, range(count)))
    elapsed = perf_counter() - started
    values = sorted(duration for _, duration in observations)
    p95 = values[(count * 95 + 99) // 100 - 1]
    failures = sum(not success for success, _ in observations)
    return {"requests": count, "workers": workers, "failed": failures,
            "p95_ms": round(p95, 2), "requests_per_second": round(count / elapsed, 2),
            "p95_target_ms": max_p95_ms, "passed": failures == 0 and p95 <= max_p95_ms}


def rehearsal(backup, captured_at, incident_at, rto_seconds, rpo_seconds, known_scan=None, read_token=None):
    app = Path(__file__).resolve().parents[1] / "app.py"

    def cli(db, *args):
        return subprocess.run([sys.executable, str(app), "--db", str(db), *map(str, args)],
                              capture_output=True, text=True, check=True, timeout=30).stdout.strip()

    with TemporaryDirectory() as directory:
        restore = Path(directory) / "restore.sqlite"
        started = perf_counter()
        status = json.loads(cli(restore, "verify-backup", backup))
        shutil.copyfile(backup, restore)
        os.chmod(restore, 0o600)
        stream = json.loads(cli(restore, "promote-recovery"))["stream_id"]
        token = cli(restore, "issue", "Recovery Drill", "canary", "admin", "--ttl-minutes", "5")
        with TemporaryDirectory() as log_directory:
            log = Path(log_directory) / "server.log"
            with log.open("w") as output, subprocess.Popen(
                [sys.executable, str(app), "--db", str(restore), "serve", "--port", "0"],
                stdout=output, stderr=output, text=True,
            ) as server:
                try:
                    base = None
                    for _ in range(50):
                        line = log.read_text()
                        label = "http://127.0.0.1:"
                        if label in line:
                            port = int(line.split(label, 1)[1].splitlines()[0])
                            base = f"{label}{port}"
                            break
                        if server.poll() is not None:
                            break
                        sleep(0.1)
                    if base is None or request(base, "/health") != {"status": "ok"}:
                        raise ValueError("Recovery copy did not become ready.")
                    if known_scan is not None:
                        old = request(base, "/api/v1/scans/" + known_scan, read_token)
                        if old["id"] != known_scan:
                            raise ValueError("Recovery copy did not contain the known scan.")
                    request(base, "/api/v1/assets", token, {
                        "id": "recovery-canary", "kind": "storage",
                        "facts": {"encrypted": True, "public": False},
                    })
                    scan = request(base, "/api/v1/scans", token, {"asset": "recovery-canary"})
                    stored = request(base, "/api/v1/scans/" + scan["id"], token)
                    events = request(base, "/api/v1/security-events", token)
                    if stored["id"] != scan["id"] or events["stream_id"] != stream:
                        raise ValueError("Recovery copy failed its read/write or stream check.")
                    elapsed = perf_counter() - started
                finally:
                    if server.poll() is None:
                        server.terminate()
    age = (incident_at - captured_at).total_seconds()
    return {"rto_seconds": round(elapsed, 3), "backup_age_seconds": age,
            "rto_target_seconds": rto_seconds, "rpo_target_seconds": rpo_seconds,
            "recovered_counts": status["counts"], "known_scan_verified": known_scan is not None,
            "passed": elapsed <= rto_seconds and 0 <= age <= rpo_seconds}


def date(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is not None:
            return parsed.astimezone(timezone.utc)
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("Use a timestamp with an explicit time zone.")


def observe_failover(base, token, previous_stream, scan_id, rto_seconds):
    started = perf_counter()
    deadline = started + rto_seconds

    def probe(path, credential=None):
        remaining = deadline - perf_counter()
        if remaining <= 0:
            raise TimeoutError()
        return request(base, path, credential, timeout=min(5, remaining))

    while perf_counter() < deadline:
        try:
            health = probe("/health")
            cursor = probe("/api/v1/security-events", token)
            stream = cursor["stream_id"]
            if health == {"status": "ok"} and stream != previous_stream and re.fullmatch(r"[a-f0-9]{32}", stream):
                record = probe("/api/v1/scans/" + scan_id, token)
                elapsed = perf_counter() - started
                if record["id"] == scan_id and elapsed <= rto_seconds:
                    return {"passed": True, "elapsed_seconds": round(elapsed, 3),
                            "rto_target_seconds": rto_seconds, "new_stream_id": stream}
        except (OSError, KeyError, ValueError, TypeError):
            pass
        sleep(min(0.25, max(0, deadline - perf_counter())))
    return {"passed": False, "rto_target_seconds": rto_seconds,
            "error": "Recovery origin did not expose a new stream with the known report in time."}


def observe_reschedule(base, token, previous_boot, previous_node, stream, scan_id, rto_seconds):
    started = perf_counter()
    deadline = started + rto_seconds

    def probe(path, credential=None):
        remaining = deadline - perf_counter()
        if remaining <= 0:
            raise TimeoutError()
        return request(base, path, credential, timeout=min(5, remaining))

    while perf_counter() < deadline:
        try:
            health = probe("/health")
            current = probe("/api/v1/instance", token)
            node = current.get("node")
            boot = current.get("boot_id")
            if (health == {"status": "ok"} and current.get("stream_id") == stream
                    and isinstance(boot, str) and re.fullmatch(r"[a-f0-9]{32}", boot) and boot != previous_boot
                    and isinstance(node, str) and node and node != previous_node):
                record = probe("/api/v1/scans/" + scan_id, token)
                elapsed = perf_counter() - started
                if record.get("id") == scan_id and elapsed <= rto_seconds:
                    return {"passed": True, "elapsed_seconds": round(elapsed, 3), "previous_node": previous_node,
                            "new_node": node, "boot_id": boot, "rto_target_seconds": rto_seconds}
        except (OSError, KeyError, TypeError, AttributeError, ValueError):
            pass
        sleep(min(0.25, max(0, deadline - perf_counter())))
    return {"passed": False, "rto_target_seconds": rto_seconds,
            "error": "The same stream and known report did not recover on another node in time."}


def pilot(base, token, expected_project, expected_principal, scopes, github_workload, max_age_hours):
    if token.count(".") != 2:
        return {"passed": False, "error": "Supply a federated staging access token."}
    identity = request(base, "/api/v1/me", token)
    if identity.get("project") != expected_project or identity.get("principal") != expected_principal:
        return {"passed": False, "error": "Federated identity did not match the expected pilot principal."}
    syncs = request(base, "/api/v1/sync-runs", token)
    recent = datetime.now(timezone.utc)
    checks = []
    for provider, source in scopes:
        current = next((run for run in syncs["runs"] if run["provider"] == provider
                        and run["source_project"] == source), None)
        age = (recent - date(current["finished_at"])).total_seconds() if current else None
        checks.append({"provider": provider, "scope": source, "passed": current is not None
                       and current["status"] == "completed" and 0 <= age <= max_age_hours * 3600})
    if github_workload:
        catalog = request(base, "/api/v1/boms", token)
        latest = next((entry for entry in catalog["boms"] if entry["workload"] == github_workload), None)
        collected = False
        if latest and re.fullmatch(r"[a-f0-9-]{36}", latest["id"]):
            details = request(base, "/api/v1/boms/" + latest["id"], token)
            age = (recent - date(latest["imported_at"])).total_seconds()
            collected = (details["document"].get("origin", {}).get("provider") == "github"
                         and 0 <= age <= max_age_hours * 3600)
        checks.append({"provider": "github", "scope": github_workload, "passed": collected})
    return {"federated_identity": True, "checks": checks, "passed": all(check["passed"] for check in checks)}


def remediation(base, token, issue, provider, max_age_hours):
    proof = request(base, "/api/v1/issues/" + issue + "/remediation-proof", token)
    if not isinstance(proof, dict) or proof.get("verified") is not True or proof.get("issue") != issue:
        return {"passed": False, "error": "No verified source-backed remediation for this issue."}
    baseline, latest = proof["before"], proof["after"]
    if (baseline["sync"]["provider"] != provider or latest["sync"]["provider"] != provider
            or baseline["sync"]["id"] == latest["sync"]["id"]
            or baseline["sync"]["source_project"] != latest["sync"]["source_project"]
            or baseline["control"]["status"] != "finding" or latest["control"]["status"] != "pass"):
        return {"passed": False, "error": "Remediation does not match the expected provider and control transition."}
    age = (datetime.now(timezone.utc) - date(latest["sync"]["finished_at"])).total_seconds()
    return {"passed": 0 <= age <= max_age_hours * 3600, "issue": issue, "provider": provider,
            "before_scan": baseline["id"], "after_scan": latest["id"], "age_seconds": round(age, 2)}


def access_change(base, token, review, baseline, provider, expected, max_age_hours):
    evidence = request(base, f"/api/v1/access-reviews/{review}/compare?baseline={baseline}", token)
    if (evidence.get("review") != review or evidence.get("baseline") != baseline
            or evidence.get("provider") != provider or evidence.get("inventory_changed") is not False):
        return {"passed": False, "error": "Review scope or inventory version did not match the requested gate."}
    age = (datetime.now(timezone.utc) - date(evidence["review_evaluated_at"])).total_seconds()
    if not 0 <= age <= max_age_hours * 3600:
        return {"passed": False, "error": "Latest review is outside the allowed evidence age."}
    transitions = {item["action"]: item["change"] for item in evidence["transitions"]}
    checks = [{"action": action, "expected": change, "observed": transitions.get(action),
               "passed": transitions.get(action) == change} for action, change in expected]
    return {"passed": all(item["passed"] for item in checks), "provider": provider,
            "review": review, "baseline": baseline, "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    load = sub.add_parser("load")
    load.add_argument("origin", type=origin)
    load.add_argument("--requests", type=int, default=120)
    load.add_argument("--workers", type=int, default=4)
    load.add_argument("--p95-target-ms", type=float, default=500)
    recovery = sub.add_parser("recover")
    recovery.add_argument("backup", type=Path)
    recovery.add_argument("--captured-at", type=date, required=True)
    recovery.add_argument("--incident-at", type=date, required=True)
    recovery.add_argument("--rto-seconds", type=float, required=True)
    recovery.add_argument("--rpo-seconds", type=float, required=True)
    recovery.add_argument("--known-scan", help="Verify a previously recorded scan with the qualification token")
    failover = sub.add_parser("observe-failover")
    failover.add_argument("origin", type=origin)
    failover.add_argument("--previous-stream", required=True)
    failover.add_argument("--known-scan", required=True)
    failover.add_argument("--rto-seconds", type=float, required=True)
    reschedule = sub.add_parser("observe-reschedule", help="Verify single-writer recovery on a new node")
    reschedule.add_argument("origin", type=origin)
    reschedule.add_argument("--previous-boot", required=True)
    reschedule.add_argument("--previous-node", required=True)
    reschedule.add_argument("--stream", required=True)
    reschedule.add_argument("--known-scan", required=True)
    reschedule.add_argument("--rto-seconds", type=float, required=True)
    staging = sub.add_parser("pilot", help="Gate a designated staging origin on live federation and recent collection")
    staging.add_argument("origin", type=origin)
    staging.add_argument("--project", required=True)
    staging.add_argument("--principal", required=True)
    staging.add_argument("--require-sync", action="append", default=[], metavar="PROVIDER=SCOPE")
    staging.add_argument("--github-workload")
    staging.add_argument("--max-age-hours", type=int, choices=range(1, 169), default=24, metavar="HOURS")
    verify_fix = sub.add_parser("remediation", help="Check a finding-to-pass transition against completed source evidence")
    verify_fix.add_argument("origin", type=origin)
    verify_fix.add_argument("--issue", required=True)
    verify_fix.add_argument("--provider", required=True, choices=("gcs", "vertex", "aws", "azure", "vsphere", "oci", "ibm", "salesforce"))
    verify_fix.add_argument("--max-age-hours", type=int, choices=range(1, 169), default=24, metavar="HOURS")
    verify_access = sub.add_parser("access-change", help="Check a recent permission change against a comparable baseline")
    verify_access.add_argument("origin", type=origin)
    verify_access.add_argument("--review", required=True)
    verify_access.add_argument("--baseline", required=True)
    verify_access.add_argument("--provider", required=True, choices=("aws", "vsphere", "gcs"))
    verify_access.add_argument("--require", action="append", required=True, metavar="ACTION=CHANGE")
    verify_access.add_argument("--max-age-hours", type=int, choices=range(1, 169), default=24, metavar="HOURS")
    args = parser.parse_args()
    try:
        if args.mode in ("load", "observe-failover", "observe-reschedule", "pilot", "remediation", "access-change"):
            token = os.environ.get("SPM_QUALIFICATION_TOKEN")
            if not token:
                parser.error("Set SPM_QUALIFICATION_TOKEN to a test credential.")
        if args.mode == "load":
            if not (1 <= args.requests <= 10000 and 1 <= args.workers <= min(32, args.requests)
                    and 0 < args.p95_target_ms < float("inf")):
                parser.error("Use 1–10,000 requests, at most 32 workers, and a positive latency target.")
            result = latency_run(args.origin, token, args.requests, args.workers, args.p95_target_ms)
        elif args.mode == "recover":
            if not (0 < args.rto_seconds < float("inf") and 0 <= args.rpo_seconds < float("inf")):
                parser.error("Use a positive RTO and a nonnegative RPO.")
            read_token = os.environ.get("SPM_QUALIFICATION_TOKEN")
            if args.known_scan and (re.fullmatch(r"[a-f0-9-]{36}", args.known_scan) is None or not read_token):
                parser.error("Use a scan UUID and set SPM_QUALIFICATION_TOKEN for its project.")
            result = rehearsal(args.backup, args.captured_at, args.incident_at,
                               args.rto_seconds, args.rpo_seconds, args.known_scan, read_token)
        elif args.mode == "observe-failover":
            if (re.fullmatch(r"[a-f0-9]{32}", args.previous_stream) is None
                    or re.fullmatch(r"[a-f0-9-]{36}", args.known_scan) is None
                    or not 0 < args.rto_seconds <= 3600):
                parser.error("Use a stream ID, a scan UUID, and an RTO of at most 3,600 seconds.")
            result = observe_failover(args.origin, token, args.previous_stream,
                                      args.known_scan, args.rto_seconds)
        elif args.mode == "observe-reschedule":
            if (any(re.fullmatch(r"[a-f0-9]{32}", item) is None for item in (args.previous_boot, args.stream))
                    or re.fullmatch(r"[a-f0-9-]{36}", args.known_scan) is None or not args.previous_node
                    or not 0 < args.rto_seconds <= 3600):
                parser.error("Use the previous boot and node, stream ID, known scan UUID, and an RTO up to 3,600 seconds.")
            result = observe_reschedule(args.origin, token, args.previous_boot, args.previous_node,
                                        args.stream, args.known_scan, args.rto_seconds)
        elif args.mode == "pilot":
            scopes = [tuple(item.split("=", 1)) for item in args.require_sync]
            if (len(scopes) > 20 or any(len(item) != 2 or item[0] not in ("gcs", "vertex", "aws", "azure", "vsphere", "oci", "ibm", "salesforce")
                                       or not item[1] for item in scopes)):
                parser.error("Use up to 20 requirements of the form PROVIDER=SCOPE.")
            result = pilot(args.origin, token, args.project, args.principal, scopes,
                           args.github_workload, args.max_age_hours)
        elif args.mode == "remediation":
            if re.fullmatch(r"[a-f0-9-]{36}", args.issue) is None:
                parser.error("Use an issue UUID.")
            result = remediation(args.origin, token, args.issue, args.provider, args.max_age_hours)
        else:
            expected = [tuple(item.split("=", 1)) for item in args.require]
            if (any(re.fullmatch(r"[a-f0-9-]{36}", item) is None for item in (args.review, args.baseline))
                    or len(expected) > 30 or any(len(item) != 2 or not item[0] or item[1] not in (
                        "access-added", "access-removed", "unchanged", "denial-changed",
                    ) for item in expected)):
                parser.error("Use two review UUIDs and expected changes in ACTION=CHANGE format.")
            result = access_change(args.origin, token, args.review, args.baseline, args.provider,
                                   expected, args.max_age_hours)
    except (OSError, ValueError, KeyError, TypeError, argparse.ArgumentTypeError, subprocess.SubprocessError) as error:
        result = {"passed": False, "error": type(error).__name__}
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
