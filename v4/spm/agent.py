"""DoofusAI platform collector and deployment CLI. Authored by Aniza Inc."""
import argparse
from io import BytesIO
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
from time import sleep
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener
from zipfile import BadZipFile, ZipFile

from agent_protocol import MAX_REPORT, PROVIDERS, deployment
from controls import Problem
from gcs import CollectionError, NoRedirect


class API:
    def __init__(self, origin, token):
        parts = urlsplit(origin)
        if (not parts.hostname or parts.username or parts.password or parts.path not in ("", "/")
                or parts.query or parts.fragment or not (parts.scheme == "https" or
                    parts.scheme == "http" and parts.hostname in ("127.0.0.1", "::1", "localhost"))):
            raise Problem(400, "Use the central HTTPS origin or a local loopback test origin.")
        if not token or not re.fullmatch(r"[A-Za-z0-9._~-]{1,8192}", token):
            raise Problem(400, "Supply a bearer credential through the environment or a private token file.")
        self.origin, self.token = origin.rstrip("/"), token
        self.opener = build_opener(NoRedirect())

    def request(self, path, data=None, method=None, *, binary=False):
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/zip" if binary else "application/json"}
        encoded = None
        if data is not None:
            encoded = json.dumps(data, allow_nan=False, ensure_ascii=True).encode("ascii")
            if len(encoded) > MAX_REPORT:
                raise Problem(400, "Collection report exceeded the 2 MiB limit.")
            headers["Content-Type"] = "application/json"
        request = Request(self.origin + path, data=encoded, headers=headers, method=method)
        limit = MAX_REPORT if binary else 512 * 1024
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(limit + 1)
            if len(raw) > limit:
                raise Problem(502, "Central engine response exceeded its limit.")
            return raw if binary else json.loads(raw)
        except HTTPError as exc:
            with exc:
                raise Problem(exc.code, f"Central engine returned HTTP {exc.code}.") from None
        except (OSError, ValueError):
            raise Problem(503, "Could not communicate with the central engine.") from None


def collect(api, job):
    try:
        _, connector = deployment(job["provider"], job["arguments"])
        result = connector()
        if job["provider"] == "gcs":
            snapshot = result
        else:
            nodes, edges = result
            snapshot = {"nodes": nodes, "edges": sorted(edges)}
        report = {"job": job["id"], "claim": job["claim"], "status": "completed", "snapshot": snapshot}
        if len(json.dumps(report, ensure_ascii=True, allow_nan=False).encode("ascii")) > MAX_REPORT:
            raise CollectionError("Snapshot exceeded the report limit.")
    except (CollectionError, Problem, OSError, ValueError):
        report = {"job": job["id"], "claim": job["claim"], "status": "failed", "snapshot": None}
    for attempt in range(5):
        try:
            return api.request("/api/v1/agent/report", report)
        except Problem as error:
            if error.status < 500 and report["status"] == "completed" and error.status in (400, 413):
                report = report | {"status": "failed", "snapshot": None}
                continue
            if error.status not in (429, 500, 502, 503, 504) or attempt == 4:
                raise
            sleep(2 ** attempt)
    raise Problem(503, "Collection report could not be delivered.")


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)


def token_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise Problem(400, "Agent token file must be private to its owner.")
        return file.read(8193).decode("ascii").strip()


def run(api, once, interval):
    while True:
        try:
            job = api.request("/api/v1/agent/poll", {})["job"]
            if job:
                result = collect(api, job)
                print(json.dumps(result), flush=True)
                if once:
                    return 1 if result["status"] == "failed" else 0
            elif once:
                print(json.dumps({"status": "idle"}))
                return 0
        except Problem as error:
            if once or error.status < 500 and error.status not in (409, 429):
                raise
            print(str(error), file=sys.stderr, flush=True)
        sleep(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=os.environ.get("DOOFUS_ENGINE_ORIGIN"))
    actions = parser.add_subparsers(dest="command", required=True)
    deploy = actions.add_parser("deploy", help="Enroll and install a collector bundle on this host")
    deploy.add_argument("provider", choices=sorted(PROVIDERS))
    deploy.add_argument("directory", type=Path)
    deploy.add_argument("--name", default=socket.gethostname())
    deploy.add_argument("--ttl-hours", type=int, default=24)
    deploy.add_argument("--target", action="append", required=True, help="Repeat for ordered provider arguments")
    deploy.add_argument("--queue", action="store_true", help="Queue a first collection after installing")
    deploy.add_argument("--run-now", action="store_true", help="Queue and run the first collection on this host")
    runner = actions.add_parser("run", help="Poll using an agent credential")
    runner.add_argument("--token-file", type=Path)
    runner.add_argument("--config", type=Path, help="Read the origin from a deployment configuration")
    runner.add_argument("--once", action="store_true")
    runner.add_argument("--interval", type=int, default=10, choices=range(2, 301), metavar="SECONDS")
    actions.add_parser("list")
    for command in ("queue", "jobs", "rotate", "revoke"):
        sub = actions.add_parser(command)
        sub.add_argument("agent")
        if command == "rotate":
            sub.add_argument("--ttl-hours", type=int, default=24)
    args = parser.parse_args()
    try:
        if args.command == "run":
            origin = args.origin
            if args.config:
                origin = json.loads(args.config.read_text())["origin"]
            token = token_file(args.token_file) if args.token_file else os.environ.get("DOOFUS_AGENT_TOKEN")
            if not origin:
                raise Problem(400, "Supply an engine origin.")
            return run(API(origin, token), args.once, args.interval)
        if not args.origin:
            raise Problem(400, "Supply an engine origin.")
        api = API(args.origin, os.environ.get("DOOFUS_ADMIN_TOKEN"))
        path = "/api/v1/agents"
        if args.command == "deploy":
            deployment(args.provider, args.target)
            bundle = api.request(path + "/package", binary=True)
            with ZipFile(BytesIO(bundle)) as archive:
                entries = archive.infolist()
                names = [entry.filename for entry in entries]
                if (not 1 <= len(entries) <= 32 or "agent.py" not in names or len(set(names)) != len(names)
                        or sum(entry.file_size for entry in entries) > MAX_REPORT
                        or any(not re.fullmatch(r"[a-z0-9_.-]+[.](?:py|txt)", name) or len(name) > 80
                               for name in names)):
                    raise Problem(400, "Bundle contained unsupported files.")
                args.directory.mkdir(mode=0o700)
                for entry in entries:
                    private_write(args.directory / entry.filename, archive.read(entry))
            info = api.request(path, {"name": args.name, "provider": args.provider,
                                      "arguments": args.target, "ttl_hours": args.ttl_hours})
            private_write(args.directory / "agent.token", (info.pop("token") + "\n").encode())
            private_write(args.directory / "agent.json", json.dumps({"origin": api.origin}).encode())
            if args.queue or args.run_now:
                info["job"] = api.request(path + "/" + info["id"] + "/jobs", {})
            result = info | {"directory": str(args.directory)}
        elif args.command == "list":
            result = api.request(path)
        else:
            if not re.fullmatch(r"[a-f0-9-]{36}", args.agent):
                raise Problem(400, "Supply an enrolled agent ID.")
            target = path + "/" + args.agent
            if args.command == "rotate":
                result = api.request(target + "/rotate", {"ttl_hours": args.ttl_hours})
            elif args.command == "revoke":
                result = api.request(target, {}, method="DELETE")
            else:
                result = api.request(target + "/jobs", {} if args.command == "queue" else None)
        print(json.dumps(result), flush=True)
        if args.command == "deploy" and args.run_now:
            return run(API(api.origin, token_file(args.directory / "agent.token")), True, 10)
        return 0
    except (Problem, ValueError, KeyError, OSError, BadZipFile) as error:
        parser.exit(1, f"Collection agent: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
