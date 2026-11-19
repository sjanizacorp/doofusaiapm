"""DoofusAI SPM lifecycle commands for Linux and macOS. Authored by Aniza Inc."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep


HERE = Path(__file__).resolve().parent
DEFAULT_HOME = Path.home() / ".local/share/doofusai-spm"
MARK = ".doofusai-spm-installation"
COMMANDS = ("install", "uninstall", "start", "stop", "status", "spm")


def runtime_file(directory, name):
    for suffix in (".py", ".pyc"):
        candidate = directory / (name + suffix)
        if candidate.is_file():
            return candidate
    raise ValueError(f"Product component is missing ({name}).")


def write_json(path, value):
    temporary = path.with_suffix(".new")
    with temporary.open("w") as file:
        json.dump(value, file)
    temporary.replace(path)


def installed(home):
    if not (home / MARK).is_file():
        raise ValueError("No installation at this location. Run install.sh first.")


@contextmanager
def locked(home):
    with (home / ".lifecycle.lock").open("a") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        yield


def identity(pid):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def current_process(home):
    file = home / "process.json"
    if not file.exists():
        return None
    state = json.loads(file.read_text())
    pid = state.get("pid")
    if type(pid) is not int or pid < 2:
        raise ValueError("Installation process record is invalid.")
    actual = identity(pid)
    if actual and actual == state["identity"] and str(home / "data" / "posture.sqlite") in actual:
        return pid
    file.unlink()
    return None


def settings(home):
    return json.loads((home / "config" / "service.json").read_text())


def start(home):
    existing = current_process(home)
    if existing:
        print(f"Already running (PID {existing}).")
        return
    config = settings(home)
    app = runtime_file(home / "runtime", "app")
    listen = config["listen_address"]
    command = [sys.executable, "-B", "-u", str(app), "--db", str(home / "data" / "posture.sqlite"),
               "serve", "--listen-address", listen, "--port", str(config["port"])]
    for flag, name in (("--issuer-config", "issuer.json"), ("--sso-config", "sso.json"), ("--metrics-token-file", "metrics.token"),
                       ("--chat-gateway-config", "gateway.json"), ("--relay-config", "relay.json")):
        path = home / "config" / name
        if path.is_file():
            command.extend((flag, str(path)))
    output = home / "logs" / "service.log"
    with output.open("a+") as log:
        log.seek(0, os.SEEK_END)
        beginning = log.tell()
        process = subprocess.Popen(command, cwd=home / "runtime", stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log, start_new_session=True)
    deadline = monotonic() + 12
    try:
        while monotonic() < deadline:
            if process.poll() is not None:
                raise ValueError(f"Service exited during startup. See {output}")
            with output.open() as log:
                log.seek(beginning)
                if f"http://{listen}:{config['port']}" in log.read(65536):
                    write_json(home / "process.json", {"pid": process.pid, "identity": identity(process.pid)})
                    print(f"Running (PID {process.pid}). Open http://127.0.0.1:{config['port']} on this host.")
                    return
            sleep(0.2)
        raise ValueError(f"Service startup timed out. See {output}")
    except BaseException:
        if process.poll() is None:
            process.terminate()
        raise


def stop(home):
    pid = current_process(home)
    if pid is None:
        print("Already stopped.")
        return
    os.kill(pid, signal.SIGTERM)
    deadline = monotonic() + 35
    while current_process(home) is not None:
        if monotonic() >= deadline:
            raise ValueError("Graceful shutdown is still in progress. Check status before trying again.")
        sleep(0.2)
    print("Stopped.")


def install(home, port, listen):
    source = next((path for path in (HERE / "runtime", HERE / "spm", HERE.parent / "spm")
                   if (path / "app.py").is_file() or (path / "app.pyc").is_file()), None)
    if source is None:
        raise ValueError("Run install.sh from an extracted DoofusAI package.")
    if (source / "app.pyc").exists() and (sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 13)):
        raise ValueError("The client runtime requires CPython 3.13.")
    if home.exists() and not (home / MARK).is_file() and any(home.iterdir()):
        raise ValueError("Choose an empty installation directory.")
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    with locked(home):
        if current_process(home):
            raise ValueError("Stop the service before replacing the installed runtime.")
        for name in ("data", "logs", "config", "bin"):
            (home / name).mkdir(mode=0o700, exist_ok=True)
        if not (home / "config" / "service.json").exists() or port is not None or listen is not None:
            before = settings(home) if (home / "config" / "service.json").exists() else {}
            write_json(home / "config" / "service.json",
                       {"port": port or before.get("port", 8000),
                        "listen_address": listen or before.get("listen_address", "127.0.0.1")})
        with TemporaryDirectory(dir=home) as temporary:
            stage = Path(temporary) / "runtime"
            stage.mkdir()
            for component in sorted(source.iterdir()):
                if component.is_file() and (component.suffix in (".py", ".pyc") or
                                            component.name.startswith("requirements-")):
                    shutil.copy2(component, stage / component.name)
            shutil.copytree(source / "web", stage / "web")
            previous = None
            if (home / "runtime").exists():
                previous = Path(temporary) / "previous"
                (home / "runtime").rename(previous)
            try:
                stage.rename(home / "runtime")
            except OSError:
                if previous:
                    previous.rename(home / "runtime")
                raise
        component = runtime_file(HERE, "lifecycle")
        if component.parent != home / "bin":
            shutil.copy2(component, home / "bin" / component.name)
        for command in COMMANDS[1:]:
            wrapper = HERE / (command + ".sh")
            if wrapper.parent != home / "bin":
                shutil.copy2(wrapper, home / "bin" / wrapper.name)
        (home / MARK).touch()
    print(f"Installed in {home}")
    print(f"Start with: {home / 'bin/start.sh'}")


def main():
    command = sys.argv[1]
    parser = argparse.ArgumentParser(prog=command + ".sh")
    parser.add_argument("--prefix", type=Path)
    if command == "install":
        parser.add_argument("--port", type=int)
        parser.add_argument("--listen-address", choices=("127.0.0.1", "0.0.0.0"))
    args, remainder = parser.parse_known_args(sys.argv[2:])
    if command != "spm" and remainder:
        parser.error("unrecognized arguments: " + " ".join(remainder))
    if command == "spm" and not remainder:
        remainder = ["--help"]
    if getattr(args, "port", None) is not None and not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    inferred = HERE.parent if HERE.name == "bin" and (HERE.parent / MARK).exists() else DEFAULT_HOME
    home = (args.prefix or Path(os.environ.get("DOOFUS_SPM_HOME", inferred))).expanduser().resolve()
    if home in (Path("/"), Path.home()):
        parser.error("Choose a dedicated installation directory.")
    os.umask(0o077)
    try:
        if command == "install":
            install(home, args.port, args.listen_address)
            return 0
        installed(home)
        if command == "spm":
            app = runtime_file(home / "runtime", "app")
            os.execv(sys.executable, [sys.executable, "-B", str(app), "--db",
                                      str(home / "data" / "posture.sqlite"), *remainder])
        with locked(home):
            if command == "start":
                start(home)
            elif command == "stop":
                stop(home)
            elif command == "status":
                pid = current_process(home)
                if pid:
                    print(f"Running (PID {pid}) · port {settings(home)['port']}")
                else:
                    print("Stopped.")
                    return 3
            elif command == "uninstall":
                stop(home)
                if (home / "runtime").exists():
                    shutil.rmtree(home / "runtime")
                if (home / "bin").exists():
                    shutil.rmtree(home / "bin")
                print(f"Uninstalled. Data, configuration, and logs are retained in {home}.")
        return 0
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f"DoofusAI SPM: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
