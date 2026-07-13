"""Console runtime used by the installed server task and management CLI."""

import json
import logging
import os
import sys

from flask.cli import FlaskGroup

from app import create_app
from services.runtime_paths import ensure_runtime_directories


def _configure_file_logging(data_dir):
    log_path = data_dir / "logs" / "server.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8")],
        force=True,
    )
    return log_path


def run_server():
    from waitress import serve

    data_dir = ensure_runtime_directories()
    _configure_file_logging(data_dir)
    os.environ.setdefault("START_SCHEDULER", "true")
    app = create_app()
    host = os.environ.get("LYNCEUS_HOST", "0.0.0.0")
    port = app.config["APP_PORT"]
    pid_file = data_dir / "server.pid"
    pid_file.write_text(
        json.dumps({"pid": os.getpid(), "host": host, "port": port}),
        encoding="utf-8",
    )
    logging.getLogger(__name__).info("Lynceus server starting on %s:%s", host, port)
    try:
        serve(app, host=host, port=port, threads=8)
    finally:
        try:
            state = json.loads(pid_file.read_text(encoding="utf-8"))
            if state.get("pid") == os.getpid():
                pid_file.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError):
            pass


def run_cli(args, *, standalone_mode=True):
    cli = FlaskGroup(create_app=create_app)
    return cli.main(
        args=args,
        prog_name="LynceusCLI",
        standalone_mode=standalone_mode,
    )


def run_initial_admin_setup():
    exit_code = 0
    try:
        run_cli(["create-admin"], standalone_mode=False)
    except Exception as error:
        exit_code = 1
        print(f"\nAdmin setup failed: {error}")
    finally:
        try:
            input("\nPress Enter to close the admin setup window...")
        except EOFError:
            pass
    return exit_code


def main():
    args = sys.argv[1:]
    if args and args[0].lower() == "server":
        run_server()
        return
    if args and args[0].lower() == "setup-admin":
        raise SystemExit(run_initial_admin_setup())
    run_cli(args)


if __name__ == "__main__":
    main()
