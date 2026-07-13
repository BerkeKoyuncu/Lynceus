"""Console runtime used by the installed server task and management CLI."""

import json
import logging
import os
import sys

from flask.cli import FlaskGroup

from app import create_app
from services.runtime_paths import ensure_runtime_directories


# Handle the configure file logging operation.
def _configure_file_logging(data_dir):
    log_path = data_dir / "logs" / "server.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_path, encoding="utf-8")],
        force=True,
    )
    return log_path


# Run server.
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
    # Run this block with structured exception handling.
    try:
        serve(app, host=host, port=port, threads=8)
    # Run cleanup that must occur after the protected block.
    finally:
        # Run this block with structured exception handling.
        try:
            state = json.loads(pid_file.read_text(encoding="utf-8"))
            # Handle the branch where state.get('pid') == os.getpid() evaluates to true.
            if state.get("pid") == os.getpid():
                pid_file.unlink(missing_ok=True)
        # Handle an exception raised by the preceding protected block.
        except (OSError, ValueError, TypeError):
            pass


# Run cli.
def run_cli(args, *, standalone_mode=True):
    cli = FlaskGroup(create_app=create_app)
    return cli.main(
        args=args,
        prog_name="LynceusCLI",
        standalone_mode=standalone_mode,
    )


# Run initial admin setup.
def run_initial_admin_setup():
    exit_code = 0
    # Run this block with structured exception handling.
    try:
        run_cli(["create-admin"], standalone_mode=False)
    # Handle an exception raised by the preceding protected block.
    except Exception as error:
        exit_code = 1
        print(f"\nAdmin setup failed: {error}")
    # Run cleanup that must occur after the protected block.
    finally:
        # Run this block with structured exception handling.
        try:
            input("\nPress Enter to close the admin setup window...")
        # Handle an exception raised by the preceding protected block.
        except EOFError:
            pass
    return exit_code


# Handle the main operation.
def main():
    args = sys.argv[1:]
    # Handle the branch where args and args[0].lower() == 'server' evaluates to true.
    if args and args[0].lower() == "server":
        run_server()
        return
    # Handle the branch where args and args[0].lower() == 'setup-admin' evaluates to true.
    if args and args[0].lower() == "setup-admin":
        raise SystemExit(run_initial_admin_setup())
    run_cli(args)


# Handle the branch where __name__ == '__main__' evaluates to true.
if __name__ == "__main__":
    main()
