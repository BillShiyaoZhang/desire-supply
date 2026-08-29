"""Run the disposable local-synthetic server on an IPv4 loopback address."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .http import LocalSyntheticHTTPServer
from .service import LocalSyntheticError, LocalSyntheticService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the loopback-only synthetic role platform.")
    parser.add_argument("--database", required=True, help="Absolute path to the disposable SQLite file.")
    parser.add_argument("--host", default="127.0.0.1", help="Must be exactly 127.0.0.1.")
    parser.add_argument("--port", default=8000, type=int, help="Loopback port (default: 8000).")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.host != "127.0.0.1":
        print("ERROR: host must be exactly 127.0.0.1", file=sys.stderr)
        return 2
    database = Path(args.database).expanduser()
    if not database.is_absolute():
        print("ERROR: --database must be an absolute path", file=sys.stderr)
        return 2
    try:
        service = LocalSyntheticService(str(database))
        server = LocalSyntheticHTTPServer((args.host, args.port), service)
    except (OSError, ValueError, LocalSyntheticError) as error:
        print("ERROR: local synthetic server failed closed: {}".format(error), file=sys.stderr)
        return 1
    host, port = server.server_address
    print("LOCAL_SYNTHETIC · G1 NO-GO · G2 NO-GO · no external side effects", flush=True)
    print("Listening only on http://{}:{}".format(host, port), flush=True)
    print("Database: {} (disposable synthetic state; never publish or back up)".format(database), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nStopping local synthetic server.", flush=True)
    finally:
        server.server_close()
        service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
