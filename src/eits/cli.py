"""Small local analyst CLI; JSON output is both human-readable and scriptable."""

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

import duckdb

from .adapters import source_catalog
from .db import connect, evidence, ingest, rows
from .engine import detect, explain, hunt, hunt_catalog, revisions
from .evaluation import evaluate
from .model import digest


def serialize(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"unsupported JSON value {type(value).__name__}")


def emit(value, output=None):
    rendered = json.dumps(value, indent=2, default=serialize) + "\n"
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x") as stream:  # Preserve earlier evaluation results by default.
            stream.write(rendered)
        print(json.dumps({"written": str(path)}))
    else:
        print(rendered, end="")


def parser():
    root = argparse.ArgumentParser(
        description="Eye in the Sky — local evidence-backed detection engineering"
    )
    root.add_argument(
        "--db", default="work/eye.duckdb", help="local database (default: work/eye.duckdb)"
    )
    commands = root.add_subparsers(dest="command", required=True)
    command = commands.add_parser(
        "ingest", help="verify provenance and ingest files through their source adapter"
    )
    command.add_argument("manifest")
    for name in ("detect", "explain"):
        command = commands.add_parser(name)
        command.add_argument("--revision", choices=revisions(), default="baseline")
        if name == "explain":
            command.add_argument("finding_id")
    command = commands.add_parser(
        "event", help="inspect a source event ID or an internal event UID"
    )
    command.add_argument("event_id")
    command = commands.add_parser("hunt", help="run an exploratory SQL hunt")
    hunts = hunt_catalog()
    default_hunt = next(key for key, value in hunts.items() if value.get("default"))
    command.add_argument("--hunt-id", choices=tuple(hunts), default=default_hunt)
    command.add_argument("--hours", type=float, default=24)
    commands.add_parser("status", help="show only locally demonstrated dataset and event counts")
    command = commands.add_parser(
        "export-raw", help="export exact stored source bytes, verifying their hash"
    )
    command.add_argument("sha256")
    command.add_argument("output")
    command = commands.add_parser(
        "evaluate", help="isolated in-memory run with separate ground truth"
    )
    command.add_argument("--manifest", default="fixtures/aws/synthetic/manifest.json")
    command.add_argument("--truth", default="evaluation/ground_truth.json")
    command.add_argument("--revision", choices=revisions(), default="baseline")
    command.add_argument("--split", choices=["all", "development", "holdout"], default="all")
    command.add_argument("--output", help="new report path; existing reports are never overwritten")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    connection = None
    try:
        if args.command == "evaluate":
            emit(evaluate(args.manifest, args.truth, args.revision, args.split), args.output)
            return 0
        connection = connect(args.db)
        if args.command == "ingest":
            result = ingest(connection, args.manifest)
        elif args.command == "detect":
            result = detect(connection, args.revision)
        elif args.command == "explain":
            result = explain(connection, args.finding_id, args.revision)
        elif args.command == "event":
            candidates = rows(
                connection,
                "SELECT event_uid FROM events WHERE event_uid=? OR source_event_id=?",
                [args.event_id, args.event_id],
            )
            if len(candidates) != 1:
                raise ValueError("event ID is unknown or nonunique; use the internal event_uid")
            result = evidence(connection, candidates[0]["event_uid"])
        elif args.command == "hunt":
            result = {
                "hunt_id": args.hunt_id,
                "hours": args.hours,
                "verdict": "investigative leads, not malicious classifications",
                "results": hunt(connection, args.hours, hunt_id=args.hunt_id),
            }
        elif args.command == "status":
            sources = source_catalog()
            result = {
                "phase": 1,
                "schema_version": connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
                "providers_implemented": sorted(
                    {source["provider"] for source in sources if source["implemented"]}
                ),
                "sources": sources,
                "live_validation": "not established by this command",
                "events": rows(
                    connection,
                    "SELECT provider, source, count(*) AS count FROM events GROUP BY provider,source",
                ),
                "datasets": rows(
                    connection,
                    "SELECT dataset_id, json_extract_string(manifest, '$.category') AS category FROM datasets ORDER BY dataset_id",
                ),
            }
        elif args.command == "export-raw":
            row = connection.execute(
                "SELECT content FROM artifacts WHERE sha256=?", [args.sha256]
            ).fetchone()
            if not row:
                raise ValueError("unknown raw artifact hash")
            content = bytes(row[0])
            if digest(content) != args.sha256:
                raise ValueError("stored artifact integrity check failed")
            path = Path(args.output)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(content)
            result = {"exported": str(path), "sha256": args.sha256, "bytes": len(content)}
        emit(result)
        return 0
    except (ValueError, OSError, KeyError, duckdb.Error) as exc:
        print(f"eits: {exc}", file=sys.stderr)
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
