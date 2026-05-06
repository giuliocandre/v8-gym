from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="verify-task",
        description="Run a command under Frida and score it against the expected v8gym backtrace.",
        usage="verify-task --task-id ID [--timeout N] [--threshold F] -- <command> [args...]",
    )
    parser.add_argument("--task-id", type=int, required=True, help="Task ID from the dataset")
    parser.add_argument("--timeout", type=int, default=60, help="Seconds before killing the process (default: 60)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Match threshold for success (default: 0.5)")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run (after --)")

    args = parser.parse_args()

    cmd_parts = args.command
    if cmd_parts and cmd_parts[0] == "--":
        cmd_parts = cmd_parts[1:]

    if not cmd_parts:
        parser.error("No command provided. Usage: verify-task --task-id ID -- <command> [args...]")

    command_line = " ".join(cmd_parts)

    from v8gym._gym import VerifyTask

    result = VerifyTask(
        task_id=args.task_id,
        command_line=command_line,
        timeout=args.timeout,
        match_threshold=args.threshold,
    )

    print()
    print(f"crashed : {result.crashed}")
    print(f"score   : {result.score:.3f}")
    print(f"success : {result.success}")
    if result.crashed:
        print(f"exc type: {result.exception_type}")
        print(f"address : {result.address}")
        print()
        print("captured backtrace:")
        print(json.dumps(result.captured_backtrace, indent=2))

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
