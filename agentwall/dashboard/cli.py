from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentWall Dashboard")
    parser.add_argument("--db", default="./agentwall_events.db", help="SQLite database path")
    parser.add_argument("--port", type=int, default=8501, help="Port to run on")
    args = parser.parse_args()

    cmd = [
        sys.executable, "-m", "streamlit", "run",
        "agentwall/dashboard/app.py",
        "--server.port", str(args.port),
        "--server.headless", "true",
    ]
    subprocess.run(cmd)


if __name__ == "__main__":
    main()
