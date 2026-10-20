"""
GroundedCVE Link Health Check CLI Runner.
Runs a real network check of every external reference on the triaged
candidates, updates the link health cache, and writes a dead-link report.
"""
import argparse
import json
import logging
import sys
from pathlib import Path

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.api.data_service import DataService
from Backend.api.link_validator import link_validator, DEAD, MOVED
from Backend.config import STAGING_DIR


def main():
    parser = argparse.ArgumentParser(
        description="GroundedCVE link health check",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=STAGING_DIR / "dead_links_report.json",
        help="Where to write the list of dead or removed links",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-check every link, ignoring cached results",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    candidates = DataService().get_all_candidates()
    descriptors = [
        {"url": ref["url"], "source": ref.get("source_provider"), "type": ref.get("link_type")}
        for c in candidates
        for ref in c.get("external_references", [])
        if ref.get("url")
    ]
    print(f"Checking {len(descriptors)} references across {len(candidates)} candidates...")

    results = link_validator.validate_batch(descriptors, force_refresh=args.force)
    dead = sorted(
        (r for r in results if r.get("state") in (DEAD, MOVED)),
        key=lambda r: r["url"],
    )

    args.report.parent.mkdir(parents=True, exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(dead, f, indent=2)

    stats = link_validator.get_stats()
    print(json.dumps(stats, indent=2))
    print(f"{len(dead)} dead or removed links written to {args.report}")
    for r in dead:
        fallback = f" -> {r['archive_url']}" if r.get("archive_url") else ""
        print(f"  [{r['status_label']}] {r['url']}{fallback}")


if __name__ == "__main__":
    main()
