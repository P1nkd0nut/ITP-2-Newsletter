"""
Adds NVD data to the staged items without a full pipeline run: affected
versions for NVD items from their stored NVD JSON (no network), and for CISA
KEV items the same CVE's NVD record (its text, which the next card run writes
from, and its affected versions; one NVD lookup each, use --max-lookups to pace).
The daily pipeline does the same for new items; this is for existing data.

    python Backend/run_nvd_versions.py               # NVD items + up to 40 KEV lookups
    python Backend/run_nvd_versions.py --offline     # NVD items only
"""
import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import STAGING_DIR
from Backend.ingestion.collectors.nvd import affected_versions
from Backend.ingestion.models import SourceType, StagingEnvelope
from Backend.ingestion.pipeline import IngestionPipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Add NVD data (record text, affected versions) to staged items")
    parser.add_argument("--offline", action="store_true", help="Only use stored NVD JSON; no NVD lookups")
    parser.add_argument("--max-lookups", type=int, default=40, help="NVD lookups for CISA KEV items")
    args = parser.parse_args()

    env_file = STAGING_DIR / "latest_envelopes.json"
    envelopes = [StagingEnvelope.model_validate(e) for e in json.loads(env_file.read_text(encoding="utf-8"))]

    from_json = 0
    for env in envelopes:
        if env.Source_Type == SourceType.NVD and not env.Affected_Versions:
            versions = affected_versions(json.loads(env.Raw_Content).get("configurations", []))
            if versions:
                env.Affected_Versions = versions
                from_json += 1
    looked_up = 0 if args.offline else IngestionPipeline(staging_dir=STAGING_DIR).add_nvd_versions(
        envelopes, max_lookups=args.max_lookups
    )
    env_file.write_text(json.dumps([e.model_dump() for e in envelopes], indent=2, ensure_ascii=False), encoding="utf-8")

    # Copy the new fields onto the triaged candidates so the dashboard shows them without re-triaging
    by_id = {e.Item_ID: e for e in envelopes}
    cand_file = STAGING_DIR / "triaged_candidates.json"
    if cand_file.exists():
        candidates = json.loads(cand_file.read_text(encoding="utf-8"))
        for c in candidates:
            env = by_id.get(c["envelope"]["Item_ID"])
            if env is not None:
                c["envelope"]["Affected_Versions"] = env.Affected_Versions
                c["envelope"]["Extra_Metadata"] = env.Extra_Metadata
        cand_file.write_text(json.dumps(candidates, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Affected versions added to {from_json} NVD items (from stored JSON); "
          f"NVD record added to {looked_up} CISA KEV items. Their cards are rewritten on the next card run.")


if __name__ == "__main__":
    main()
