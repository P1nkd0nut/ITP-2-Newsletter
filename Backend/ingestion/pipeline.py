"""
Ingestion Pipeline Orchestrator.
Coordinates threat feed collection across multiple sources, applies envelope
standardization, optionally enriches with PoC repositories, and saves to staging.
"""
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from Backend.config import NVD_LIMIT, STAGING_DIR
from Backend.ingestion.collectors import (
    BaseCollector,
    CisaKevCollector,
    NvdCollector,
    create_portswigger_collector,
    create_project_zero_collector,
    GitHubAdvisoryCollector,
    FridaCollector,
    AndroidBulletinCollector,
    AppleSecurityCollector,
    GitHubPoCDetector,
)
from Backend.ingestion.change_tracker import UNCHANGED, UPDATED, apply_change_tracking, describe_changes, load_previous, merge_recheck
from Backend.ingestion.recheck_policy import is_due, is_frozen
from Backend.ingestion.models import SourceType, StagingEnvelope

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """Orchestrates multi-source threat intelligence collection."""

    def __init__(self, staging_dir: Optional[Path] = None, enable_poc_detection: bool = False):
        self.staging_dir = staging_dir or STAGING_DIR
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.enable_poc_detection = enable_poc_detection
        self.poc_detector = GitHubPoCDetector() if enable_poc_detection else None

        # Registry of available collectors
        self.registry: Dict[str, BaseCollector] = {
            "cisa_kev": CisaKevCollector(),
            "nvd": NvdCollector(),
            "portswigger": create_portswigger_collector(),
            "project_zero": create_project_zero_collector(),
            "github_advisory": GitHubAdvisoryCollector(),
            "frida": FridaCollector(),
            "android_bulletin": AndroidBulletinCollector(),
            "apple_security": AppleSecurityCollector(),
        }

    def list_available_sources(self) -> List[str]:
        return list(self.registry.keys())

    def _recheck_due_items(self, items: List[StagingEnvelope], now: datetime):
        """
        Re-checks items that were not in this run's feeds but are due under the age
        policy: NVD records are fetched again and PoC search is repeated.
        """
        now_iso = now.isoformat()
        nvd = self.registry.get("nvd")
        counts = {"RECHECKED": 0, "RECHECK_UPDATED": 0}
        result: List[StagingEnvelope] = []
        for item in items:
            carried_over = item.Last_Seen is not None and item.Last_Seen < now_iso
            if not (carried_over and item.CVE_ID and is_due(item.Published_Date, item.Last_Checked, now)):
                result.append(item)
                continue

            updated = item
            if item.Source_Type == SourceType.NVD and nvd is not None and hasattr(nvd, "fetch_by_cve_id"):
                fresh = nvd.fetch_by_cve_id(item.CVE_ID)
                if fresh is None:
                    result.append(item)  # fetch failed; try again next run
                    continue
                if self.poc_detector:
                    self.poc_detector.enrich_envelope_with_pocs(fresh, limit=2)
                updated = merge_recheck(item, fresh, now_iso)
            elif self.poc_detector:
                before = item.model_copy(deep=True)
                self.poc_detector.enrich_envelope_with_pocs(item, limit=2)
                changes = describe_changes(before, item)
                item.Last_Checked = now_iso
                if changes:
                    item.Change_Status, item.Change_Summary, item.Last_Changed = UPDATED, changes, now_iso
            else:
                result.append(item)
                continue

            counts["RECHECKED"] += 1
            if updated.Change_Status == UPDATED and updated.Last_Changed == now_iso:
                counts["RECHECK_UPDATED"] += 1
            result.append(updated)
        return result, counts

    def run(
        self,
        sources: Optional[List[str]] = None,
        limit_per_source: Optional[int] = 5,
        save_output: bool = True,
        track_changes: bool = True,
        retain_days: Optional[int] = None,
        keep_snapshots: int = 0,
        recheck_older: bool = True,
    ) -> Dict[str, Any]:
        """
        Executes ingestion for specified sources.
        
        Args:
            sources: List of source keys to collect from (defaults to all if None)
            limit_per_source: Max items per source collector
            save_output: Whether to persist staging envelopes to JSON file
            track_changes: Compare against the previous latest_envelopes.json, label
                items NEW/UPDATED/UNCHANGED and carry over items no longer in the feeds
            retain_days: If set, carried-over items not fetched for this many days are
                dropped. By default the age policy applies instead (see recheck_policy)
            recheck_older: Re-check items that dropped out of the feeds when their age
                tier says they are due. CVEs older than a year are never updated
            keep_snapshots: Also write a timestamped envelopes_*.json and keep only the
                newest N of them (0 = write none and leave existing ones alone)
            
        Returns:
            Dict containing ingestion summary, metrics, and envelope objects.
        """
        target_keys = sources if sources else list(self.registry.keys())
        start_time = datetime.now(timezone.utc)
        all_envelopes: List[StagingEnvelope] = []
        source_counts: Dict[str, int] = {}
        errors: Dict[str, str] = {}

        for key in target_keys:
            collector = self.registry.get(key)
            if not collector:
                logger.warning(f"Unknown collector source requested: '{key}'")
                continue

            try:
                logger.info(f"Running collector: {collector.name}")
                limit = limit_per_source
                if key == "nvd" and NVD_LIMIT and limit_per_source:
                    limit = max(limit_per_source, NVD_LIMIT)
                items = collector.collect(limit=limit)
                
                # Optional PoC detection enrichment
                if self.enable_poc_detection and self.poc_detector:
                    for item in items:
                        if item.CVE_ID and not is_frozen(item.Published_Date, start_time):
                            self.poc_detector.enrich_envelope_with_pocs(item, limit=2)

                all_envelopes.extend(items)
                source_counts[collector.name] = len(items)

            except Exception as e:
                logger.error(f"Error executing collector '{key}': {e}", exc_info=True)
                errors[key] = str(e)
                source_counts[key] = 0

        # Deduplicate envelopes by Content_Hash while preserving order
        unique_envelopes: List[StagingEnvelope] = []
        seen_hashes = set()
        for env in all_envelopes:
            if env.Content_Hash not in seen_hashes:
                seen_hashes.add(env.Content_Hash)
                unique_envelopes.append(env)

        latest_file = self.staging_dir / "latest_envelopes.json"
        change_counts: Dict[str, int] = {}
        if track_changes and unique_envelopes:
            unique_envelopes, change_counts = apply_change_tracking(
                unique_envelopes, load_previous(latest_file), retain_days=retain_days, now=start_time
            )

        if recheck_older and unique_envelopes:
            unique_envelopes, rechecked = self._recheck_due_items(unique_envelopes, start_time)
            change_counts.update(rechecked)

        end_time = datetime.now(timezone.utc)
        duration_seconds = round((end_time - start_time).total_seconds(), 2)

        output_file_path: Optional[str] = None
        if save_output and unique_envelopes:
            json_data = [env.model_dump() for env in unique_envelopes]
            with open(latest_file, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            output_file_path = str(latest_file)

            if keep_snapshots > 0:
                timestamp_str = start_time.strftime("%Y%m%d_%H%M%S")
                snapshot_file = self.staging_dir / f"envelopes_{timestamp_str}.json"
                with open(snapshot_file, "w", encoding="utf-8") as f:
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
                output_file_path = str(snapshot_file)
                for stale in sorted(self.staging_dir.glob("envelopes_*.json"))[:-keep_snapshots]:
                    stale.unlink()

            # Sync to Frontend/data.js for instant browser dashboard visualization
            frontend_dir = self.staging_dir.parent.parent / "Frontend"
            if frontend_dir.exists():
                frontend_data_js = frontend_dir / "data.js"
                with open(frontend_data_js, "w", encoding="utf-8") as f:
                    f.write("window.INITIAL_ENVELOPES = " + json.dumps(json_data, ensure_ascii=False) + ";")

            logger.info(f"Persisted {len(unique_envelopes)} staging envelopes to {latest_file}")

        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration_seconds,
            "total_collected": len(all_envelopes),
            "unique_envelopes": len(unique_envelopes),
            "source_counts": source_counts,
            "errors": errors,
            "change_counts": change_counts,
            "output_file": output_file_path,
            "envelopes": unique_envelopes,
        }
