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
from Backend.config import STAGING_DIR
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
from Backend.ingestion.change_tracker import apply_change_tracking, load_previous
from Backend.ingestion.models import StagingEnvelope

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

    def run(
        self,
        sources: Optional[List[str]] = None,
        limit_per_source: Optional[int] = 5,
        save_output: bool = True,
        track_changes: bool = True,
        retain_days: int = 30,
        keep_snapshots: int = 0,
    ) -> Dict[str, Any]:
        """
        Executes ingestion for specified sources.
        
        Args:
            sources: List of source keys to collect from (defaults to all if None)
            limit_per_source: Max items per source collector
            save_output: Whether to persist staging envelopes to JSON file
            track_changes: Compare against the previous latest_envelopes.json, label
                items NEW/UPDATED/UNCHANGED and carry over items no longer in the feeds
            retain_days: Carried-over items not fetched for this many days are dropped
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
                items = collector.collect(limit=limit_per_source)
                
                # Optional PoC detection enrichment
                if self.enable_poc_detection and self.poc_detector:
                    for item in items:
                        if item.CVE_ID:
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
