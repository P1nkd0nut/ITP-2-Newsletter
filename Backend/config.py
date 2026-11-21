"""
Configuration settings for GroundedCVE Ingestion Pipeline.
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STAGING_DIR = DATA_DIR / "staging"

# Ensure directories exist
STAGING_DIR.mkdir(parents=True, exist_ok=True)

# User-Agent string for polite threat intelligence scraping
DEFAULT_USER_AGENT = "GroundedCVE-Bot/1.0 (Penetration Testing Threat Intelligence)"

# Auto-load .env file if present in project root
ENV_FILE = BASE_DIR.parent / ".env"
if ENV_FILE.exists():
    with open(ENV_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))

# API Keys (optional from environment or .env)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "qwen/qwen-2.5-72b-instruct")

# Ingestion Source Endpoints
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
PORTSWIGGER_RSS_URL = "https://portswigger.net/research/rss"
PROJECT_ZERO_RSS_URL = "https://googleprojectzero.blogspot.com/feeds/posts/default"
FRIDA_RELEASES_URL = "https://api.github.com/repos/frida/frida/releases"
ANDROID_BULLETIN_INDEX_URL = "https://source.android.com/docs/security/bulletin"
APPLE_SECURITY_RELEASES_URL = "https://support.apple.com/en-us/100100"

# Target Web Ecosystems for GitHub Advisories
WEB_ECOSYSTEMS = ["npm", "pip", "go", "maven"]

# Default Collection Limits (can be overridden via CLI)
DEFAULT_ITEM_LIMIT = 5
DEFAULT_DAYS_BACK = 7
# NVD publishes hundreds of CVEs a week, far more than the other feeds, so it may
# take more per run than the shared per-source limit (0 = use that limit).
NVD_LIMIT = int(os.getenv("NVD_LIMIT", "0") or 0)

# Qdrant Vector Database (Task 2.1 - self-hosted via docker-compose.yml)
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))
QDRANT_COLLECTION_ITEMS = "groundedcve_items"        # all ingested items/chunks + ranking metadata
QDRANT_COLLECTION_PUBLISHED = "groundedcve_published"  # validated, published cards (novelty check source)

# Ollama (Task 2.1 - local embedding generation)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
EMBED_MODEL = "nomic-embed-text"
EMBED_DIM = 768

# Chunking (Task 2.2 - two-tier heading-aware chunking)
CHUNK_TIER1_MAX_CHARS = 2500   # Executive Summary Tier cap
CHUNK_TIER2_MAX_CHARS = 5000   # Technical PoC / Evidence Tier cap
CHUNK_MIN_MERGE_CHARS = 400    # start a new chunk at a new h1/h2 section once the buffer has this much
CHUNK_THIN_SOURCE_CHARS = 300  # cleaned text shorter than this is flagged "thin_source"
CHUNKS_FILE = STAGING_DIR / "latest_chunks.json"

# Grounded summaries (Task 3.1) - only gate-PASSED cards are written here and published
GROUNDED_CARDS_FILE = STAGING_DIR / "grounded_cards.json"
QUARANTINE_LOG_FILE = STAGING_DIR / "quarantine_log.jsonl"
SUMMARY_TOP_K_CHUNKS = 8
