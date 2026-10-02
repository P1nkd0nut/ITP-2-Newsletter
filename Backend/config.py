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
DEFAULT_USER_AGENT = "GroundedCVE-Bot/1.0 (Penetration Testing Threat Intelligence; SIT Team 4)"

# API Keys (optional from environment)
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

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

# Qdrant Vector Database (Task 2.1 - self-hosted via docker-compose.yml)
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", "6333"))
QDRANT_COLLECTION_ITEMS = "groundedcve_items"        # all ingested items/chunks + ranking metadata
QDRANT_COLLECTION_PUBLISHED = "groundedcve_published"  # validated, published cards (novelty check source)

# Ollama (Task 2.1 - local embedding generation)
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
EMBED_MODEL = "nomic-embed-text"
EMBED_DIM = 768
