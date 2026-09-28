import json
import urllib.request
import time
import sys

# Official CISA Known Exploited Vulnerabilities (KEV) Catalog (No API key needed)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_live_threat_data():
    print("\n" + "="*65)
    print("🌐 [STAGE 1: LIVE INGESTION] FETCHING FROM CISA KEV CATALOG...")
    print("="*65)
    
    headers = {"User-Agent": "GroundedCVE-Ingest/1.0 (Academic Research; SIT ICT2114)"}
    req = urllib.request.Request(CISA_KEV_URL, headers=headers)
    
    try:
        start_time = time.time()
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        latency = round(time.time() - start_time, 2)
        
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"  ✅ Connection successful! Retrieved catalog containing {len(vulnerabilities)} vulnerabilities ({latency}s).")
        
        # Pick the latest actively weaponized vulnerability added to the catalog
        latest_vuln = vulnerabilities[-1]
        return latest_vuln
        
    except Exception as e:
        print(f"  ❌ Error fetching live feed: {e}")
        sys.exit(1)

def normalize_to_staging_envelope(raw):
    print("\n" + "="*65)
    print("📦 [STAGE 2: NORMALIZATION] BUILDING STANDARDIZED ENVELOPE...")
    print("="*65)
    
    # 100% deterministic field extraction directly from authentic source (Zero LLM / Zero Hallucination)
    envelope = {
        "item_id": f"CISA-KEV-{raw['cveID']}",
        "cve_id": raw["cveID"],
        "vendor": raw["vendorProject"],
        "product": raw["product"],
        "vulnerability_name": raw["vulnerabilityName"],
        "date_added": raw["dateAdded"],
        "short_description": raw["shortDescription"],
        "required_action": raw["requiredAction"],
        "official_nvd_url": f"https://nvd.nist.gov/vuln/detail/{raw['cveID']}",
        "kev_catalog_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    }
    
    print(json.dumps(envelope, indent=2))
    return envelope

def render_grounded_telegram_card(env):
    print("\n" + "="*65)
    print("📱 [STAGE 8: VERIFIED DISPATCH] TELEGRAM CARD (ZERO HALLUCINATION)")
    print("="*65)
    
    card = (
        f"🚨 [ACTIVE WEAPONIZATION ALERT]\n"
        f"📌 {env['cve_id']} — {env['vulnerability_name']}\n"
        f"🏢 Vendor / Product: {env['vendor']} ({env['product']})\n"
        f"📅 Date Added to KEV: {env['date_added']}\n\n"
        f"💡 Description (Verbatim Source Grounded):\n"
        f"{env['short_description']}\n\n"
        f"🛡️ Required Action:\n"
        f"{env['required_action']}\n\n"
        f"🔗 Verified Compliance Links:\n"
        f"• NVD Record: {env['official_nvd_url']}\n"
        f"• CISA Advisory: {env['kev_catalog_url']}\n"
    )
    print(card)
    print("="*65)

if __name__ == "__main__":
    raw_data = fetch_live_threat_data()
    envelope = normalize_to_staging_envelope(raw_data)
    render_grounded_telegram_card(envelope)
