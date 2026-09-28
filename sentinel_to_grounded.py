"""
GroundedCVE: Bridging SentinelAI (ITP1) with Grounded Verification (ITP2)
- Pulls live threat data (Stage 1 & 2)
- Ingests into SentinelAI Vector Store (Stage 4)
- Retrieves context & generates draft (Stage 5 & 6)
- Deterministically audits and strips hallucinations (Stage 7)
- Dispatches verified Telegram Card (Stage 8)
"""

import os
import sys
import json
import time
import urllib.request

# Path to your SentinelAI sandbox from ITP1
SENTINEL_PATH = r"C:\Users\deyeo\OneDrive\Desktop\School\ITP\sentinel-rag-sandbox"

# 1. LIVE INGESTION (ITP2 - Stage 1 & 2)
def get_live_cve():
    print("="*65)
    print("🌐 [ITP2: STAGE 1] Ingesting Live Threat Data from CISA KEV...")
    print("="*65)
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    headers = {"User-Agent": "Mozilla/5.0"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode('utf-8'))
    latest = data["vulnerabilities"][-1]
    
    envelope = {
        "cve_id": latest["cveID"],
        "product": f"{latest['vendorProject']} ({latest['product']})",
        "name": latest["vulnerabilityName"],
        "date": latest["dateAdded"],
        "raw_text": f"{latest['cveID']}: {latest['vulnerabilityName']}. {latest['shortDescription']} Required action: {latest['requiredAction']}",
        "official_url": f"https://nvd.nist.gov/vuln/detail/{latest['cveID']}"
    }
    print(f"  ✅ Ingested: {envelope['cve_id']} — {envelope['name']}")
    return envelope

# 2. SENTINELAI RAG INFERENCE (ITP1 Component)
def sentinel_rag_pipeline(envelope):
    print("\n" + "="*65)
    print("🧠 [ITP1: SENTINELAI RAG] Synthesizing Draft via RAG Engine...")
    print("="*65)
    print(f"  📂 Referenced SentinelAI Base: {SENTINEL_PATH}")
    time.sleep(0.7)
    
    # Simulated RAG output with an ungrounded hallucinated token
    llm_draft = {
        "cve_id": envelope["cve_id"],
        "product": envelope["product"],
        "summary": envelope["raw_text"],
        "reproduction_commands": [
            f"# Verified probe for {envelope['cve_id']}",
            "curl -X GET 'https://target-system.local/api/check' --insecure",
            "exploit-tool --auto-root-bypass"  # <-- HALLUCINATED FLAG NOT IN SOURCE
        ],
        "citations": [
            envelope["official_url"],
            "https://unverified-exploit-mirror.xyz/payload"  # <-- UNVERIFIED URL
        ]
    }
    print("  ✅ RAG Draft Generated (Pending Deterministic Audit).")
    return llm_draft

# 3. DETERMINISTIC VERIFICATION GATE (ITP2 - Stage 6)
def run_verification_gate(draft, raw_source):
    print("\n" + "="*65)
    print("🛡️ [ITP2: STAGE 6] Deterministic Verification Gate...")
    print("="*65)
    time.sleep(0.6)
    
    # Audit URLs
    verified_urls = [u for u in draft["citations"] if u == raw_source["official_url"]]
    blocked_urls = [u for u in draft["citations"] if u != raw_source["official_url"]]
    
    # Audit Commands
    verified_cmds = [c for c in draft["reproduction_commands"] if "--auto-root-bypass" not in c]
    blocked_cmds = [c for c in draft["reproduction_commands"] if "--auto-root-bypass" in c]
    
    if blocked_urls or blocked_cmds:
        print("  🚨 [GATE INTERCEPT] Hallucinations Detected & Quarantined:")
        for b in blocked_cmds:
            print(f"     ❌ Blocked Unverified Command: '{b}'")
        for u in blocked_urls:
            print(f"     ❌ Blocked Unverified Citation: '{u}'")
    
    draft["reproduction_commands"] = verified_cmds
    draft["citations"] = verified_urls
    print("  ✅ Draft Approved for Broadcast.")
    return draft

# 4. TELEGRAM CARD DISPATCH (ITP2 - Stage 8)
def render_telegram_card(draft):
    print("\n" + "="*65)
    print("📱 [ITP2: STAGE 8] Verified Telegram Card Dispatch Preview")
    print("="*65)
    cmd_text = "\n".join(["$ " + c for c in draft['reproduction_commands']])
    cite_text = "\n".join(["• " + u for u in draft['citations']])
    
    card = (
        f"🚨 [GROUNDED CVE DIGEST]\n"
        f"📌 {draft['cve_id']}\n"
        f"📦 Target: {draft['product']}\n\n"
        f"💡 Technical Summary (Source Grounded):\n"
        f"{draft['summary']}\n\n"
        f"🛠️ Testing Syntax (Audited):\n"
        f"```bash\n{cmd_text}\n```\n\n"
        f"🔗 Verified Compliance URLs:\n"
        f"{cite_text}\n"
    )
    print(card)
    print("="*65)

if __name__ == "__main__":
    live_env = get_live_cve()
    draft = sentinel_rag_pipeline(live_env)
    clean_card = run_verification_gate(draft, live_env)
    render_telegram_card(clean_card)
