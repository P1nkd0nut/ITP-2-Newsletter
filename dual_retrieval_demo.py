"""
GroundedCVE: Core Dual Retrieval & Reciprocal Rank Fusion (RRF) Engine
Demonstrates Task 2.3 from Proposal (No LLM required):
- Dense Semantic Track (concept matching)
- Sparse Lexical / BM25 Track (exact token & CVE matching)
- Reciprocal Rank Fusion (RRF, k=60) mathematical rank fusion
"""

import math
import re
from collections import Counter

# --- SAMPLE INGESTED THREAT KNOWLEDGE BASE ---
DOCUMENTS = [
    {
        "id": "DOC-1",
        "title": "CVE-2024-0044: Android Package Installer ADB Privilege Escalation",
        "content": "Google Android OS vulnerability allowing attackers to bypass package isolation via newline injection in ADB pm install."
    },
    {
        "id": "DOC-2",
        "title": "PortSwigger Research: HTTP Request Smuggling & Desync Attacks",
        "content": "Novel web protocol desynchronization techniques exploiting TE.CL and CL.TE front-end server discrepancies for cache poisoning."
    },
    {
        "id": "DOC-3",
        "title": "iOS Runtime Instrumentation: Dynamic Hooking Bypasses via Frida",
        "content": "Techniques for subverting SSL pinning and jailbreak detection on iOS 17 using Frida dynamic binary instrumentation scripts."
    },
    {
        "id": "DOC-4",
        "title": "CVE-2024-21413: Microsoft Outlook Remote Code Execution",
        "content": "Critical Moniker Link vulnerability in Outlook bypassing Office Protected View when handling malicious file:// hyperlinks."
    }
]

# --- 1. SPARSE LEXICAL (BM25) SEARCH TRACK ---
def tokenize(text):
    return re.findall(r'[A-Za-z0-9\-\.]+', text.lower())

def sparse_bm25_search(query, docs, k1=1.5, b=0.75):
    query_tokens = tokenize(query)
    doc_lens = [len(tokenize(d["title"] + " " + d["content"])) for d in docs]
    avg_len = sum(doc_lens) / len(docs) if docs else 1
    N = len(docs)
    
    scores = {}
    for i, doc in enumerate(docs):
        text = tokenize(doc["title"] + " " + doc["content"])
        tf_map = Counter(text)
        doc_score = 0.0
        
        for q in query_tokens:
            if q in tf_map:
                # Document frequency for q
                df = sum(1 for d in docs if q in tokenize(d["title"] + " " + d["content"]))
                idf = math.log((N - df + 0.5) / (df + 0.5) + 1.0)
                tf = tf_map[q]
                numerator = tf * (k1 + 1)
                denominator = tf + k1 * (1 - b + b * (doc_lens[i] / avg_len))
                doc_score += idf * (numerator / denominator)
        scores[doc["id"]] = doc_score
        
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return ranked

# --- 2. DENSE SEMANTIC SIMILARITY TRACK (Vector Cosine Simulation) ---
# Pre-computed semantic affinity weights for demonstration
SEMANTIC_AFFINITIES = {
    "mobile hooking bypass": {
        "DOC-3": 0.89,  # Frida iOS hooking (Highest semantic match)
        "DOC-1": 0.65,  # Android ADB exploit (Relevant mobile context)
        "DOC-4": 0.22,
        "DOC-2": 0.15
    },
    "CVE-2024-0044": {
        "DOC-1": 0.72,  # Dense vector sees some context
        "DOC-4": 0.68,  # Mistakenly thinks another CVE is almost equally close!
        "DOC-2": 0.30,
        "DOC-3": 0.25
    }
}

def dense_semantic_search(query, docs):
    affinities = SEMANTIC_AFFINITIES.get(query, {})
    scores = {d["id"]: affinities.get(d["id"], 0.1) for d in docs}
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return ranked

# --- 3. RECIPROCAL RANK FUSION (RRF, k=60) ---
def reciprocal_rank_fusion(dense_ranks, sparse_ranks, k=60):
    rrf_scores = Counter()
    
    # Process Dense ranks
    for rank_idx, (doc_id, _) in enumerate(dense_ranks):
        rrf_scores[doc_id] += 1.0 / (k + (rank_idx + 1))
        
    # Process Sparse ranks
    for rank_idx, (doc_id, _) in enumerate(sparse_ranks):
        rrf_scores[doc_id] += 1.0 / (k + (rank_idx + 1))
        
    fused_ranking = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)
    return fused_ranking

def run_retrieval_experiment(query):
    print("\n" + "="*70)
    print(f"🔎 EXECUTING DUAL RETRIEVAL QUERY: '{query}'")
    print("="*70)
    
    dense_res = dense_semantic_search(query, DOCUMENTS)
    sparse_res = sparse_bm25_search(query, DOCUMENTS)
    fused_res = reciprocal_rank_fusion(dense_res, sparse_res, k=60)
    
    doc_lookup = {d["id"]: d["title"] for d in DOCUMENTS}
    
    print("\n1️⃣  Dense Semantic Track (Concepts & Synonyms):")
    for r, (doc_id, score) in enumerate(dense_res, 1):
        print(f"   Rank {r}: [{doc_id}] {doc_lookup[doc_id][:50]}... (Score: {score:.3f})")
        
    print("\n2️⃣  Sparse Lexical Track (BM25 Exact Keyword/CVE):")
    for r, (doc_id, score) in enumerate(sparse_res, 1):
        print(f"   Rank {r}: [{doc_id}] {doc_lookup[doc_id][:50]}... (BM25: {score:.3f})")
        
    print("\n3️⃣  FUSED RESULT -> Reciprocal Rank Fusion (RRF, k=60):")
    for r, (doc_id, score) in enumerate(fused_res, 1):
        star = "🌟 [TOP MATCH]" if r == 1 else "             "
        print(f"   {star} Rank {r}: [{doc_id}] {doc_lookup[doc_id]}")
        print(f"                     RRF Score: {score:.5f}")

if __name__ == "__main__":
    print("🚀 Initializing GroundedCVE Dual-Track Retrieval Prototype...")
    # Test 1: Conceptual query where Dense shines
    run_retrieval_experiment("mobile hooking bypass")
    
    # Test 2: Exact identifier query where BM25 shines
    run_retrieval_experiment("CVE-2024-0044")
