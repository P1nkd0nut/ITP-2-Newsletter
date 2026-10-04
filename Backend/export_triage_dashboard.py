"""
Exports the GroundedCVE Triage & Scoring Dashboard as a self-contained HTML artifact
compatible with Google Antigravity Generative UI.
"""
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
TRIAGED_FILE = ROOT_DIR / "Backend" / "data" / "staging" / "triaged_candidates.json"
ARTIFACT_PATH = Path(r"C:\Users\deyeo\.gemini\antigravity\brain\1deaf1fb-e3d6-4f1e-8f21-644188d5c466\groundedcve_triage_dashboard.html")

data = []
if TRIAGED_FILE.exists():
    with open(TRIAGED_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

# Sort candidates by priority score descending
data.sort(key=lambda x: x.get("priority_score", 0.0), reverse=True)

json_data_str = json.dumps(data, ensure_ascii=False)

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GroundedCVE - Pentest Pre-Filter & AI Priority Scoring Dashboard</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    pre, code, .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
  </style>
</head>
<body class="bg-slate-950 text-slate-100 p-6 min-h-screen antialiased selection:bg-cyan-500 selection:text-black">

  <!-- Header -->
  <header class="border-b border-slate-800 pb-5 mb-6 flex flex-wrap items-center justify-between gap-4">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-emerald-400 flex items-center justify-center font-bold text-black font-mono shadow-lg shadow-cyan-500/20 text-lg">
        GC
      </div>
      <div>
        <div class="flex items-center gap-2">
          <h1 class="text-xl font-bold tracking-tight text-white">GroundedCVE Triage & AI Priority Leaderboard</h1>
          <span class="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-950 text-cyan-400 border border-cyan-800">100-Point Formula</span>
        </div>
        <p class="text-xs text-slate-400">Lead DevOps & Performance Validation &bull; Tan De Ye (SIT Team 4)</p>
      </div>
    </div>
    <div class="text-right">
      <span class="text-xs text-emerald-400 font-mono flex items-center gap-1.5 justify-end">
        <span class="h-2 w-2 rounded-full bg-emerald-400 inline-block animate-pulse"></span>
        CVSS Anomaly Gate Active (|&Delta;| &ge; 4.0)
      </span>
      <span class="text-xs text-slate-400">40 KEV + 40 AI Severity + 20 PoC</span>
    </div>
  </header>

  <!-- KPI Metrics -->
  <section class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Evaluated</span>
      <p id="kpiTotal" class="text-3xl font-extrabold text-white mt-1 font-mono">0</p>
      <span class="text-xs text-slate-500">Ingested disclosures</span>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <span class="text-xs font-semibold text-cyan-400 uppercase tracking-wider">In-Scope (Web / Mobile)</span>
      <p id="kpiInScope" class="text-3xl font-extrabold text-cyan-400 mt-1 font-mono">0</p>
      <span class="text-xs text-slate-500">Passed Pre-Filter Gate</span>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Out of Scope</span>
      <p id="kpiOutOfScope" class="text-3xl font-extrabold text-slate-400 mt-1 font-mono">0</p>
      <span class="text-xs text-slate-500">Bypassed (0.0 pts)</span>
    </div>
    <div class="bg-slate-900 border border-rose-900/40 rounded-xl p-4">
      <span class="text-xs font-semibold text-rose-400 uppercase tracking-wider">CVSS Anomalies</span>
      <p id="kpiAnomalies" class="text-3xl font-extrabold text-rose-400 mt-1 font-mono">0</p>
      <span class="text-xs text-slate-500">|AI - CVSS| &ge; 4.0</span>
    </div>
  </section>

  <!-- Anomaly Alert Banner (if any) -->
  <section id="anomalyBanner" class="mb-6 hidden">
    <div class="bg-rose-950/40 border border-rose-800/80 rounded-xl p-4">
      <div class="flex items-center gap-2 mb-2">
        <span class="px-2 py-0.5 rounded bg-rose-900 text-rose-200 text-xs font-bold font-mono">ANOMALY DETECTED</span>
        <h2 class="text-sm font-bold text-white">CVSS Discrepancy Gate Alerts Triggered</h2>
      </div>
      <p class="text-xs text-rose-300/90 mb-3">
        The following disclosures exhibit critical divergence between the official CVSS score and practical AI severity analysis.
      </p>
      <div id="anomalyList" class="space-y-2"></div>
    </div>
  </section>

  <!-- Filter & Tab Toolbar -->
  <section class="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-6 flex flex-col md:flex-row items-center justify-between gap-3">
    <div class="flex flex-wrap items-center gap-2 text-xs" id="filterTabs">
      <button onclick="setFilter('ALL')" id="btnALL" class="px-3 py-1.5 rounded-lg bg-cyan-600 text-white font-semibold">All Items (<span id="countAll">0</span>)</button>
      <button onclick="setFilter('WEB')" id="btnWEB" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">Web Pentesting (<span id="countWeb">0</span>)</button>
      <button onclick="setFilter('MOBILE')" id="btnMOBILE" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">Mobile Pentesting (<span id="countMobile">0</span>)</button>
      <button onclick="setFilter('OUT_OF_SCOPE')" id="btnOUT_OF_SCOPE" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">Out of Scope (<span id="countOut">0</span>)</button>
      <button onclick="setFilter('DISCREPANCY')" id="btnDISCREPANCY" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">Anomalies Only (<span id="countDisc">0</span>)</button>
    </div>
    <input type="text" id="searchBox" oninput="onSearch(this.value)" placeholder="Search CVE, CWE, title..." class="w-full md:w-64 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
  </section>

  <!-- Main Table View -->
  <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg mb-6">
    <div class="overflow-x-auto">
      <table class="w-full text-left text-xs">
        <thead class="bg-slate-950 text-slate-400 font-mono uppercase border-b border-slate-800">
          <tr>
            <th class="py-3 px-4">Rank</th>
            <th class="py-3 px-4">Scope</th>
            <th class="py-3 px-4">Identifier / Title</th>
            <th class="py-3 px-4 text-center">AI Severity (10)</th>
            <th class="py-3 px-4 text-center">CVSS</th>
            <th class="py-3 px-4 text-center">Score (100)</th>
            <th class="py-3 px-4 text-center">Anomaly Status</th>
            <th class="py-3 px-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody id="tableBody" class="divide-y divide-slate-800/60 font-sans">
          <!-- Rows inserted by JS -->
        </tbody>
      </table>
    </div>
  </div>

  <!-- Detail Modal -->
  <div id="detailModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm hidden z-50 flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col overflow-hidden shadow-2xl">
      <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
        <div>
          <span id="mScopeBadge" class="px-2 py-0.5 rounded text-xs font-bold font-mono">SCOPE</span>
          <h3 id="mTitle" class="text-sm font-bold text-white mt-1"></h3>
          <p id="mCve" class="text-xs text-cyan-400 font-mono mt-0.5"></p>
        </div>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white text-2xl font-bold px-2">&times;</button>
      </div>
      <div class="p-6 overflow-y-auto space-y-4 text-xs">
        
        <!-- Score Breakdown Box -->
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
            <span class="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">100-Point Score Formula Breakdown</span>
            <span id="mTotalScore" class="text-lg font-bold text-emerald-400 font-mono">0.0 / 100</span>
          </div>
          <div class="grid grid-cols-3 gap-3 text-center">
            <div class="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
              <span class="text-slate-400 block text-xs">CISA KEV (40 pts)</span>
              <span id="mKevPts" class="text-sm font-bold text-white font-mono mt-1 block">0.0</span>
            </div>
            <div class="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
              <span class="text-slate-400 block text-xs">AI Severity (40 pts)</span>
              <span id="mAiPts" class="text-sm font-bold text-cyan-400 font-mono mt-1 block">0.0</span>
            </div>
            <div class="bg-slate-900 p-2.5 rounded-lg border border-slate-800">
              <span class="text-slate-400 block text-xs">GitHub PoC (20 pts)</span>
              <span id="mPocPts" class="text-sm font-bold text-amber-400 font-mono mt-1 block">0.0</span>
            </div>
          </div>
        </div>

        <!-- AI Assessment Rationale -->
        <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
          <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono block">AI Practical Severity Assessment</span>
          <div class="flex items-center gap-3">
            <span class="text-xs text-slate-400">Offensive Impact:</span>
            <span id="mImpact" class="text-xs font-semibold text-white"></span>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-xs text-slate-400">Evaluator:</span>
            <span id="mEvaluator" class="text-xs font-mono text-cyan-300"></span>
          </div>
          <p id="mReasoning" class="text-xs text-slate-300 bg-slate-900 p-3 rounded-lg border border-slate-800 leading-relaxed"></p>
        </div>

        <!-- Raw Content / Envelope Snippet -->
        <div>
          <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono block mb-1">Raw Unmodified Content</span>
          <pre id="mRaw" class="bg-slate-950 border border-slate-800 text-slate-300 p-4 rounded-xl font-mono max-h-48 overflow-y-auto whitespace-pre-wrap leading-relaxed select-all"></pre>
        </div>

      </div>
      <div class="px-6 py-3 border-t border-slate-800 flex justify-end bg-slate-950">
        <button onclick="closeModal()" class="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold">Close</button>
      </div>
    </div>
  </div>

  <script>
    const dataset = {json_data_str};
    let currentFilter = 'ALL';
    let query = '';

    function init() {{
      const total = dataset.length;
      const inScope = dataset.filter(x => x.pre_filter && x.pre_filter.is_in_scope).length;
      const outScope = total - inScope;
      const anomalies = dataset.filter(x => x.discrepancy && x.discrepancy.is_discrepancy).length;

      document.getElementById('kpiTotal').innerText = total;
      document.getElementById('kpiInScope').innerText = inScope;
      document.getElementById('kpiOutOfScope').innerText = outScope;
      document.getElementById('kpiAnomalies').innerText = anomalies;

      document.getElementById('countAll').innerText = total;
      document.getElementById('countWeb').innerText = dataset.filter(x => x.pre_filter && x.pre_filter.category === 'WEB').length;
      document.getElementById('countMobile').innerText = dataset.filter(x => x.pre_filter && x.pre_filter.category === 'MOBILE').length;
      document.getElementById('countOut').innerText = outScope;
      document.getElementById('countDisc').innerText = anomalies;

      if (anomalies > 0) {{
        document.getElementById('anomalyBanner').classList.remove('hidden');
        const list = document.getElementById('anomalyList');
        const discItems = dataset.filter(x => x.discrepancy && x.discrepancy.is_discrepancy);
        list.innerHTML = discItems.map(d => `
          <div class="bg-slate-900/80 border border-rose-900/60 rounded-lg p-3 flex flex-col md:flex-row md:items-center justify-between gap-2">
            <div>
              <span class="text-xs font-bold text-white font-mono">${{d.envelope.CVE_ID || d.envelope.Item_ID}}</span>
              <p class="text-xs text-slate-300">${{d.discrepancy.troubleshoot_note}}</p>
            </div>
            <div class="flex items-center gap-3 text-xs font-mono shrink-0">
              <span class="text-slate-400">CVSS: <strong class="text-amber-400">${{d.discrepancy.cvss_score}}</strong></span>
              <span class="text-slate-400">AI: <strong class="text-rose-400">${{d.discrepancy.ai_severity}}/10</strong></span>
              <span class="px-2 py-0.5 rounded bg-rose-900/60 text-rose-300 font-bold">&Delta; ${{d.discrepancy.delta}}</span>
            </div>
          </div>
        `).join('');
      }}

      render();
    }}

    function render() {{
      const tbody = document.getElementById('tableBody');
      const filtered = dataset.filter(item => {{
        const pf = item.pre_filter || {{}};
        let matchF = true;
        if (currentFilter === 'WEB') matchF = pf.category === 'WEB';
        else if (currentFilter === 'MOBILE') matchF = pf.category === 'MOBILE';
        else if (currentFilter === 'OUT_OF_SCOPE') matchF = !pf.is_in_scope;
        else if (currentFilter === 'DISCREPANCY') matchF = item.discrepancy && item.discrepancy.is_discrepancy;

        let matchQ = true;
        if (query) {{
          const str = JSON.stringify(item).toLowerCase();
          matchQ = str.includes(query.toLowerCase());
        }}
        return matchF && matchQ;
      }});

      tbody.innerHTML = filtered.map((c, idx) => {{
        const pf = c.pre_filter || {{}};
        const ai = c.ai_assessment || {{}};
        const disc = c.discrepancy || {{}};
        const env = c.envelope || {{}};

        let scopeBadge = '<span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-slate-800 text-slate-400">OUT OF SCOPE</span>';
        if (pf.category === 'WEB') {{
          scopeBadge = '<span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">WEB</span>';
        }} else if (pf.category === 'MOBILE') {{
          scopeBadge = '<span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">MOBILE</span>';
        }}

        let anomalyBadge = '<span class="text-emerald-400 font-medium font-mono text-xs">ALIGNED</span>';
        if (disc.is_discrepancy) {{
          anomalyBadge = '<span class="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold font-mono text-xs">[!] DISCREPANCY</span>';
        }} else if (!pf.is_in_scope) {{
          anomalyBadge = '<span class="text-slate-500 font-mono text-xs">BYPASS</span>';
        }}

        const aiScoreStr = ai.severity_score !== undefined ? `${{ai.severity_score}}/10` : '-';
        const cvssStr = env.CVSS !== null && env.CVSS !== undefined ? env.CVSS : 'N/A';
        const finalScoreStr = pf.is_in_scope ? Number(c.priority_score || 0).toFixed(1) : '<span class="text-slate-500">0.0</span>';

        return `
          <tr class="hover:bg-slate-800/40 transition">
            <td class="py-3 px-4 font-mono text-slate-400 font-bold">${{idx + 1}}</td>
            <td class="py-3 px-4">${{scopeBadge}}</td>
            <td class="py-3 px-4">
              <div class="font-bold text-white text-xs truncate max-w-xs md:max-w-md" title="${{env.Title}}">${{env.Title}}</div>
              <div class="text-slate-400 text-xs font-mono mt-0.5">${{env.CVE_ID || env.Source_Type}}</div>
            </td>
            <td class="py-3 px-4 text-center font-mono text-cyan-300 font-semibold">${{aiScoreStr}}</td>
            <td class="py-3 px-4 text-center font-mono text-slate-300">${{cvssStr}}</td>
            <td class="py-3 px-4 text-center font-mono font-bold text-emerald-400 text-sm">${{finalScoreStr}}</td>
            <td class="py-3 px-4 text-center">${{anomalyBadge}}</td>
            <td class="py-3 px-4 text-right">
              <button onclick="openDetail('${{env.Item_ID}}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-600 text-cyan-300 hover:text-white transition font-medium border border-slate-700">
                View &rarr;
              </button>
            </td>
          </tr>
        `;
      }}).join('');
    }}

    function setFilter(type) {{
      currentFilter = type;
      document.querySelectorAll('#filterTabs button').forEach(b => {{
        b.className = 'px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700';
      }});
      document.getElementById('btn' + type).className = 'px-3 py-1.5 rounded-lg bg-cyan-600 text-white font-semibold';
      render();
    }}

    function onSearch(val) {{
      query = val;
      render();
    }}

    function openDetail(itemId) {{
      const item = dataset.find(x => x.envelope && x.envelope.Item_ID === itemId);
      if (!item) return;

      const env = item.envelope || {{}};
      const pf = item.pre_filter || {{}};
      const ai = item.ai_assessment || {{}};
      const breakdown = item.score_breakdown || {{}};

      document.getElementById('mTitle').innerText = env.Title;
      document.getElementById('mCve').innerText = (env.CVE_ID ? env.CVE_ID + ' &bull; ' : '') + env.Source_Type;
      document.getElementById('mScopeBadge').innerText = pf.category || 'OUT OF SCOPE';
      document.getElementById('mScopeBadge').className = 'px-2 py-0.5 rounded text-xs font-bold font-mono ' + 
        (pf.category === 'WEB' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 
         pf.category === 'MOBILE' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-800 text-slate-400');

      document.getElementById('mTotalScore').innerText = `${{(item.priority_score || 0).toFixed(1)}} / 100`;
      document.getElementById('mKevPts').innerText = (breakdown.cisa_kev_points || 0).toFixed(1) + ' pts';
      document.getElementById('mAiPts').innerText = (breakdown.ai_severity_points || 0).toFixed(1) + ' pts';
      document.getElementById('mPocPts').innerText = (breakdown.poc_points || 0).toFixed(1) + ' pts';

      document.getElementById('mImpact').innerText = ai.offensive_impact || 'Standard Disclosure';
      document.getElementById('mEvaluator').innerText = ai.evaluated_by || 'Heuristic Rules';
      document.getElementById('mReasoning').innerText = ai.reasoning || pf.reason || 'Evaluated against pentesting scope criteria.';
      document.getElementById('mRaw').innerText = env.Raw_Content || 'No raw content recorded.';

      document.getElementById('detailModal').classList.remove('hidden');
    }}

    function closeModal() {{
      document.getElementById('detailModal').classList.add('hidden');
    }}

    window.onload = init;
  </script>
</body>
</html>
"""

ARTIFACT_PATH.write_text(html_content, encoding="utf-8")
print(f"[+] GroundedCVE Triage Dashboard Artifact exported successfully to:\n    {ARTIFACT_PATH}")
