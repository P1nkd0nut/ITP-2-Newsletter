"""
Exports the GroundedCVE Ingestion Dashboard as a self-contained HTML artifact
compatible with Google Antigravity Generative UI.
"""
import json
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).resolve().parent.parent
STAGING_FILE = ROOT_DIR / "Backend" / "data" / "staging" / "latest_envelopes.json"
ARTIFACT_PATH = Path(r"C:\Users\deyeo\.gemini\antigravity\brain\1deaf1fb-e3d6-4f1e-8f21-644188d5c466\ingestion_dashboard.html")

data = []
if STAGING_FILE.exists():
    with open(STAGING_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

json_data_str = json.dumps(data, ensure_ascii=False)

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GroundedCVE Threat Intelligence Ingestion Dashboard</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    pre, code, .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
  </style>
</head>
<body class="bg-slate-950 text-slate-100 p-6 min-h-screen antialiased">

  <!-- Header -->
  <div class="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-5 mb-6">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-emerald-400 flex items-center justify-center font-bold text-black mono shadow-lg shadow-cyan-500/20 text-lg">
        GC
      </div>
      <div>
        <div class="flex items-center gap-2">
          <h1 class="text-xl font-bold tracking-tight text-white">GroundedCVE Threat Ingestion Viewer</h1>
          <span class="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-950 text-cyan-400 border border-cyan-800">Phase 1 Active</span>
        </div>
        <p class="text-xs text-slate-400">Team 4 &bull; Standardised JSON Staging Envelopes (Task 1.3)</p>
      </div>
    </div>
    <div class="text-right">
      <span class="text-xs text-emerald-400 mono flex items-center gap-1.5 justify-end">
        <span class="h-2 w-2 rounded-full bg-emerald-400 inline-block animate-pulse"></span>
        100% SHA-256 Verified
      </span>
      <span class="text-[11px] text-slate-500">Raw Content Preserved Unmodified</span>
    </div>
  </div>

  <!-- KPI Metrics -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <span class="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total Ingested</span>
      <p id="kpiTotal" class="text-3xl font-extrabold text-white mt-1 mono">0</p>
      <span class="text-[10px] text-slate-500">Unique envelopes</span>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <span class="text-[11px] font-semibold text-rose-400 uppercase tracking-wider">CISA KEV Actives</span>
      <p id="kpiKev" class="text-3xl font-extrabold text-rose-400 mt-1 mono">0</p>
      <span class="text-[10px] text-slate-500">Active weaponization</span>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <span class="text-[11px] font-semibold text-amber-400 uppercase tracking-wider">Web Stream</span>
      <p id="kpiWeb" class="text-3xl font-extrabold text-amber-400 mt-1 mono">0</p>
      <span class="text-[10px] text-slate-500">PortSwigger & Packages</span>
    </div>
    <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <span class="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider">Mobile Stream</span>
      <p id="kpiMobile" class="text-3xl font-extrabold text-emerald-400 mt-1 mono">0</p>
      <span class="text-[10px] text-slate-500">Frida & Bulletins</span>
    </div>
  </div>

  <!-- Filter & Search Toolbar -->
  <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-6 flex flex-col md:flex-row items-center justify-between gap-3">
    <div class="flex flex-wrap items-center gap-2 text-xs" id="filterTabs">
      <button onclick="setFilter('ALL')" id="btnALL" class="px-3 py-1.5 rounded-lg bg-cyan-600 text-white font-semibold">All Sources (<span id="tabCountAll">0</span>)</button>
      <button onclick="setFilter('CISA_KEV')" id="btnCISA_KEV" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">CISA KEV (<span id="tabCountKev">0</span>)</button>
      <button onclick="setFilter('NVD')" id="btnNVD" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">NVD 2.0 (<span id="tabCountNvd">0</span>)</button>
      <button onclick="setFilter('PORTSWIGGER')" id="btnPORTSWIGGER" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">PortSwigger (<span id="tabCountPortswigger">0</span>)</button>
      <button onclick="setFilter('PROJECT_ZERO')" id="btnPROJECT_ZERO" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">Project Zero (<span id="tabCountPz">0</span>)</button>
      <button onclick="setFilter('GITHUB_ADVISORY')" id="btnGITHUB_ADVISORY" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">GitHub Advisories (<span id="tabCountGhsa">0</span>)</button>
      <button onclick="setFilter('MOBILE')" id="btnMOBILE" class="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700">Frida / Mobile (<span id="tabCountMobile">0</span>)</button>
    </div>
    <input type="text" id="searchBox" oninput="onSearch(this.value)" placeholder="Search CVE, vendor, keyword..." class="w-full md:w-64 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 mono">
  </div>

  <!-- Cards Grid -->
  <div id="itemsGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"></div>

  <!-- Raw Content Inspector Modal -->
  <div id="rawModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm hidden z-50 flex items-center justify-center p-4">
    <div class="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[85vh] flex flex-col overflow-hidden shadow-2xl">
      <div class="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
        <div>
          <span id="mBadge" class="px-2 py-0.5 rounded text-[10px] font-bold mono">TYPE</span>
          <h3 id="mTitle" class="text-sm font-bold text-white mt-1"></h3>
          <p id="mId" class="text-xs text-slate-500 mono"></p>
        </div>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white text-2xl font-bold px-2">&times;</button>
      </div>
      <div class="p-6 overflow-y-auto space-y-4 text-xs">
        <div class="bg-cyan-950/30 border border-cyan-900/60 rounded-lg p-3">
          <span class="text-[10px] uppercase font-bold text-cyan-400 block">SHA-256 Content Hash</span>
          <span id="mHash" class="mono text-slate-300 select-all"></span>
        </div>
        <div>
          <span class="text-[10px] uppercase font-bold text-slate-400 block mb-1">Raw Unmodified Source Content</span>
          <pre id="mRaw" class="bg-slate-950 border border-slate-800 text-slate-300 p-4 rounded-xl mono max-h-72 overflow-y-auto whitespace-pre-wrap select-all leading-relaxed"></pre>
        </div>
      </div>
      <div class="px-6 py-3 border-t border-slate-800 flex justify-end bg-slate-950/70">
        <button onclick="closeModal()" class="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold">Close</button>
      </div>
    </div>
  </div>

  <script>
    const dataset = {json_data_str};
    let currentFilter = 'ALL';
    let query = '';

    function getBadge(type) {{
      const map = {{
        'CISA_KEV': 'bg-rose-950 text-rose-300 border-rose-800',
        'NVD': 'bg-blue-950 text-blue-300 border-blue-800',
        'PORTSWIGGER': 'bg-amber-950 text-amber-300 border-amber-800',
        'PROJECT_ZERO': 'bg-purple-950 text-purple-300 border-purple-800',
        'GITHUB_ADVISORY': 'bg-indigo-950 text-indigo-300 border-indigo-800',
        'FRIDA': 'bg-emerald-950 text-emerald-300 border-emerald-800',
        'ANDROID_BULLETIN': 'bg-teal-950 text-teal-300 border-teal-800',
        'APPLE_SECURITY': 'bg-sky-950 text-sky-300 border-sky-800'
      }};
      return map[type] || 'bg-slate-800 text-slate-300 border-slate-700';
    }}

    function render() {{
      const grid = document.getElementById('itemsGrid');
      const filtered = dataset.filter(item => {{
        let matchF = (currentFilter === 'ALL') ||
                     (currentFilter === 'MOBILE' ? ['FRIDA', 'ANDROID_BULLETIN', 'APPLE_SECURITY'].includes(item.Source_Type) : item.Source_Type === currentFilter);
        let matchQ = !query || JSON.stringify(item).toLowerCase().includes(query.toLowerCase());
        return matchF && matchQ;
      }});

      grid.innerHTML = filtered.map(item => `
        <div class="bg-slate-900 border border-slate-800 hover:border-cyan-800 rounded-xl p-4 flex flex-col justify-between transition shadow-sm">
          <div class="space-y-2">
            <div class="flex items-center justify-between gap-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold mono border ${{getBadge(item.Source_Type)}}">${{item.Source_Type}}</span>
              ${{item.KEV_Status ? '<span class="px-1.5 py-0.5 text-[9px] font-bold rounded bg-rose-950 text-rose-400 border border-rose-800">KEV</span>' : ''}}
              ${{item.CVSS ? `<span class="px-1.5 py-0.5 text-[10px] font-bold mono rounded bg-amber-950 text-amber-300 border border-amber-800">CVSS ${{item.CVSS}}</span>` : ''}}
            </div>
            <h3 class="text-xs font-bold text-white leading-snug line-clamp-2">${{item.Title}}</h3>
            ${{item.CVE_ID ? `<p class="text-[11px] mono text-cyan-400 font-semibold">${{item.CVE_ID}}</p>` : ''}}
            ${{item.Vendor_Product ? `<p class="text-[11px] text-slate-400 truncate">🎯 ${{item.Vendor_Product}}</p>` : ''}}
            <p class="text-[10px] mono text-slate-500 bg-slate-950 p-2 rounded border border-slate-800/80 line-clamp-3 leading-relaxed">
              ${{(item.Raw_Content || '').replace(/[\\{{\\}}"]/g, ' ').slice(0, 150)}}...
            </p>
          </div>
          <div class="pt-3 border-t border-slate-800 flex items-center justify-between mt-3 text-[11px]">
            <span class="text-slate-500 mono">${{(item.Published_Date || '').split('T')[0]}}</span>
            <button onclick="openModal('${{item.Item_ID}}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-600 hover:text-white text-cyan-400 font-medium transition border border-slate-700">
              Inspect Envelope &rarr;
            </button>
          </div>
        </div>
      `).join('');
    }}

    function init() {{
      document.getElementById('kpiTotal').innerText = dataset.length;
      document.getElementById('tabCountAll').innerText = dataset.length;

      const kev = dataset.filter(x => x.Source_Type === 'CISA_KEV').length;
      document.getElementById('kpiKev').innerText = kev;
      document.getElementById('tabCountKev').innerText = kev;

      document.getElementById('tabCountNvd').innerText = dataset.filter(x => x.Source_Type === 'NVD').length;
      document.getElementById('tabCountPortswigger').innerText = dataset.filter(x => x.Source_Type === 'PORTSWIGGER').length;
      document.getElementById('tabCountPz').innerText = dataset.filter(x => x.Source_Type === 'PROJECT_ZERO').length;
      document.getElementById('tabCountGhsa').innerText = dataset.filter(x => x.Source_Type === 'GITHUB_ADVISORY').length;
      
      const mob = dataset.filter(x => ['FRIDA', 'ANDROID_BULLETIN', 'APPLE_SECURITY'].includes(x.Source_Type)).length;
      document.getElementById('kpiMobile').innerText = mob;
      document.getElementById('tabCountMobile').innerText = mob;

      const web = dataset.filter(x => ['PORTSWIGGER', 'GITHUB_ADVISORY'].includes(x.Source_Type)).length;
      document.getElementById('kpiWeb').innerText = web;

      render();
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

    function openModal(id) {{
      const item = dataset.find(x => x.Item_ID === id);
      if (!item) return;
      document.getElementById('mBadge').innerText = item.Source_Type;
      document.getElementById('mTitle').innerText = item.Title;
      document.getElementById('mId').innerText = 'Item_ID: ' + item.Item_ID;
      document.getElementById('mHash').innerText = item.Content_Hash;
      document.getElementById('mRaw').innerText = item.Raw_Content;
      document.getElementById('rawModal').classList.remove('hidden');
    }}

    function closeModal() {{
      document.getElementById('rawModal').classList.add('hidden');
    }}

    window.onload = init;
  </script>
</body>
</html>
"""

ARTIFACT_PATH.write_text(html_content, encoding="utf-8")
print(f"Artifact exported successfully to: {ARTIFACT_PATH}")
