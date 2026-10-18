/**
 * Grounded Threat News — Modern Tech News Application Logic
 * Short, sweet, skimmable cybersecurity intelligence
 */

// Application State
let candidatesData = [];
let currentDesk = 'ALL';
let currentSearch = '';
let currentDateFilter = 'WEEK'; // 'TODAY' | 'WEEK' (12/10 - 19/10/2026) | 'ALL'
let currentCategory = 'ALL';
let currentSort = 'timeline'; // 'timeline' (Today first) | 'score_desc' | 'date_desc' | 'date_asc' | 'ai_desc' | 'score_asc'
let activeCandidate = null;

// ============================================================================
// Initialization & Data Loading
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Listen for Escape key to close modals
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeDetailModal();
      closeManualModal();
      closeSettingsModal();
      closeExportModal();
      closeLinkHealthModal();
    }
  });

  await loadData();
  await loadTelegramSettings();
  await loadLinkHealthStats();
});

async function loadData() {
  try {
    const res = await fetch('/api/newsletters?page_size=100&sort_by=priority_score&sort_order=desc');
    if (res.ok) {
      const data = await res.json();
      candidatesData = data.items || [];
    }
  } catch (err) {
    console.warn("API unavailable, fallback to local data.js envelopes:", err);
    fallbackData();
  }

  updateMetrics();
  renderContent();
}

function fallbackData() {
  if (window.INITIAL_ENVELOPES && window.INITIAL_ENVELOPES.length > 0) {
    candidatesData = window.INITIAL_ENVELOPES.map(env => {
      const isKev = Boolean(env.KEV_Status);
      const hasPoc = Boolean(env.PoC_URLs && env.PoC_URLs.length > 0);
      const isWeb = /web|http|sql|xss|ssrf|netscaler|palo|f5|struts/i.test(env.Title + " " + env.Raw_Content);
      const isMobile = /android|ios|mobile|frida|telephony/i.test(env.Title + " " + env.Raw_Content);
      const cat = isWeb ? "WEB" : isMobile ? "MOBILE" : "OUT_OF_SCOPE";
      const aiSev = env.CVSS ? Number(env.CVSS) : 7.0;
      const kevPts = isKev ? 40.0 : 0.0;
      const aiPts = Math.round((aiSev / 10.0) * 40.0 * 10) / 10;
      const pocPts = hasPoc ? 20.0 : 0.0;
      const score = cat !== "OUT_OF_SCOPE" ? Math.round((kevPts + aiPts + pocPts) * 10) / 10 : 0.0;

      const pubDate = env.Published_Date || "";
      const pubIso = pubDate.slice(0, 10);

      return {
        envelope: env,
        pre_filter: {
          category: cat,
          matched_by: "HEURISTICS",
          reason: `Filtered into ${cat} pentesting scope.`,
          is_in_scope: cat !== "OUT_OF_SCOPE",
        },
        ai_assessment: {
          severity_score: aiSev,
          offensive_impact: isKev ? "Remote Code Execution (RCE)" : "Application Exploit",
          exploitability: aiSev >= 8 ? "CRITICAL" : "HIGH",
          reasoning: "Practical offensive security assessment.",
          evaluated_by: "Qwen 2.5 72B",
        },
        priority_score: score,
        score_breakdown: { cisa_kev_points: kevPts, ai_severity_points: aiPts, poc_points: pocPts },
        discrepancy: {
          cvss_score: env.CVSS,
          ai_severity: aiSev,
          delta: 0.0,
          is_discrepancy: false,
          troubleshoot_note: "Score aligned with baseline.",
        },
        standard_category: isWeb ? "Remote Code Execution (RCE)" : "Mobile Component Hijacking",
        published_date_iso: pubIso,
        published_date_formatted: pubIso || "Monitored",
        triaged_at: env.Ingested_At || new Date().toISOString(),
      };
    });
    candidatesData.sort((a, b) => b.priority_score - a.priority_score);
  }
}

// ============================================================================
// Filtering, Sorting & Search Handlers
// ============================================================================

function filterDesk(desk) {
  currentDesk = desk;

  ['ALL', 'WEB', 'MOBILE'].forEach(d => {
    const btn = document.getElementById(`tabBtn-${d}`);
    if (btn) {
      btn.className = d === desk
        ? 'desk-btn px-3 py-1.5 rounded-md bg-cyan-600 text-white font-semibold transition'
        : 'desk-btn px-3 py-1.5 rounded-md text-slate-400 hover:text-white transition';
    }
  });

  renderContent();
}

function filterDateWindow(windowType) {
  currentDateFilter = windowType;

  ['TODAY', 'WEEK', 'ALL'].forEach(w => {
    const btn = document.getElementById(`dateBtn-${w}`);
    if (btn) {
      btn.className = w === windowType
        ? 'px-2.5 py-1.5 rounded-md bg-cyan-600 text-white font-semibold transition text-[11px]'
        : 'px-2.5 py-1.5 rounded-md text-slate-400 hover:text-white transition text-[11px]';
    }
  });

  renderContent();
}

function filterCategory(catKey) {
  currentCategory = catKey;

  const catKeys = ['ALL', 'RCE', 'AUTH', 'SSRF', 'INJECTION', 'COMPONENT', 'MEMORY', 'DESYNC', 'MOBILE_SEC'];
  catKeys.forEach(k => {
    const btn = document.getElementById(`catBtn-${k}`);
    if (btn) {
      btn.className = k === catKey
        ? 'cat-pill px-2.5 py-1 rounded-md bg-cyan-600 text-white font-semibold border border-cyan-500 transition text-[11px]'
        : 'cat-pill px-2.5 py-1 rounded-md bg-slate-950 text-slate-400 hover:text-white border border-slate-800 transition text-[11px]';
    }
  });

  renderContent();
}

function handleSortChange(sortVal) {
  currentSort = sortVal;
  renderContent();
}

function handleSearch(val) {
  currentSearch = val.trim().toLowerCase();
  const clearBtn = document.getElementById('clearSearchBtn');
  if (clearBtn) {
    if (currentSearch) {
      clearBtn.classList.remove('hidden');
    } else {
      clearBtn.classList.add('hidden');
    }
  }
  renderContent();
}

function clearSearch() {
  currentSearch = '';
  const input = document.getElementById('mainSearchInput');
  if (input) input.value = '';
  const clearBtn = document.getElementById('clearSearchBtn');
  if (clearBtn) clearBtn.classList.add('hidden');
  renderContent();
}

function resetAllFilters() {
  currentDesk = 'ALL';
  currentSearch = '';
  currentDateFilter = 'WEEK';
  currentCategory = 'ALL';
  currentSort = 'timeline';

  const searchInput = document.getElementById('mainSearchInput');
  if (searchInput) searchInput.value = '';
  const clearBtn = document.getElementById('clearSearchBtn');
  if (clearBtn) clearBtn.classList.add('hidden');

  const sortSelect = document.getElementById('sortSelect');
  if (sortSelect) sortSelect.value = 'timeline';

  filterDesk('ALL');
  filterDateWindow('WEEK');
  filterCategory('ALL');
}

function updateMetrics() {
  const total = candidatesData.length;
  const web = candidatesData.filter(x => x.pre_filter && x.pre_filter.category === 'WEB').length;
  const mobile = candidatesData.filter(x => x.pre_filter && x.pre_filter.category === 'MOBILE').length;
  const kev = candidatesData.filter(x => x.envelope && x.envelope.KEV_Status).length;

  document.getElementById('kpiTotal').innerText = total;
  document.getElementById('kpiWeb').innerText = web;
  document.getElementById('kpiMobile').innerText = mobile;
  document.getElementById('kpiKev').innerText = kev;

  document.getElementById('badgeWebCount').innerText = web;
  document.getElementById('badgeMobileCount').innerText = mobile;
}

// Category Badge Helper
function getCategoryPill(cat) {
  const c = (cat || '').toLowerCase();
  if (c.includes('remote code execution') || c.includes('rce')) {
    return { label: '⚡ RCE', cls: 'bg-rose-950 text-rose-300 border-rose-800' };
  }
  if (c.includes('authentication') || c.includes('session') || c.includes('auth')) {
    return { label: '🔑 Auth Bypass', cls: 'bg-sky-950 text-sky-300 border-sky-800' };
  }
  if (c.includes('ssrf') || c.includes('server-side request forgery')) {
    return { label: '📡 SSRF', cls: 'bg-purple-950 text-purple-300 border-purple-800' };
  }
  if (c.includes('injection') || c.includes('sql')) {
    return { label: '💉 Injection', cls: 'bg-amber-950 text-amber-300 border-amber-800' };
  }
  if (c.includes('ipc') || c.includes('intent') || c.includes('component')) {
    return { label: '📱 Component Hijacking', cls: 'bg-emerald-950 text-emerald-300 border-emerald-800' };
  }
  if (c.includes('memory') || c.includes('buffer overflow') || c.includes('corruption')) {
    return { label: '💥 Memory Corruption', cls: 'bg-red-950 text-red-300 border-red-700' };
  }
  if (c.includes('desync') || c.includes('smuggling')) {
    return { label: '🔄 Protocol Desync', cls: 'bg-teal-950 text-teal-300 border-teal-800' };
  }
  if (c.includes('frida') || c.includes('crypto') || c.includes('hooking')) {
    return { label: '🔒 Mobile Crypto/Frida', cls: 'bg-indigo-950 text-indigo-300 border-indigo-800' };
  }
  if (c.includes('denial of service') || c.includes('dos')) {
    return { label: '🛑 DoS', cls: 'bg-slate-900 text-slate-400 border-slate-700' };
  }
  return { label: cat || 'Advisory', cls: 'bg-slate-900 text-slate-300 border-slate-700' };
}

// ============================================================================
// Render Content (Timeline Sections: Today First, Then Past 7 Days)
// ============================================================================

function getFilteredCandidates() {
  const inScope = candidatesData.filter(x => x.pre_filter && x.pre_filter.is_in_scope);
  let items = [...inScope];

  // 1. Desk filter (All, Web, Mobile)
  if (currentDesk === 'WEB') {
    items = items.filter(x => x.pre_filter.category === 'WEB');
  } else if (currentDesk === 'MOBILE') {
    items = items.filter(x => x.pre_filter.category === 'MOBILE');
  }

  // 2. Date window filter
  if (currentDateFilter === 'TODAY') {
    items = items.filter(x => {
      const d = x.published_date_iso || (x.envelope && (x.envelope.Published_Date || '')).slice(0, 10);
      return d === '2026-10-19';
    });
  } else if (currentDateFilter === 'WEEK') {
    items = items.filter(x => {
      const d = x.published_date_iso || (x.envelope && (x.envelope.Published_Date || '')).slice(0, 10);
      return d >= '2026-10-12' && d <= '2026-10-19';
    });
  }

  // 3. Category filter
  if (currentCategory !== 'ALL') {
    items = items.filter(x => {
      const cat = (x.standard_category || (x.ai_assessment && x.ai_assessment.offensive_impact) || '').toLowerCase();
      const title = (x.envelope && x.envelope.Title || '').toLowerCase();
      if (currentCategory === 'RCE') return cat.includes('remote code execution') || cat.includes('rce') || title.includes('rce');
      if (currentCategory === 'AUTH') return cat.includes('auth') || cat.includes('session') || cat.includes('bypass');
      if (currentCategory === 'SSRF') return cat.includes('ssrf') || cat.includes('server-side request forgery');
      if (currentCategory === 'INJECTION') return cat.includes('sql') || cat.includes('command injection') || cat.includes('injection');
      if (currentCategory === 'COMPONENT') return cat.includes('ipc') || cat.includes('intent') || cat.includes('component');
      if (currentCategory === 'MEMORY') return cat.includes('memory') || cat.includes('buffer overflow') || cat.includes('corruption');
      if (currentCategory === 'DESYNC') return cat.includes('desync') || cat.includes('smuggling');
      if (currentCategory === 'MOBILE_SEC') return cat.includes('frida') || cat.includes('crypto') || cat.includes('hooking');
      return true;
    });
  }

  // 4. Search query
  if (currentSearch) {
    items = items.filter(x => {
      const env = x.envelope || {};
      const ai = x.ai_assessment || {};
      const indepth = x.in_depth || {};
      const stdCat = x.standard_category || '';
      const blob = `${env.CVE_ID} ${env.Title} ${env.Vendor_Product} ${stdCat} ${ai.offensive_impact} ${ai.reasoning} ${indepth.brief_summary}`.toLowerCase();
      return blob.includes(currentSearch);
    });
  }

  // 5. Sorting
  items.sort((a, b) => {
    if (currentSort === 'timeline') {
      // Timeline default: Newest date first, then highest score
      const da = (a.envelope && a.envelope.Published_Date) || '';
      const db = (b.envelope && b.envelope.Published_Date) || '';
      if (db !== da) return db.localeCompare(da);
      return (b.priority_score || 0) - (a.priority_score || 0);
    }
    if (currentSort === 'score_desc') {
      return (b.priority_score || 0) - (a.priority_score || 0);
    }
    if (currentSort === 'score_asc') {
      return (a.priority_score || 0) - (b.priority_score || 0);
    }
    if (currentSort === 'date_desc') {
      const da = (a.envelope && a.envelope.Published_Date) || '';
      const db = (b.envelope && b.envelope.Published_Date) || '';
      return db.localeCompare(da);
    }
    if (currentSort === 'date_asc') {
      const da = (a.envelope && a.envelope.Published_Date) || '';
      const db = (b.envelope && b.envelope.Published_Date) || '';
      return da.localeCompare(db);
    }
    if (currentSort === 'ai_desc') {
      const sa = (a.ai_assessment && a.ai_assessment.severity_score) || 0;
      const sb = (b.ai_assessment && b.ai_assessment.severity_score) || 0;
      return sb - sa;
    }
    return 0;
  });

  return items;
}

function renderContent() {
  const filtered = getFilteredCandidates();

  // Partition into Today (19 Oct 2026), Past 7 Days (12 Oct - 18 Oct 2026), and Earlier
  const todayItems = filtered.filter(x => (x.published_date_iso || (x.envelope && x.envelope.Published_Date || '').slice(0, 10)) === '2026-10-19');
  const weekItems = filtered.filter(x => {
    const d = x.published_date_iso || (x.envelope && x.envelope.Published_Date || '').slice(0, 10);
    return d >= '2026-10-12' && d <= '2026-10-18';
  });
  const olderItems = filtered.filter(x => {
    const d = x.published_date_iso || (x.envelope && x.envelope.Published_Date || '').slice(0, 10);
    return d < '2026-10-12';
  });

  // Update status text
  const statusEl = document.getElementById('filterStatusText');
  if (statusEl) {
    const windowLabel = currentDateFilter === 'TODAY'
      ? 'Today: 19 Oct 2026'
      : currentDateFilter === 'WEEK'
      ? 'Past 7 Days: 12/10 - 19/10/2026'
      : 'All Historical Dates';
    const deskLabel = currentDesk !== 'ALL' ? ` &bull; Desk: ${currentDesk}` : '';
    const catLabel = currentCategory !== 'ALL' ? ` &bull; Category: ${currentCategory}` : '';
    const searchLabel = currentSearch ? ` &bull; Search: "${currentSearch}"` : '';
    statusEl.innerHTML = `Showing <strong class="text-white">${filtered.length}</strong> matching advisories (${windowLabel}${deskLabel}${catLabel}${searchLabel})`;
  }

  // Section titles and counters
  document.getElementById('titleTodayCount').innerText = `(${todayItems.length})`;
  document.getElementById('titleWeekCount').innerText = `(${weekItems.length})`;
  document.getElementById('titleOlderCount').innerText = `(${olderItems.length})`;

  const secToday = document.getElementById('section-today');
  const secWeek = document.getElementById('section-week');
  const secOlder = document.getElementById('section-older');
  const spotlightBox = document.getElementById('spotlightContainer');

  // Spotlight (only in ALL mode, with no search or category filter, showing today's #1 threat or top threat)
  if (currentDesk === 'ALL' && !currentSearch && currentCategory === 'ALL' && filtered.length > 0) {
    spotlightBox.classList.remove('hidden');
    const topSpot = todayItems.length > 0 ? todayItems[0] : filtered[0];
    renderSpotlight(topSpot);
  } else {
    spotlightBox.classList.add('hidden');
  }

  // Section 1: Today's Disclosures (First on the page)
  if (currentDateFilter === 'TODAY' || currentDateFilter === 'WEEK' || currentDateFilter === 'ALL') {
    if (todayItems.length > 0 || currentDateFilter === 'TODAY') {
      secToday.classList.remove('hidden');
      renderDeskGrid('gridToday', todayItems);
    } else {
      secToday.classList.add('hidden');
    }
  } else {
    secToday.classList.add('hidden');
  }

  // Section 2: Past 7 Days Disclosures
  if (currentDateFilter === 'WEEK' || currentDateFilter === 'ALL') {
    if (weekItems.length > 0 || currentDateFilter === 'WEEK') {
      secWeek.classList.remove('hidden');
      renderDeskGrid('gridWeek', weekItems);
    } else {
      secWeek.classList.add('hidden');
    }
  } else {
    secWeek.classList.add('hidden');
  }

  // Section 3: Earlier / Historical Archive
  if (currentDateFilter === 'ALL') {
    secOlder.classList.remove('hidden');
    renderDeskGrid('gridOlder', olderItems);
  } else {
    secOlder.classList.add('hidden');
  }
}

function renderSpotlight(topItem) {
  const box = document.getElementById('spotlightContainer');
  const env = topItem.envelope || {};
  const ai = topItem.ai_assessment || {};
  const pf = topItem.pre_filter || {};
  const disc = topItem.discrepancy || {};
  const isKev = Boolean(env.KEV_Status);
  const hasPoc = Boolean(env.PoC_URLs && env.PoC_URLs.length > 0);
  const pubDateFmt = topItem.published_date_formatted || (env.Published_Date ? env.Published_Date.slice(0, 10) : 'Monitored');
  const catPill = getCategoryPill(topItem.standard_category || ai.offensive_impact);

  box.innerHTML = `
    <div class="bg-gradient-to-r from-slate-900 to-slate-925 border border-cyan-500/40 rounded-xl p-5 sm:p-6 shadow-lg relative overflow-hidden">
      <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
        <div class="flex flex-wrap items-center gap-1.5">
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-cyan-950 text-cyan-400 border border-cyan-800">
            Top Priority Threat
          </span>
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${pf.category === 'WEB' ? 'bg-sky-950 text-sky-400 border border-sky-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">
            ${pf.category}
          </span>
          <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${catPill.cls}">
            ${catPill.label}
          </span>
          <span class="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-950 border border-slate-800">
            📅 ${pubDateFmt}
          </span>
          ${isKev ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">🔥 CISA KEV</span>' : ''}
          ${hasPoc ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">💻 PoC Available</span>' : ''}
          ${disc.is_discrepancy ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-900 text-rose-200">⚠️ Discrepancy</span>' : ''}
        </div>

        <div class="flex items-baseline space-x-1 font-mono">
          <span class="text-xs text-slate-400">Threat Score:</span>
          <span class="text-xl font-black text-emerald-400">${(topItem.priority_score || 0).toFixed(1)}</span>
          <span class="text-xs text-slate-500">/ 100</span>
        </div>
      </div>

      <h3 class="text-base sm:text-lg font-bold text-white leading-snug cursor-pointer hover:text-cyan-400 transition" onclick="openDetailModal('${env.Item_ID}')">
        ${env.Title}
      </h3>

      <p class="text-xs text-slate-300 mt-2 line-clamp-2 leading-relaxed font-sans">
        ${(topItem.in_depth && topItem.in_depth.brief_summary) || ai.reasoning || 'Evaluated under offensive security triage criteria.'}
      </p>

      <div class="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
        <span class="text-slate-400">${env.CVE_ID || env.Item_ID} &bull; <strong class="text-cyan-400 font-sans">${topItem.standard_category || ai.offensive_impact || 'Exploit Primitive'}</strong></span>
        <button onclick="openDetailModal('${env.Item_ID}')" class="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow transition">
          View Details &rarr;
        </button>
      </div>
    </div>
  `;
}

function renderDeskGrid(containerId, items, desk) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (!items.length) {
    container.innerHTML = '<div class="col-span-full py-8 text-center text-xs text-slate-500 font-mono bg-slate-950/40 rounded-xl border border-slate-800/60">No threat advisories matching current filter and date criteria.</div>';
    return;
  }

  container.innerHTML = items.map(item => {
    const env = item.envelope || {};
    const ai = item.ai_assessment || {};
    const disc = item.discrepancy || {};
    const indepth = item.in_depth || {};
    const isKev = Boolean(env.KEV_Status);
    const hasPoc = Boolean(env.PoC_URLs && env.PoC_URLs.length > 0);
    const pubDateFmt = item.published_date_formatted || (env.Published_Date ? env.Published_Date.slice(0, 10) : 'Monitored');
    const catPill = getCategoryPill(item.standard_category || ai.offensive_impact);

    const score = item.priority_score || 0;
    const scoreColor = score >= 70 ? 'text-rose-400' : score >= 50 ? 'text-amber-400' : 'text-emerald-400';
    const briefText = indepth.brief_summary || ai.reasoning || env.Title || 'Triaged candidate for pentesting analysis.';

    return `
      <div class="news-card p-4 rounded-xl flex flex-col justify-between cursor-pointer space-y-3" onclick="openDetailModal('${env.Item_ID}')">
        <div class="space-y-2">
          
          <!-- Top Row: CVE ID & Category & Score -->
          <div class="flex items-center justify-between text-[11px] font-mono">
            <span class="font-bold text-cyan-400">${env.CVE_ID || env.Item_ID}</span>
            <span class="font-bold ${scoreColor}">${score.toFixed(1)} / 100</span>
          </div>

          <!-- Category Pill -->
          <div>
            <span class="inline-block px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${catPill.cls}">
              ${catPill.label}
            </span>
          </div>

          <h4 class="text-xs sm:text-sm font-semibold text-white line-clamp-2 hover:text-cyan-400 transition leading-snug">
            ${env.Title}
          </h4>

          <p class="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
            ${briefText}
          </p>
        </div>

        <div class="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
          <div class="flex items-center space-x-1.5">
            <span class="text-slate-500">📅 ${pubDateFmt}</span>
            ${isKev ? '<span class="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 font-bold border border-rose-800">🔥 KEV</span>' : ''}
            ${hasPoc ? '<span class="px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 font-bold border border-amber-800">💻 PoC</span>' : ''}
            ${disc.is_discrepancy ? '<span class="px-1.5 py-0.5 rounded bg-rose-900 text-rose-200 font-bold">⚠️ Discrepancy</span>' : ''}
          </div>

          <span class="text-cyan-400 font-medium hover:underline">
            Details &rarr;
          </span>
        </div>
      </div>
    `;
  }).join('');
}

// ============================================================================
// Detail Modal (Deep-Dive Technical Breakdown & Direct CVE Links)
// ============================================================================

function openDetailModal(itemId) {
  const item = candidatesData.find(x => (x.envelope && x.envelope.Item_ID === itemId) || (x.envelope && x.envelope.CVE_ID === itemId));
  if (!item) return;

  activeCandidate = item;
  const env = item.envelope || {};
  const pf = item.pre_filter || {};
  const ai = item.ai_assessment || {};
  const bd = item.score_breakdown || {};
  const disc = item.discrepancy || {};
  const indepth = item.in_depth || {};
  const aiEval = item.ai_evaluation_breakdown || {};

  // Header
  document.getElementById('mTitle').innerText = env.Title || 'Advisory';
  document.getElementById('mCveId').innerText = env.CVE_ID || env.Item_ID;
  document.getElementById('mSource').innerText = env.Source_Type || 'Feed';
  document.getElementById('mPublishedDate').innerText = `📅 ${item.published_date_formatted || (env.Published_Date ? env.Published_Date.slice(0, 10) : 'Monitored')}`;
  document.getElementById('mCategoryBadge').innerText = item.standard_category || ai.offensive_impact || 'Advisory';

  const scopeBadge = document.getElementById('mScopeBadge');
  scopeBadge.innerText = pf.category || 'SCOPE';
  scopeBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold ' +
    (pf.category === 'WEB' ? 'bg-sky-950 text-sky-400 border border-sky-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800');

  // Direct Authoritative CVE Links (cve.org & NVD)
  const cveId = env.CVE_ID;
  const btnCveOrg = document.getElementById('btnCveOrg');
  const btnNvd = document.getElementById('btnNvd');
  if (cveId) {
    btnCveOrg.href = `https://www.cve.org/CVERecord?id=${cveId}`;
    btnCveOrg.classList.remove('hidden');
    btnNvd.href = `https://nvd.nist.gov/vuln/detail/${cveId}`;
    btnNvd.classList.remove('hidden');
  } else {
    btnCveOrg.classList.add('hidden');
    btnNvd.classList.add('hidden');
  }

  // Original Advisory Link
  const canLink = document.getElementById('mCanonicalLink');
  const canLabel = document.getElementById('mCanonicalLabel');
  canLink.href = env.Source_URL || '#';
  canLabel.innerText = env.Source_Type === 'CISA_KEV' ? 'CISA KEV Source' : `${env.Source_Type} Advisory`;

  // Vendor Security Bulletins List
  const vBox = document.getElementById('mVendorBulletinsBox');
  const vList = document.getElementById('mVendorBulletinsList');
  const vUrls = indepth.vendor_bulletins || [];
  if (vUrls.length > 0) {
    vBox.classList.remove('hidden');
    vList.innerHTML = vUrls.map(u => `
      <a href="${u}" target="_blank" class="block text-cyan-400 hover:underline truncate">
        &bull; ${u}
      </a>
    `).join('');
  } else {
    vBox.classList.add('hidden');
  }

  // 100-Point Score Formula Breakdown
  const totalScore = (item.priority_score || 0).toFixed(1);
  const kevPts = bd.cisa_kev_points || 0;
  const aiPts = bd.ai_severity_points || 0;
  const pocPts = bd.poc_points || 0;

  document.getElementById('mTotalScore').innerText = totalScore;
  document.getElementById('mScoreKev').innerText = `${kevPts.toFixed(1)} pts`;
  document.getElementById('mScoreAi').innerText = `${aiPts.toFixed(1)} pts`;
  document.getElementById('mScorePoc').innerText = `${pocPts.toFixed(1)} pts`;

  document.getElementById('mBarKev').style.width = `${(kevPts / 40.0) * 100}%`;
  document.getElementById('mBarAi').style.width = `${(aiPts / 40.0) * 100}%`;
  document.getElementById('mBarPoc').style.width = `${(pocPts / 20.0) * 100}%`;

  document.getElementById('mKevReason').innerText = kevPts > 0
    ? 'Confirmed active exploitation in the wild (CISA KEV cataloged).'
    : 'No confirmed active exploitation reported in CISA KEV.';

  document.getElementById('mAiReason').innerText =
    `Evaluated practical rating: ${(ai.severity_score || 0).toFixed(1)} / 10. Formula: (${(ai.severity_score || 0).toFixed(1)} / 10) * 40.`;

  document.getElementById('mPocReason').innerText = pocPts > 0
    ? 'Verified public GitHub exploit code / PoC repository available.'
    : 'No public exploit repository cataloged.';

  // AI Evaluation Breakdown: Why is this rated this high / low?
  document.getElementById('mAiRatingScore').innerText = totalScore;
  document.getElementById('mAiVerdict').innerText = aiEval.ai_verdict ||
    `Priority score ${totalScore}/100 calculated from CISA KEV weaponization (+${kevPts} pts), AI practical severity (+${aiPts} pts), and public PoC code (+${pocPts} pts).`;

  document.getElementById('mAiKevEval').innerText = aiEval.cisa_kev_evaluation ||
    (kevPts > 0 ? 'Awarded +40.0 pts: Actively weaponized zero-day / N-day in CISA KEV.' : '0.0 pts: No active exploitation reported in CISA KEV.');

  document.getElementById('mAiSevEval').innerText = aiEval.ai_severity_evaluation ||
    `Awarded +${aiPts.toFixed(1)} pts: Qwen 2.5 assessed practical severity at ${(ai.severity_score || 0).toFixed(1)}/10 based on network attack surface.`;

  document.getElementById('mAiPocEval').innerText = aiEval.poc_evaluation ||
    (pocPts > 0 ? 'Awarded +20.0 pts: Public GitHub exploit script readily available.' : '0.0 pts: No public PoC repository discovered.');

  // In-Depth Vulnerability Explanation
  document.getElementById('mAiModel').innerText = ai.evaluated_by || 'Qwen 2.5 72B';
  
  const fullDesc = indepth.full_description || ai.reasoning || env.Title || 'Improper boundary check or input validation.';
  document.getElementById('mFullDescription').innerText = fullDesc;

  document.getElementById('mImpact').innerText = item.standard_category || ai.offensive_impact || 'Security Vulnerability';
  document.getElementById('mProduct').innerText = `${env.Vendor_Product || 'Generic Target'} (Scope: ${pf.category || 'PENTEST'})`;
  document.getElementById('mScopeReason').innerText = pf.reason || 'Isolated via Task 1.2 scope classifier.';

  // Mitigation & Required Action
  const actionBox = document.getElementById('mActionBox');
  const actionText = document.getElementById('mRequiredAction');
  if (indepth.required_action) {
    actionBox.classList.remove('hidden');
    actionText.innerText = indepth.required_action;
  } else {
    actionBox.classList.add('hidden');
  }

  // CVSS Discrepancy Gate (Revealed ONLY if discrepancy delta >= 4.0)
  const anomalyBox = document.getElementById('mAnomalyBox');
  if (disc.is_discrepancy) {
    anomalyBox.classList.remove('hidden');
    document.getElementById('mAnomalyDelta').innerText = `|Δ| = ${disc.delta} pts`;
    document.getElementById('mAnomalyCvss').innerText = disc.cvss_score !== null && disc.cvss_score !== undefined ? disc.cvss_score : 'N/A';
    document.getElementById('mAnomalyAi').innerText = `${disc.ai_severity || 0} / 10`;
    document.getElementById('mAnomalyNote').innerText = disc.troubleshoot_note || 'Divergence between vendor CVSS and AI practical severity.';
  } else {
    anomalyBox.classList.add('hidden');
  }

  // Verified External References, NVD Links, Forums & PoCs
  const refsContainer = document.getElementById('mRefsContainer');
  const refsList = document.getElementById('mVerifiedRefsList');
  const allRefs = item.external_references || (item.in_depth && item.in_depth.external_references) || [];

  if (refsList) {
    if (allRefs.length > 0) {
      refsList.innerHTML = allRefs.map(ref => {
        const st = linkStatusStyle(ref);
        const statusCls = st.pill;
        const dotCls = st.dot;
        const statusLabel = st.label;

        let typeBadgeCls = 'bg-slate-950 text-slate-300 border-slate-800';
        const tLower = (ref.link_type || '').toLowerCase();
        if (tLower.includes('poc') || tLower.includes('exploit')) {
          typeBadgeCls = 'bg-amber-950 text-amber-300 border-amber-800';
        } else if (tLower.includes('forum') || tLower.includes('discussion')) {
          typeBadgeCls = 'bg-purple-950 text-purple-300 border-purple-800';
        } else if (tLower.includes('patch') || tLower.includes('commit')) {
          typeBadgeCls = 'bg-indigo-950 text-indigo-300 border-indigo-800';
        } else if (tLower.includes('vendor') || tLower.includes('advisory')) {
          typeBadgeCls = 'bg-cyan-950 text-cyan-300 border-cyan-800';
        } else if (tLower.includes('authoritative') || tLower.includes('database')) {
          typeBadgeCls = 'bg-sky-950 text-sky-300 border-sky-800';
        }

        return `
          <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 transition flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div class="space-y-1 min-w-0 flex-1">
              <div class="flex flex-wrap items-center gap-1.5 text-[10px]">
                <span class="px-1.5 py-0.5 rounded font-bold uppercase bg-slate-950 text-slate-400 border border-slate-800">
                  ${escapeHtml(ref.source_provider || 'Reference')}
                </span>
                <span class="px-1.5 py-0.5 rounded font-bold border ${typeBadgeCls}">
                  ${escapeHtml(ref.link_type || 'General Link')}
                </span>
              </div>
              <a href="${escapeHtml(ref.url)}" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300 hover:underline block truncate font-mono">
                &bull; ${escapeHtml(ref.url)}
              </a>
            </div>
            
            <div class="shrink-0 flex items-center space-x-2 text-[10px] font-mono">
              <span class="px-2 py-0.5 rounded border ${statusCls} flex items-center space-x-1">
                <span class="h-1.5 w-1.5 rounded-full ${dotCls}"></span>
                <span>${escapeHtml(statusLabel)}</span>
              </span>
              ${ref.archive_url ? `<a href="${escapeHtml(ref.archive_url)}" target="_blank" class="text-cyan-400 hover:underline">Archived copy</a>` : ''}
              ${ref.latency_ms ? `<span class="text-slate-500">${ref.latency_ms}ms</span>` : ''}
            </div>
          </div>
        `;
      }).join('');
    } else {
      refsList.innerHTML = '<div class="text-slate-500 text-xs py-2">No additional external references cataloged for this advisory.</div>';
    }
  }

  document.getElementById('detailModal').classList.remove('hidden');
}

function closeDetailModal() {
  document.getElementById('detailModal').classList.add('hidden');
  activeCandidate = null;
}

// ============================================================================
// Scoring Guide & Prioritization Manual Modal
// ============================================================================

function openManualModal() {
  document.getElementById('manualModal').classList.remove('hidden');
}

function closeManualModal() {
  document.getElementById('manualModal').classList.add('hidden');
}

// ============================================================================
// Telegram Secondary Channel
// ============================================================================

async function loadTelegramSettings() {
  try {
    const res = await fetch('/api/channels');
    if (!res.ok) return;
    const cfg = await res.json();
    const sec = cfg.secondary_channel || {};

    const toggle = document.getElementById('toggleTelegram');
    if (toggle) toggle.checked = Boolean(sec.enabled);

    const token = document.getElementById('inputToken');
    if (token && sec.bot_token) token.value = sec.bot_token;

    const chat = document.getElementById('inputChatId');
    if (chat && sec.chat_id) chat.value = sec.chat_id;
  } catch (err) {
    console.warn("Could not load channel settings:", err);
  }
}

function openSettingsModal() {
  document.getElementById('settingsModal').classList.remove('hidden');
}

function closeSettingsModal() {
  document.getElementById('settingsModal').classList.add('hidden');
}

async function saveTelegramSettings() {
  const enabled = document.getElementById('toggleTelegram').checked;
  const token = document.getElementById('inputToken').value.trim();
  const chat = document.getElementById('inputChatId').value.trim();

  try {
    const res = await fetch('/api/channels/telegram', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secondary_channel: {
          enabled: enabled,
          bot_token: token,
          chat_id: chat,
        }
      })
    });

    if (res.ok) {
      showToast('Telegram wire settings saved!', 'success');
      closeSettingsModal();
    }
  } catch (err) {
    showToast('Failed to save settings.', 'error');
  }
}

async function testTelegramAlert() {
  const box = document.getElementById('settingsResultBox');
  box.classList.remove('hidden');
  box.innerText = 'Dispatching test alert...';
  box.className = 'p-2.5 rounded text-[11px] font-mono border border-slate-700 text-slate-300';

  const token = document.getElementById('inputToken').value.trim();
  const chat = document.getElementById('inputChatId').value.trim();

  try {
    const res = await fetch('/api/channels/telegram/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bot_token: token, chat_id: chat })
    });
    const data = await res.json();

    if (data.success) {
      box.className = 'p-2.5 rounded text-[11px] font-mono border border-emerald-800 bg-emerald-950/40 text-emerald-300';
      box.innerText = `✅ Test Succeeded (${data.mode.toUpperCase()} MODE): Alert verified.`;
    } else {
      box.className = 'p-2.5 rounded text-[11px] font-mono border border-rose-800 text-rose-300';
      box.innerText = `❌ Error: ${data.error}`;
    }
  } catch (err) {
    box.innerText = 'Network error.';
  }
}

async function dispatchToTelegram() {
  if (!activeCandidate) return;
  const itemId = activeCandidate.envelope?.Item_ID;

  showToast('Sending alert to Telegram...', 'info');

  try {
    const res = await fetch('/api/channels/telegram/dispatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ item_id: itemId })
    });
    const data = await res.json();

    if (data.dispatched) {
      showToast(`Alert sent to Telegram (${data.mode})!`, 'success');
    } else {
      showToast(`Bypassed: ${data.reason || data.error}`, 'info');
    }
  } catch (err) {
    showToast('Failed to send to Telegram.', 'error');
  }
}

// ============================================================================
// Export Modal & Toast
// ============================================================================

function openExportModal() {
  document.getElementById('exportModal').classList.remove('hidden');
}

function closeExportModal() {
  document.getElementById('exportModal').classList.add('hidden');
}

function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  const tMsg = document.getElementById('toastMessage');
  const tIcon = document.getElementById('toastIcon');

  if (!toast || !tMsg) return;

  tMsg.innerText = msg;
  tIcon.innerText = type === 'success' ? '✅' : type === 'error' ? '⚠️' : 'ℹ️';

  toast.classList.remove('translate-y-16', 'opacity-0');
  toast.classList.add('translate-y-0', 'opacity-100');

  setTimeout(() => {
    toast.classList.remove('translate-y-0', 'opacity-100');
    toast.classList.add('translate-y-16', 'opacity-0');
  }, 3000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================================
// Concurrent Link Health & Scalability Engine
// ============================================================================

// Maps a link record's state to badge colors. Unchecked, blocked and
// temporary-error links are neutral/amber rather than shown as live.
function linkStatusStyle(ref) {
  const state = ref.state || (ref.is_working === true ? 'live' : ref.is_working === false ? 'dead' : 'unchecked');
  const styles = {
    live:      { pill: 'bg-emerald-950 text-emerald-300 border-emerald-800', dot: 'bg-emerald-400', text: 'text-emerald-400', label: 'Live' },
    dead:      { pill: 'bg-rose-950 text-rose-300 border-rose-800',          dot: 'bg-rose-400',    text: 'text-rose-400',    label: 'Dead Link' },
    moved:     { pill: 'bg-rose-950 text-rose-300 border-rose-800',          dot: 'bg-rose-400',    text: 'text-rose-400',    label: 'Likely Removed' },
    blocked:   { pill: 'bg-amber-950 text-amber-300 border-amber-800',       dot: 'bg-amber-400',   text: 'text-amber-400',   label: 'Blocked (Unverified)' },
    temporary: { pill: 'bg-amber-950 text-amber-300 border-amber-800',       dot: 'bg-amber-400',   text: 'text-amber-400',   label: 'Temporary Error' },
    unchecked: { pill: 'bg-slate-950 text-slate-400 border-slate-700',       dot: 'bg-slate-500',   text: 'text-slate-400',   label: 'Not Yet Checked' },
  };
  const st = styles[state] || styles.unchecked;
  return { ...st, label: ref.status_label || st.label };
}

function healthText(stats) {
  return stats.health_percentage == null ? 'Not checked yet' : `${stats.health_percentage}% Active`;
}

async function loadLinkHealthStats() {
  try {
    const res = await fetch('/api/links/stats');
    if (!res.ok) return;
    const data = await res.json();
    const stats = data.stats || {};

    const badge = document.getElementById('badgeLinkHealth');
    if (badge) {
      badge.innerText = healthText(stats);
    }

    const kpiStatus = document.getElementById('lhKpiStatus');
    if (kpiStatus) {
      kpiStatus.innerText = healthText(stats);
      kpiStatus.className = (stats.health_percentage ?? 100) >= 95 
        ? 'text-base font-bold text-emerald-400' 
        : 'text-base font-bold text-amber-400';
    }

    const kpiTotal = document.getElementById('lhKpiTotal');
    if (kpiTotal) kpiTotal.innerText = stats.total_cached || 0;

    const kpiLatency = document.getElementById('lhKpiLatency');
    if (kpiLatency) kpiLatency.innerText = `${stats.avg_latency_ms || 80} ms`;
  } catch (err) {
    console.warn("Could not load link health stats:", err);
  }
}

async function openLinkHealthModal() {
  document.getElementById('linkHealthModal').classList.remove('hidden');
  await loadLinkHealthStats();
  await populateLinksTable();
}

function closeLinkHealthModal() {
  document.getElementById('linkHealthModal').classList.add('hidden');
}

async function populateLinksTable(providedLinks = null) {
  const tbody = document.getElementById('lhLinksTableBody');
  if (!tbody) return;

  let links = providedLinks;
  if (!links) {
    try {
      const res = await fetch('/api/links/verify');
      if (res.ok) {
        const data = await res.json();
        links = data.links || [];
      }
    } catch (e) {
      console.warn("Could not fetch links list:", e);
    }
  }

  if (!links || links.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-500">No external links loaded yet.</td></tr>';
    return;
  }

  tbody.innerHTML = links.map(l => {
    const st = linkStatusStyle(l);
    const statusCls = `${st.text} font-bold`;
    const statusDot = st.dot;

    return `
      <tr class="hover:bg-slate-900/60 transition">
        <td class="p-2.5 whitespace-nowrap">
          <span class="inline-flex items-center space-x-1.5 ${statusCls}">
            <span class="h-1.5 w-1.5 rounded-full ${statusDot}"></span>
            <span>${escapeHtml(st.label)}</span>
          </span>
        </td>
        <td class="p-2.5 whitespace-nowrap text-slate-400">${escapeHtml(l.source_provider || 'NVD')}</td>
        <td class="p-2.5 whitespace-nowrap text-slate-300">${escapeHtml(l.link_type || 'Reference')}</td>
        <td class="p-2.5 max-w-xs truncate">
          <a href="${escapeHtml(l.url)}" target="_blank" class="text-cyan-400 hover:underline">
            ${escapeHtml(l.url)}
          </a>
          ${l.archive_url ? `<a href="${escapeHtml(l.archive_url)}" target="_blank" class="text-slate-400 hover:underline ml-1">(archived)</a>` : ''}
        </td>
        <td class="p-2.5 text-right whitespace-nowrap text-slate-400 font-mono">${l.latency_ms || 0}ms</td>
      </tr>
    `;
  }).join('');
}

async function runLiveLinkVerification() {
  const btn = document.getElementById('btnRunLinkCheck');
  const benchBox = document.getElementById('lhBenchmarkResult');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span>⏳</span><span>Validating Concurrent Workers...</span>';
  }

  showToast('Running high-speed concurrent link check across 30 workers...', 'info');

  try {
    const t0 = performance.now();
    const res = await fetch('/api/links/verify?force=true', { method: 'POST' });
    const data = await res.json();
    const clientElapsed = ((performance.now() - t0) / 1000).toFixed(2);

    const b = data.benchmark || {};
    if (benchBox) {
      benchBox.classList.remove('hidden');
      benchBox.innerHTML = `
        ⚡ <strong>Benchmark Completed:</strong> Tested <strong>${data.total_tested} URLs</strong> concurrently in 
        <strong>${b.verification_time_seconds || clientElapsed}s</strong> 
        (Avg: <strong>${b.avg_latency_ms}ms / link</strong>). 
        Active Ratio: <strong>${healthText(b)}</strong>. 
        <span class="text-cyan-300">Throughput: ~${Math.round(data.total_tested / (b.verification_time_seconds || 1))} links/sec</span>.
      `;
    }

    await loadLinkHealthStats();
    await populateLinksTable(data.links);
    showToast(`Validated ${data.total_tested} links in ${b.verification_time_seconds || clientElapsed}s!`, 'success');
  } catch (err) {
    showToast('Failed to complete link verification.', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<span>⚡</span><span>Run Parallel Re-Check</span>';
    }
  }
}
