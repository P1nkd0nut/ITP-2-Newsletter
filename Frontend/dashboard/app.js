/**
 * GroundedCVE dashboard application logic
 * Short, sweet, skimmable cybersecurity intelligence
 */

// Application State
let candidatesData = [];
let currentDesk = 'ALL';
let currentSearch = '';
let searchRanks = null; // Item_ID -> rank from /api/search (hybrid search); null = use the plain text filter
let searchTimer = null;
let currentDateFilter = 'RECENT'; // 'RECENT' (past week) | 'MONTH' (past month) | 'ALL'
let currentCategory = 'ALL';
// Default: highest priority first, since ranking is the point of the dashboard
const DEFAULT_SORT = 'score_desc';
let currentSort = DEFAULT_SORT; // 'score_desc' | 'timeline' (newest first, then score) | 'date_desc' | 'date_asc' | 'ai_desc' | 'score_asc'
let activeCandidate = null;

// Users see how recent an item is, never its date. Buckets match recencyLabel().
const RECENT_DAYS = 7;
const MONTH_DAYS = 30;

function recencyBucket(x) {
  const age = ageInDays(x.envelope && x.envelope.Published_Date);
  if (age === null || age <= RECENT_DAYS) return 'RECENT';
  return age <= MONTH_DAYS ? 'MONTH' : 'OLDER';
}

// Exact dates are not shown to users; items show how recent they are instead
const FREEZE_AFTER_DAYS = 365;
const FREEZE_NOTICE = 'Published over a year ago. PoCs and details for older CVEs are no longer updated, so check the source for newer information.';

function ageInDays(published) {
  const t = Date.parse(published || '');
  return Number.isNaN(t) ? null : Math.max(0, Math.floor((Date.now() - t) / 86400000));
}

function recencyLabel(published) {
  const age = ageInDays(published);
  if (age === null) return 'Monitored';
  if (age <= 7) return 'Recent';
  if (age <= 30) return 'Past month';
  if (age <= 90) return 'Past 3 months';
  if (age <= 180) return 'Past 6 months';
  if (age <= 365) return 'Past year';
  return 'Over a year ago';
}

function isFrozen(item) {
  if (typeof item.updates_frozen === 'boolean') return item.updates_frozen;
  const age = ageInDays(item.envelope && item.envelope.Published_Date);
  return age !== null && age > FREEZE_AFTER_DAYS;
}

function frozenBadge(item) {
  return isFrozen(item)
    ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-600" title="${escapeAttr(FREEZE_NOTICE)}">🔒 Not updated</span>`
    : '';
}

function verifiedBadge(item) {
  const card = item.grounded_card;
  return card
    ? `<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 font-bold border border-emerald-800" title="Summary written from the source and passed ${card.checks_run} verification checks">✓ Verified</span>`
    : '';
}

// ============================================================================
// Initialization & Data Loading
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // The dashboard is the home page; /#reader opens reader mode directly
  setReaderMode(location.hash === '#reader', false);
  window.addEventListener('hashchange', () => setReaderMode(location.hash === '#reader'));

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

  // Pick up new results from the scheduler without a page refresh
  setInterval(loadData, 5 * 60 * 1000);
});

async function loadData() {
  try {
    // The API returns at most 100 items per page, so read every page
    const items = [];
    let ok = false;
    for (let page = 1, pages = 1; page <= pages && page <= 50; page++) {
      const res = await fetch(`/api/newsletters?page_size=100&page=${page}&sort_by=priority_score&sort_order=desc`);
      if (!res.ok) break;
      const data = await res.json();
      items.push(...(data.items || []));
      pages = data.total_pages || 1;
      ok = true;
    }
    if (ok) candidatesData = items;
  } catch (err) {
    console.warn("API unavailable, fallback to local data.js envelopes:", err);
    fallbackData();
  }

  updateMetrics();
  updateCategoryPills();
  // A fresh install starts with older seed data until the scheduler's first run
  // finishes; show All Dates rather than an empty week.
  if (!fallbackApplied && currentDateFilter === 'RECENT' && candidatesData.length > 0 &&
      !candidatesData.some(x => recencyBucket(x) === 'RECENT')) {
    fallbackApplied = true;
    filterDateWindow(candidatesData.some(x => recencyBucket(x) === 'MONTH') ? 'MONTH' : 'ALL');
    return;
  }
  renderContent();
}

let fallbackApplied = false;

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
        published_date_formatted: recencyLabel(pubDate),
        updates_frozen: (ageInDays(pubDate) || 0) > FREEZE_AFTER_DAYS,
        freeze_notice: (ageInDays(pubDate) || 0) > FREEZE_AFTER_DAYS ? FREEZE_NOTICE : null,
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

  ['RECENT', 'MONTH', 'ALL'].forEach(w => {
    const btn = document.getElementById(`dateBtn-${w}`);
    if (btn) {
      btn.className = w === windowType
        ? 'px-2.5 py-1.5 rounded-md bg-cyan-600 text-white font-semibold transition text-[11px]'
        : 'px-2.5 py-1.5 rounded-md text-slate-400 hover:text-white transition text-[11px]';
    }
  });

  renderContent();
}

const CATEGORY_KEYS = ['ALL', 'RCE', 'AUTH', 'SSRF', 'INJECTION', 'COMPONENT', 'MEMORY', 'DESYNC', 'MOBILE_SEC'];

// Category pill predicate, shared by the filter and the pill counts
function matchesCategory(x, key) {
  const cat = (x.standard_category || (x.ai_assessment && x.ai_assessment.offensive_impact) || '').toLowerCase();
  const title = (x.envelope && x.envelope.Title || '').toLowerCase();
  if (key === 'RCE') return cat.includes('remote code execution') || cat.includes('rce') || title.includes('rce');
  if (key === 'AUTH') return cat.includes('auth') || cat.includes('session') || cat.includes('bypass');
  if (key === 'SSRF') return cat.includes('ssrf') || cat.includes('server-side request forgery');
  if (key === 'INJECTION') return cat.includes('sql') || cat.includes('command injection') || cat.includes('injection');
  if (key === 'COMPONENT') return cat.includes('ipc') || cat.includes('intent') || cat.includes('component');
  if (key === 'MEMORY') return cat.includes('memory') || cat.includes('buffer overflow') || cat.includes('corruption');
  if (key === 'DESYNC') return cat.includes('desync') || cat.includes('smuggling');
  if (key === 'MOBILE_SEC') return cat.includes('frida') || cat.includes('crypto') || cat.includes('hooking');
  return true;
}

// Dims category pills that match no in-scope item, so a click never lands on an empty list
function updateCategoryPills() {
  const inScope = candidatesData.filter(x => x.pre_filter && x.pre_filter.is_in_scope);
  CATEGORY_KEYS.forEach(k => {
    if (k === 'ALL') return;
    const btn = document.getElementById(`catBtn-${k}`);
    if (!btn) return;
    const count = inScope.filter(x => matchesCategory(x, k)).length;
    btn.disabled = count === 0;
    btn.classList.toggle('opacity-40', count === 0);
    btn.classList.toggle('cursor-not-allowed', count === 0);
    btn.title = count === 0 ? 'No items in this category right now' : `${count} item${count === 1 ? '' : 's'}`;
  });
  if (currentCategory !== 'ALL') {
    const active = document.getElementById(`catBtn-${currentCategory}`);
    if (active && active.disabled) filterCategory('ALL');
  }
}

function filterCategory(catKey) {
  currentCategory = catKey;

  CATEGORY_KEYS.forEach(k => {
    const btn = document.getElementById(`catBtn-${k}`);
    if (btn) {
      const dim = btn.disabled ? ' opacity-40 cursor-not-allowed' : '';
      btn.className = (k === catKey
        ? 'cat-pill px-2.5 py-1 rounded-md bg-cyan-600 text-white font-semibold border border-cyan-500 transition text-[11px]'
        : 'cat-pill px-2.5 py-1 rounded-md bg-slate-950 text-slate-400 hover:text-white border border-slate-800 transition text-[11px]') + dim;
    }
  });

  renderContent();
}

function handleSortChange(sortVal) {
  currentSort = sortVal;
  renderContent();
}

function handleSearch(val) {
  const startingSearch = !currentSearch;
  currentSearch = val.trim().toLowerCase();
  // A new search looks through every date; Recent / Past month can still narrow it afterwards
  if (startingSearch && currentSearch && currentDateFilter !== 'ALL') {
    currentDateFilter = 'ALL';
    filterDateWindow('ALL');
  }
  const clearBtn = document.getElementById('clearSearchBtn');
  if (clearBtn) {
    if (currentSearch) {
      clearBtn.classList.remove('hidden');
    } else {
      clearBtn.classList.add('hidden');
    }
  }
  searchRanks = null;
  renderContent();
  if (currentSearch) {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => runHybridSearch(currentSearch), 250);
  }
}

// Ask the hybrid search engine (keyword + meaning) for the best matches across
// all collected items. If it can't be reached, the plain text filter stays in use.
async function runHybridSearch(query) {
  try {
    const res = await fetch(`/api/search?q=${encodeURIComponent(query)}&limit=50`);
    if (!res.ok) return;
    const data = await res.json();
    if (query !== currentSearch) return; // the user kept typing
    searchRanks = new Map((data.results || []).map(r => [r.item_id, r.rank]));
    renderContent();
  } catch (err) {
    console.warn('Hybrid search unavailable, using the text filter:', err);
  }
}

function clearSearch() {
  currentSearch = '';
  searchRanks = null;
  const input = document.getElementById('mainSearchInput');
  if (input) input.value = '';
  const clearBtn = document.getElementById('clearSearchBtn');
  if (clearBtn) clearBtn.classList.add('hidden');
  renderContent();
}

function resetAllFilters() {
  currentDesk = 'ALL';
  currentSearch = '';
  searchRanks = null;
  currentDateFilter = 'RECENT';
  currentCategory = 'ALL';
  currentSort = DEFAULT_SORT;

  const searchInput = document.getElementById('mainSearchInput');
  if (searchInput) searchInput.value = '';
  const clearBtn = document.getElementById('clearSearchBtn');
  if (clearBtn) clearBtn.classList.add('hidden');

  const sortSelect = document.getElementById('sortSelect');
  if (sortSelect) sortSelect.value = DEFAULT_SORT;

  filterDesk('ALL');
  filterDateWindow('RECENT');
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
// NEW / UPDATED badge from the ingestion change tracker (nothing for UNCHANGED)
function changeBadge(env) {
  if (env.Change_Status === 'NEW') {
    return '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-violet-950 text-violet-300 border border-violet-800" title="First seen in the latest ingestion run">🆕 NEW</span>';
  }
  if (env.Change_Status === 'UPDATED') {
    const tip = escapeAttr((env.Change_Summary || []).join(' | ') || 'Changed since the previous ingestion run');
    return `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800" title="${tip}">🔄 UPDATED</span>`;
  }
  return '';
}

function escapeAttr(text) {
  return String(text).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

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
// Render Content (Sections: Recent, Past month, Older)
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

  // 2. Recency window filter
  if (currentDateFilter === 'RECENT') {
    items = items.filter(x => recencyBucket(x) === 'RECENT');
  } else if (currentDateFilter === 'MONTH') {
    items = items.filter(x => recencyBucket(x) !== 'OLDER');
  }

  // 3. Category filter
  if (currentCategory !== 'ALL') {
    items = items.filter(x => matchesCategory(x, currentCategory));
  }

  // 4. Search query: hybrid search results when available, otherwise plain text match
  const rankOf = x => searchRanks.get(x.envelope && x.envelope.Item_ID);
  if (currentSearch && searchRanks) {
    items = items.filter(x => rankOf(x) !== undefined);
  } else if (currentSearch) {
    items = items.filter(x => {
      const env = x.envelope || {};
      const ai = x.ai_assessment || {};
      const indepth = x.in_depth || {};
      const stdCat = x.standard_category || '';
      const blob = `${env.CVE_ID} ${env.Title} ${env.Vendor_Product} ${stdCat} ${ai.offensive_impact} ${ai.reasoning} ${indepth.brief_summary}`.toLowerCase();
      return blob.includes(currentSearch);
    });
  }

  // 5. Sorting (while searching, the default order is best match first)
  items.sort((a, b) => {
    if (currentSearch && searchRanks && currentSort === DEFAULT_SORT) {
      return rankOf(a) - rankOf(b);
    }
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
  if (readerMode) renderReader(filtered);

  // Partition into Recent, Past month and Older
  const todayItems = filtered.filter(x => recencyBucket(x) === 'RECENT');
  const weekItems = filtered.filter(x => recencyBucket(x) === 'MONTH');
  const olderItems = filtered.filter(x => recencyBucket(x) === 'OLDER');

  // Update status text
  const statusEl = document.getElementById('filterStatusText');
  if (statusEl) {
    const windowLabel = currentDateFilter === 'RECENT'
      ? 'Recent'
      : currentDateFilter === 'MONTH'
      ? 'Past month'
      : 'All';
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

  // While hybrid search results are shown, list them in one section, best match first,
  // instead of splitting them by recency (a strong older match would otherwise sit last)
  const todayHeading = secToday.querySelector('h2 span');
  const todaySubtitle = secToday.querySelector('.sm\\:inline');
  if (currentSearch && searchRanks) {
    if (todayHeading) todayHeading.innerText = 'Search results · best match first';
    if (todaySubtitle) todaySubtitle.innerText = 'Keyword + meaning search';
    document.getElementById('titleTodayCount').innerText = `(${filtered.length})`;
    spotlightBox.classList.add('hidden');
    secWeek.classList.add('hidden');
    secOlder.classList.add('hidden');
    secToday.classList.remove('hidden');
    renderDeskGrid('gridToday', filtered);
    return;
  }
  if (todayHeading) todayHeading.innerText = 'Recent';
  if (todaySubtitle) todaySubtitle.innerText = 'Priority Zero-Days & Fresh Disclosures';

  // Spotlight (only in ALL mode, with no search or category filter, showing today's #1 threat or top threat)
  if (currentDesk === 'ALL' && !currentSearch && currentCategory === 'ALL' && filtered.length > 0) {
    spotlightBox.classList.remove('hidden');
    // Highest priority score in the current view; the list itself may be sorted newest first
    const topSpot = filtered.reduce((best, x) => ((x.priority_score || 0) > (best.priority_score || 0) ? x : best), filtered[0]);
    renderSpotlight(topSpot);
  } else {
    spotlightBox.classList.add('hidden');
  }

  // Section 1: Recent (first on the page)
  if (currentDateFilter === 'RECENT' || currentDateFilter === 'MONTH' || currentDateFilter === 'ALL') {
    if (todayItems.length > 0 || currentDateFilter === 'RECENT') {
      secToday.classList.remove('hidden');
      renderDeskGrid('gridToday', todayItems);
    } else {
      secToday.classList.add('hidden');
    }
  } else {
    secToday.classList.add('hidden');
  }

  // Section 2: Past month
  if (currentDateFilter === 'MONTH' || currentDateFilter === 'ALL') {
    if (weekItems.length > 0 || currentDateFilter === 'MONTH') {
      secWeek.classList.remove('hidden');
      renderDeskGrid('gridWeek', weekItems);
    } else {
      secWeek.classList.add('hidden');
    }
  } else {
    secWeek.classList.add('hidden');
  }

  // Section 3: Older
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
  const isKev = Boolean(env.KEV_Status) || ((topItem.score_breakdown || {}).cisa_kev_points || 0) > 0;
  const hasPoc = Boolean(env.PoC_URLs && env.PoC_URLs.length > 0) || ((topItem.score_breakdown || {}).poc_points || 0) > 0;
  const pubDateFmt = topItem.published_date_formatted || recencyLabel(env.Published_Date);
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
            ${pubDateFmt}
          </span>
          ${changeBadge(env)}
          ${frozenBadge(topItem)}
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
    const isKev = Boolean(env.KEV_Status) || ((item.score_breakdown || {}).cisa_kev_points || 0) > 0;
    const hasPoc = Boolean(env.PoC_URLs && env.PoC_URLs.length > 0) || ((item.score_breakdown || {}).poc_points || 0) > 0;
    const pubDateFmt = item.published_date_formatted || recencyLabel(env.Published_Date);
    const catPill = getCategoryPill(item.standard_category || ai.offensive_impact);

    const score = item.priority_score || 0;
    const scoreColor = score >= 70 ? 'text-rose-400' : score >= 50 ? 'text-amber-400' : 'text-emerald-400';
    const briefText = indepth.brief_summary || ai.reasoning || env.Title || 'Triaged candidate for pentesting analysis.';

    return `
      <div class="news-card p-4 rounded-xl flex flex-col justify-between cursor-pointer space-y-3 ${(ai.severity_score || 0) === 0 ? 'opacity-60' : ''}" title="${(ai.severity_score || 0) === 0 ? 'Research or release note, not a specific vulnerability' : ''}" onclick="openDetailModal('${env.Item_ID}')">
        <div class="space-y-2">
          
          <!-- Top Row: CVE ID & Category & Score -->
          <div class="flex items-center justify-between text-[11px] font-mono">
            <span class="flex items-center gap-1.5"><span class="font-bold text-cyan-400">${env.CVE_ID || env.Item_ID}</span>${changeBadge(env)}</span>
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
            ${item.grounded_card ? escapeHtml(briefText) : briefText}
          </p>
        </div>

        <div class="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
          <div class="flex items-center space-x-1.5">
            <span class="text-slate-500">${pubDateFmt}</span>
            ${frozenBadge(item)}
            ${verifiedBadge(item)}
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
  // Open on the summary and sources; scoring and checks stay folded under More details
  const more = document.getElementById('mMoreDetails');
  if (more) more.open = false;
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
  document.getElementById('btnReaderPage').href = `/incident/${encodeURIComponent(env.Item_ID || '')}`;
  document.getElementById('mSource').innerText = env.Source_Type || 'Feed';
  document.getElementById('mPublishedDate').innerText = item.published_date_formatted || recencyLabel(env.Published_Date);
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

  // Older than a year: no longer updated
  const freezeBox = document.getElementById('mFreezeBox');
  if (freezeBox) {
    freezeBox.classList.toggle('hidden', !isFrozen(item));
    document.getElementById('mFreezeText').innerText = item.freeze_notice || FREEZE_NOTICE;
  }
  const checkedEl = document.getElementById('mCheckedLabel');
  if (checkedEl) {
    checkedEl.innerText = item.checked_label ? `• ${item.checked_label}` : '';
  }

  // What changed since the previous ingestion run
  const changeBox = document.getElementById('mChangeBox');
  if (changeBox) {
    const changes = env.Change_Summary || [];
    if (env.Change_Status === 'NEW' || (env.Change_Status === 'UPDATED' && changes.length)) {
      changeBox.classList.remove('hidden');
      document.getElementById('mChangeTitle').innerText = env.Change_Status === 'NEW'
        ? 'New in the latest ingestion run'
        : 'Updated since the previous run:';
      const list = document.getElementById('mChangeList');
      list.innerHTML = '';
      changes.forEach(c => {
        const li = document.createElement('li');
        li.textContent = `• ${c}`;
        list.appendChild(li);
      });
    } else {
      changeBox.classList.add('hidden');
    }
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
    ? 'Public GitHub PoC repository found for this CVE (not run or verified).'
    : 'No public exploit repository cataloged.';

  // AI Evaluation Breakdown: Why is this rated this high / low?
  document.getElementById('mAiRatingScore').innerText = totalScore;
  document.getElementById('mAiVerdict').innerText = aiEval.ai_verdict ||
    `Priority score ${totalScore}/100 calculated from CISA KEV listing (+${kevPts} pts), AI practical severity (+${aiPts} pts), and public PoC code (+${pocPts} pts).`;

  document.getElementById('mAiKevEval').innerText = aiEval.cisa_kev_evaluation ||
    (kevPts > 0 ? '+40 pts: listed in CISA KEV, so attackers have been seen using it.' : '0 pts: not in CISA KEV; no exploitation confirmed.');

  document.getElementById('mAiSevEval').innerText = aiEval.ai_severity_evaluation ||
    `Awarded +${aiPts.toFixed(1)} pts: Qwen 2.5 assessed practical severity at ${(ai.severity_score || 0).toFixed(1)}/10 from the advisory text.`;

  document.getElementById('mAiPocEval').innerText = aiEval.poc_evaluation ||
    (pocPts > 0 ? '+20 pts: a public GitHub repository names this CVE as a PoC (not run or verified).' : '0.0 pts: No public PoC repository discovered.');

  // In-Depth Vulnerability Explanation
  document.getElementById('mAiModel').innerText = ai.evaluated_by || 'Qwen 2.5 72B';
  
  // Items with a gate-verified grounded card show the card itself; others show the AI triage reasoning
  const card = item.grounded_card;
  const fullDesc = (card && card.mechanism) || indepth.full_description || ai.reasoning || env.Title || 'No description available.';
  document.getElementById('mFullDescription').innerText = fullDesc;
  renderCardSections(card);
  renderSourceFacts(item.source_facts || {});

  document.getElementById('mImpact').innerText = item.standard_category || ai.offensive_impact || 'Security Vulnerability';
  document.getElementById('mProduct').innerText = `${env.Vendor_Product || 'Generic Target'} (Scope: ${pf.category || 'PENTEST'})`;
  document.getElementById('mScopeReason').innerText = pf.reason || 'Placed by the web/mobile scope filter.';

  // Mitigation & Required Action
  const actionBox = document.getElementById('mActionBox');
  const actionText = document.getElementById('mRequiredAction');
  const remediation = (card && card.remediation) || indepth.required_action;
  if (remediation) {
    actionBox.classList.remove('hidden');
    actionText.innerText = remediation;
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
        if (tLower.includes('not cve-specific')) {
          typeBadgeCls = 'bg-slate-950 text-slate-400 border-slate-700 border-dashed';
        } else if (tLower.includes('poc') || tLower.includes('exploit')) {
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
              ${ref.found_via ? `<div class="text-[10px] text-slate-500">Found via: ${escapeHtml(ref.found_via)}</div>` : ''}
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

function renderCardSections(card) {
  const badge = document.getElementById('mSummaryBadge');
  const note = document.getElementById('mCardNote');
  const show = (id, on) => document.getElementById(id).classList.toggle('hidden', !on);

  if (!card) {
    badge.innerHTML = '<span class="text-slate-500">No verified card</span>';
    note.innerText = 'This item has no gate-verified card (it was not among the top items summarised, or its card did not pass the checks), so the text below is the AI triage reasoning.';
    ['mCardImpactBox', 'mCardTestBox', 'mCardRefsBox'].forEach(id => show(id, false));
    return;
  }

  badge.innerHTML = verifiedBadge({ grounded_card: card });
  note.innerText = `Written from the source text${card.model ? ` by ${card.model}` : ''}. Its CVE IDs, scores, CWEs, versions, known product names, commands, impact claims and links passed ${card.checks_run || 0} verification checks against the source.`;

  document.getElementById('mCardImpact').innerText = card.impact || '';
  show('mCardImpactBox', !!card.impact);

  const commands = (card.testing_syntax || []).filter(Boolean);
  document.getElementById('mCardTest').innerHTML = commands
    .map(cmd => `<pre class="bg-slate-900 p-2.5 rounded border border-slate-800 text-[11px] text-emerald-300 font-mono whitespace-pre-wrap break-all">${escapeHtml(cmd)}</pre>`)
    .join('');
  show('mCardTestBox', commands.length > 0);

  const refs = (card.references || []).filter(Boolean);
  document.getElementById('mCardRefs').innerHTML = refs
    .map(url => `<li><a href="${escapeAttr(url)}" target="_blank" rel="noopener" class="text-cyan-400 hover:underline">${escapeHtml(url)}</a></li>`)
    .join('');
  show('mCardRefsBox', refs.length > 0);
}

function renderSourceFacts(facts) {
  const versions = (facts.affected_versions || []).filter(Boolean);
  const pocs = (facts.pocs || []).filter(p => p && p.url);
  document.getElementById('mVersions').innerHTML = versions.map(v => `<li>${escapeHtml(v)}</li>`).join('');
  document.getElementById('mVersionsFrom').innerText = facts.versions_from ? `From the ${facts.versions_from}.` : '';
  document.getElementById('mVersionsBox').classList.toggle('hidden', versions.length === 0);
  document.getElementById('mPocs').innerHTML = pocs.map(p => {
    const st = linkStatusStyle(p);
    return `<li class="flex flex-wrap items-center gap-2"><a href="${escapeAttr(p.url)}" target="_blank" rel="noopener" class="text-cyan-400 hover:underline">${escapeHtml(p.url)}</a>` +
      `<span class="px-1.5 py-0.5 rounded border ${st.pill} text-[10px]">${escapeHtml(st.label)}</span></li>`;
  }).join('');
  document.getElementById('mPocBox').classList.toggle('hidden', pocs.length === 0);
  document.getElementById('mFactsBox').classList.toggle('hidden', versions.length === 0 && pocs.length === 0);
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

    // The token itself stays in .env; the API only says whether it is set
    const tokenStatus = document.getElementById('tokenStatus');
    if (tokenStatus && sec.bot_token_set) tokenStatus.innerText = '✅ Loaded from .env (TELEGRAM_BOT_TOKEN)';

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
  const chat = document.getElementById('inputChatId').value.trim();

  try {
    const res = await fetch('/api/channels/telegram', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secondary_channel: {
          enabled: enabled,
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

  const chat = document.getElementById('inputChatId').value.trim();

  try {
    const res = await fetch('/api/channels/telegram/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chat })
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

// ============================================================================
// Reader mode: the current advisories laid out as a newsletter
// ============================================================================
// The dashboard stays the home page. Reader mode reads the same filtered items
// (desk, recency window, category, search) and lays them out as an issue: a lead
// story, a contents list, Web and Mobile sections with the verified cards, and a
// short "briefly noted" list for items without a verified card.

let readerMode = false;
const READER_STORY_LIMIT = 12; // full stories per issue; the rest go to "Briefly noted"
const READER_BRIEF_LIMIT = 15;

function toggleReaderMode() {
  setReaderMode(!readerMode);
}

function setReaderMode(on, updateUrl = true) {
  readerMode = Boolean(on);
  document.body.classList.toggle('reader-on', readerMode);
  document.getElementById('readerView').classList.toggle('hidden', !readerMode);
  document.getElementById('readerToggleIcon').innerText = readerMode ? '📊' : '📰';
  document.getElementById('readerToggleLabel').innerText = readerMode ? 'Dashboard' : 'Reader mode';
  if (updateUrl) {
    const url = location.pathname + location.search + (readerMode ? '#reader' : '');
    if (url !== location.pathname + location.search + location.hash) history.replaceState(null, '', url);
  }
  if (readerMode) {
    renderReader(getFilteredCandidates());
    window.scrollTo(0, 0);
  }
}

function readerEdition() {
  if (currentDateFilter === 'RECENT') return { name: 'Weekly edition', span: 'this week' };
  if (currentDateFilter === 'MONTH') return { name: 'Monthly edition', span: 'this month' };
  return { name: 'Full archive', span: 'across everything we track' };
}

function readerDesk(item) {
  return (item.pre_filter || {}).category === 'MOBILE' ? 'Mobile' : 'Web';
}

function readerKicker(item) {
  const env = item.envelope || {};
  const ai = item.ai_assessment || {};
  const isKev = Boolean(env.KEV_Status) || ((item.score_breakdown || {}).cisa_kev_points || 0) > 0;
  const hasPoc = Boolean(env.PoC_URLs && env.PoC_URLs.length) || ((item.score_breakdown || {}).poc_points || 0) > 0;
  const cat = getCategoryPill(item.standard_category || ai.offensive_impact).label.replace(/^[^\w\s]+\s/u, '');
  return `
    <div class="kicker">
      <span>${escapeHtml(readerDesk(item))} · ${escapeHtml(cat)}</span>
      ${isKev ? '<span class="kev">Actively exploited</span>' : ''}
      ${hasPoc ? '<span class="poc">Public PoC</span>' : ''}
      <span class="quiet">${escapeHtml(item.published_date_formatted || recencyLabel(env.Published_Date))}</span>
    </div>`;
}

function readerFacts(item) {
  const facts = item.source_facts || {};
  const versions = (facts.affected_versions || []).filter(Boolean);
  const pocs = (facts.pocs || []).filter(p => p && p.url);
  if (!versions.length && !pocs.length) return '';
  const shown = versions.slice(0, 3).map(v => `<code>${escapeHtml(v)}</code>`).join(' ');
  const more = versions.length > 3 ? ` <span class="label">+${versions.length - 3} more</span>` : '';
  const pocLinks = pocs
    .map(p => `<a href="${escapeAttr(p.url)}" target="_blank" rel="noopener">${escapeHtml(p.url.replace(/^https?:\/\//, ''))}</a>`)
    .join(', ');
  return `
    <div class="facts">
      ${versions.length ? `<div><span class="label">Affected:</span> ${shown}${more}</div>` : ''}
      ${pocs.length ? `<div><span class="label">Proof of concept:</span> ${pocLinks}</div>` : ''}
    </div>`;
}

function readerStory(item, isLead) {
  const env = item.envelope || {};
  const card = item.grounded_card || {};
  const id = escapeAttr(env.Item_ID);
  const score = (item.priority_score || 0).toFixed(0);
  return `
    <article id="story-${id}" class="${isLead ? 'lead' : ''}">
      ${readerKicker(item)}
      <h3><a href="javascript:void(0)" onclick="openDetailModal('${id}')">${escapeHtml(env.Title)}</a></h3>
      ${card.impact ? `<p class="dek">${escapeHtml(card.impact)}</p>` : ''}
      ${card.mechanism ? `<p class="body">${escapeHtml(card.mechanism)}</p>` : ''}
      ${card.remediation ? `<div class="action"><b>What to do</b>${escapeHtml(card.remediation)}</div>` : ''}
      ${readerFacts(item)}
      <div class="byline">
        <span>${escapeHtml(env.CVE_ID || env.Item_ID)}</span>
        <span>Priority ${score}/100</span>
        <span class="verified" title="Written from the source and passed ${card.checks_run || 0} verification checks">✓ Verified against the source</span>
        <a href="javascript:void(0)" onclick="openDetailModal('${id}')">Full details</a>
        ${env.Source_URL ? `<a href="${escapeAttr(env.Source_URL)}" target="_blank" rel="noopener">Source</a>` : ''}
      </div>
    </article>`;
}

function readerBrief(x) {
  const env = x.envelope || {};
  const text = (x.in_depth || {}).brief_summary || (x.ai_assessment || {}).reasoning || '';
  const short = text.length > 220 ? text.slice(0, 217) + '…' : text;
  return `<li><b><a href="javascript:void(0)" onclick="openDetailModal('${escapeAttr(env.Item_ID)}')">${escapeHtml(env.Title)}</a></b>` +
    `<span class="meta">${readerDesk(x)} · ${(x.priority_score || 0).toFixed(0)}/100</span>` +
    (short ? `<br><span>${escapeHtml(short)}</span>` : '') + '</li>';
}

function scrollToStory(itemId) {
  const el = document.getElementById('story-' + itemId);
  if (el) el.scrollIntoView({ behavior: 'smooth' });
}

function renderReader(filtered) {
  const box = document.getElementById('readerView');
  if (!box) return;

  // A newsletter leads with what matters most, whatever the dashboard's sort order
  const items = [...filtered].sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));
  const withCard = items.filter(x => x.grounded_card && (x.grounded_card.mechanism || x.grounded_card.impact));
  const stories = withCard.slice(0, READER_STORY_LIMIT);
  const storyIds = new Set(stories.map(x => x.envelope.Item_ID));
  const briefs = items.filter(x => !storyIds.has(x.envelope.Item_ID) && ((x.ai_assessment || {}).severity_score || 0) > 0);

  const edition = readerEdition();
  const today = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  const kev = items.filter(x => (x.envelope || {}).KEV_Status).length;
  const poc = items.filter(x => ((x.envelope || {}).PoC_URLs || []).length).length;
  const web = items.filter(x => readerDesk(x) === 'Web').length;
  const mobile = items.length - web;
  const deskNote = currentDesk === 'WEB' ? 'Web desk only. ' : currentDesk === 'MOBILE' ? 'Mobile desk only. ' : '';
  const filterNote = currentSearch
    ? `Matching “${escapeHtml(currentSearch)}”. `
    : currentCategory !== 'ALL' ? `Category: ${escapeHtml(currentCategory)}. ` : '';

  const switcher = [['RECENT', 'Week'], ['MONTH', 'Month'], ['ALL', 'All']]
    .map(([k, label]) => `<button class="${currentDateFilter === k ? 'active' : ''}" onclick="filterDateWindow('${k}')">${label}</button>`)
    .join('');

  let html = `
    <div class="masthead">
      <div class="eyebrow">Web &amp; Mobile Pentest Briefing</div>
      <h1>GroundedCVE</h1>
      <div class="tagline">The vulnerabilities worth a pentester's time, checked against their sources</div>
    </div>
    <div class="issue-line">
      <span><b>${edition.name}</b> · ${today}</span>
      <span class="edition-switch no-print">${switcher}</span>
    </div>`;

  if (!items.length) {
    box.innerHTML = html + `<p class="empty">No advisories ${edition.span}. Try the Month or All edition.</p>`;
    return;
  }

  const lead = stories[0];
  const leadTitle = lead ? escapeHtml(lead.envelope.Title.replace(/^CVE-\d+-\d+\s+-\s+/, '')) : '';
  html += `
    <p class="intro">${deskNote}${filterNote}We tracked <b>${items.length}</b> in-scope advisories ${edition.span}${kev ? `, <b>${kev}</b> of them already exploited in the wild` : ''}.
      ${lead ? `Top of the list: <i>${leadTitle}</i>.` : ''}</p>
    <div class="glance">
      <div><strong>${items.length}</strong><span>Advisories</span></div>
      <div><strong>${kev}</strong><span>Exploited (KEV)</span></div>
      <div><strong>${poc}</strong><span>Public PoC</span></div>
      <div><strong>${web} / ${mobile}</strong><span>Web / Mobile</span></div>
    </div>`;

  if (lead) {
    html += `<h2 class="section">Lead story</h2>${readerStory(lead, true)}`;
    const rest = stories.slice(1);
    if (rest.length) {
      html += '<h2 class="section">In this issue</h2><ol class="toc">' +
        rest.map(x => `<li><a href="#story-${escapeAttr(x.envelope.Item_ID)}" onclick="event.preventDefault(); scrollToStory('${escapeAttr(x.envelope.Item_ID)}')">${escapeHtml(x.envelope.Title)}</a><span class="toc-tag">${readerDesk(x)}</span></li>`).join('') +
        '</ol>';
      for (const desk of ['Web', 'Mobile']) {
        const deskStories = rest.filter(x => readerDesk(x) === desk);
        if (deskStories.length) {
          html += `<h2 class="section">${desk === 'Web' ? '🌐 Web' : '📱 Mobile'}</h2>` + deskStories.map(x => readerStory(x, false)).join('');
        }
      }
    }
  }

  if (briefs.length) {
    html += '<h2 class="section">Briefly noted</h2><ul class="brief-list">' +
      briefs.slice(0, READER_BRIEF_LIMIT).map(readerBrief).join('') + '</ul>';
    if (briefs.length > READER_BRIEF_LIMIT) {
      html += `<p class="sans more-note">…and ${briefs.length - READER_BRIEF_LIMIT} more on the <a href="javascript:void(0)" onclick="setReaderMode(false)">dashboard</a>.</p>`;
    }
  }

  html += `
    <footer>
      <span>Stories are written from each advisory's own source text and pass GroundedCVE's verification checks before they appear. Briefly noted items are AI triage notes, not verified summaries.</span>
      <span class="no-print"><button onclick="window.print()">Print / save as PDF</button></span>
    </footer>`;

  box.innerHTML = html;
}
