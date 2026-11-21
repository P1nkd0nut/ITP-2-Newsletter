// ============================================================================
// Reader mode: the verified cards laid out as a newsletter edition.
// The dashboard stays the home page; this view is switched on from the header
// and remembered in the address (#reader) so it can be bookmarked or shared.
// Built with DOM nodes only, so source text is never parsed as HTML.
// ============================================================================

const READER_TOP_N = 12;
let readerLoaded = false;

function rEl(tag, className, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false || child === '') continue;
    node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

function rSafeUrl(url) {
  try {
    const u = new URL(url);
    return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : null;
  } catch (e) {
    return null;
  }
}

function rLink(url, text) {
  const href = rSafeUrl(url);
  if (!href) return rEl('span', '', text || url);
  const a = rEl('a', 'reader-link', text || url);
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}

function rShortUrl(url) {
  try {
    const u = new URL(url);
    const path = u.pathname.replace(/\/$/, '');
    return u.hostname.replace(/^www\./, '') + (path.length > 48 ? path.slice(0, 45) + '...' : path);
  } catch (e) {
    return url;
  }
}

// ISO 8601 week, matching the Telegram digest's "Edition YYYY-Wnn"
function isoEdition(date) {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const day = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, '0')}`;
}

// "CVE-2026-1 - Apache Roller ..." reads better without the repeated CVE prefix
function storyHeadline(t) {
  const title = String(t.title || t.cve_id || 'Untitled advisory');
  const cve = t.cve_id || '';
  return cve && title.toUpperCase().startsWith(cve.toUpperCase())
    ? title.slice(cve.length).replace(/^[\s\-–—:]+/, '') || title
    : title;
}

function storySection(label, ...body) {
  return rEl('div', 'reader-part', rEl('h4', 'reader-label', label), ...body);
}

function renderStory(t) {
  const card = t.grounded_card || {};
  const facts = t.source_facts || {};
  const id = `story-${t.rank}`;

  const kicker = rEl('p', 'reader-kicker',
    rEl('span', 'reader-rank', `No. ${t.rank}`),
    t.category === 'WEB' ? 'Web' : t.category === 'MOBILE' ? 'Mobile' : null,
    t.is_kev ? rEl('span', 'reader-flag reader-flag-kev', 'Actively exploited') : null,
    (facts.pocs || []).length ? rEl('span', 'reader-flag reader-flag-poc', 'Public PoC') : null,
    t.recency_label || null,
  );

  const meta = rEl('p', 'reader-meta',
    t.cve_id ? rEl('span', 'reader-cve', t.cve_id) : null,
    `Priority ${Number(t.priority_score || 0).toFixed(0)}/100`,
    t.cvss != null ? `CVSS ${t.cvss}` : null,
    rEl('span', 'reader-verified', `✓ Verified against the source (${card.checks_run || 0} checks)`),
  );

  const article = rEl('article', 'reader-story', kicker, rEl('h3', 'reader-headline', storyHeadline(t)), meta);
  article.id = id;

  if (card.mechanism) article.append(storySection('What it is', rEl('p', 'reader-body', card.mechanism)));
  if (card.impact) article.append(storySection('Why it matters', rEl('p', 'reader-body', card.impact)));

  const versions = facts.affected_versions || [];
  if (versions.length) {
    article.append(storySection('Affected versions',
      rEl('ul', 'reader-list', versions.map(v => rEl('li', '', v))),
      facts.versions_from ? rEl('p', 'reader-note', `From the ${facts.versions_from}.`) : null));
  }

  const commands = card.testing_syntax || [];
  if (commands.length) {
    article.append(storySection('How to test',
      commands.map(cmd => rEl('pre', 'reader-code', rEl('code', '', cmd))),
      rEl('p', 'reader-note', 'Copied from the source. Only run against systems you are authorised to test.')));
  }

  if (card.remediation) article.append(storySection('How to fix', rEl('p', 'reader-body', card.remediation)));

  const pocs = facts.pocs || [];
  if (pocs.length) {
    article.append(storySection('Proof of concept',
      rEl('ul', 'reader-list', pocs.map(p => rEl('li', '', rLink(p.url, rShortUrl(p.url))))),
      rEl('p', 'reader-note', 'Found by the GitHub PoC search for this CVE. Not run or verified.')));
  }

  const refs = (card.references || []).filter(rSafeUrl);
  if (refs.length) {
    article.append(storySection('Sources',
      rEl('ul', 'reader-list reader-sources', refs.map(u => rEl('li', '', rLink(u, rShortUrl(u))))),
      (t.also_reported_by || []).length ? rEl('p', 'reader-note', `Also reported by ${t.also_reported_by.join(', ')}.`) : null));
  }

  const more = rEl('button', 'reader-more', 'Open full details on the dashboard →');
  more.type = 'button';
  more.addEventListener('click', () => openDetailModal(t.item_id || t.cve_id));
  article.append(more);
  return article;
}

function renderReader(digest) {
  const root = document.getElementById('readerContent');
  root.replaceChildren();
  const now = new Date();
  const threats = digest.curated_threats || [];

  root.append(rEl('header', 'reader-masthead',
    rEl('p', 'reader-edition', `Edition ${isoEdition(now)} · ${now.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}`),
    rEl('h1', 'reader-title', 'GroundedCVE Weekly'),
    rEl('p', 'reader-tagline', 'Verified web and mobile vulnerabilities for penetration testers'),
  ));

  root.append(rEl('p', 'reader-lede',
    `GroundedCVE checked ${digest.total_evaluated || 0} advisories. ${digest.in_scope_count || 0} are in scope for web and mobile testing, `,
    `and ${digest.verified_count || 0} have a write-up that passed source verification. `,
    threats.length ? `The top ${threats.length} are below, ranked by active exploitation, severity and public proof of concept.` : 'No write-up has passed verification yet.'));

  if (threats.length) {
    root.append(rEl('nav', 'reader-contents',
      rEl('h2', 'reader-label', 'In this issue'),
      rEl('ol', '', threats.map(t => {
        const a = rEl('a', 'reader-link', storyHeadline(t));
        a.href = `#story-${t.rank}`;
        a.addEventListener('click', (e) => {
          e.preventDefault();
          document.getElementById(`story-${t.rank}`).scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        return rEl('li', '', a);
      }))));
    threats.forEach(t => root.append(renderStory(t)));
  }

  root.append(rEl('footer', 'reader-footer',
    rEl('p', '', 'Every CVE ID, version, score, command and link in these write-ups was checked against the source text before publishing. Proof-of-concept code is linked, never run.'),
    rEl('p', '', 'Generated automatically from public sources by GroundedCVE. Check the sources before acting on it.')));
}

async function loadReader() {
  const root = document.getElementById('readerContent');
  root.replaceChildren(rEl('p', 'reader-note', 'Loading this edition...'));
  try {
    const res = await fetch(`/api/newsletter/digest?top_n=${READER_TOP_N}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderReader(await res.json());
    readerLoaded = true;
  } catch (err) {
    root.replaceChildren(rEl('p', 'reader-note', 'Could not load the newsletter. Is the server running?'));
  }
}

function setReaderMode(on) {
  document.body.classList.toggle('reader-on', on);
  document.getElementById('readerView').classList.toggle('hidden', !on);
  document.getElementById('dashboardMain').classList.toggle('hidden', on);
  document.getElementById('readerToggleLabel').textContent = on ? 'Dashboard' : 'Reader mode';
  document.getElementById('readerToggleIcon').textContent = on ? '📊' : '📰';
  const hash = on ? '#reader' : '';
  if (location.hash !== hash) history.replaceState(null, '', location.pathname + location.search + hash);
  if (on && !readerLoaded) loadReader();
  window.scrollTo(0, 0);
}

function toggleReaderMode() {
  setReaderMode(!document.body.classList.contains('reader-on'));
}

document.addEventListener('DOMContentLoaded', () => {
  if (location.hash === '#reader') setReaderMode(true);
});
