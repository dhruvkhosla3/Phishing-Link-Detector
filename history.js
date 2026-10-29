/**
 * history.js
 * Shared localStorage helpers + History page logic.
 * Loaded by both index.html (for saving) and history.html (for display).
 */

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------
const STORAGE_KEY = 'phishing_detector_history';

/** Read the full history array from localStorage (safe, never throws). */
function historyLoad() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Persist the full history array to localStorage. */
function historySave(entries) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // storage quota exceeded or unavailable — fail silently
  }
}

/** Clear all history from localStorage. */
function historyClear() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

/**
 * Add one entry. Prevents duplicate: if the same URL was already checked
 * within the last 2 seconds (double-click / double-submit guard), skip it.
 *
 * @param {Object} entry
 * @param {string} entry.url          - The checked URL/domain
 * @param {string} entry.status       - 'safe' | 'unsafe' | 'error'
 * @param {string} entry.statusLabel  - Human-readable: 'SAFE' | 'UNSAFE' | 'UNKNOWN/ERROR'
 * @param {string} entry.detail       - Reason / threat description
 * @param {string} entry.checkType    - e.g. 'URL/Domain Scan'
 */
function historyAddEntry(entry) {
  const entries = historyLoad();

  // Duplicate guard: same URL within 2 s
  const now = Date.now();
  const last = entries[0];
  if (last && last.url === entry.url && now - last.ts < 2000) return;

  const record = {
    id: now + '_' + Math.random().toString(36).slice(2, 7),
    ts: now,
    datetime: new Date(now).toLocaleString(),
    url: entry.url,
    status: entry.status,           // 'safe' | 'unsafe' | 'error'
    statusLabel: entry.statusLabel,
    detail: entry.detail || '',
    checkType: entry.checkType || 'URL/Domain Scan',
  };

  entries.unshift(record);  // newest first
  historySave(entries);
}

// ---------------------------------------------------------------------------
// History page — only runs when the #history-page root element exists
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  const page = document.getElementById('history-page');
  if (!page) return;   // not on the history page

  const listEl        = document.getElementById('history-list');
  const searchEl      = document.getElementById('history-search');
  const filterBtns    = document.querySelectorAll('.filter-btn');
  const clearBtn      = document.getElementById('clear-history-btn');
  const modal         = document.getElementById('confirm-modal');
  const modalConfirm  = document.getElementById('modal-confirm');
  const modalCancel   = document.getElementById('modal-cancel');
  const countEl       = document.getElementById('history-count');

  let currentFilter = 'all';
  let currentSearch = '';

  // ---- render ----
  function render() {
    let entries = historyLoad();

    // filter by status
    if (currentFilter !== 'all') {
      entries = entries.filter(e => e.status === currentFilter);
    }

    // filter by search text
    if (currentSearch) {
      const q = currentSearch.toLowerCase();
      entries = entries.filter(e =>
        e.url.toLowerCase().includes(q) ||
        (e.detail && e.detail.toLowerCase().includes(q))
      );
    }

    // update count badge
    const total = historyLoad().length;
    countEl.textContent = total === 0 ? 'No scans yet'
      : total === 1 ? '1 scan recorded'
      : `${total} scans recorded`;

    if (entries.length === 0) {
      listEl.innerHTML = buildEmptyState();
      return;
    }

    listEl.innerHTML = entries.map(buildCard).join('');
  }

  // ---- card builder ----
  function buildCard(e) {
    const statusClass = e.status;   // 'safe' | 'unsafe' | 'error'
    const icon = e.status === 'safe'   ? '[SAFE]'
               : e.status === 'unsafe' ? '[UNSAFE]'
               :                        '[ERROR]';
    const escapedUrl = escapeHtml(e.url);
    const escapedDetail = escapeHtml(e.detail || 'No additional detail available.');

    return `
      <div class="history-card ${statusClass}">
        <div class="card-header">
          <span class="card-icon">${icon}</span>
          <span class="card-url" title="${escapedUrl}">${escapedUrl}</span>
          <span class="card-badge badge-${statusClass}">${escapeHtml(e.statusLabel)}</span>
        </div>
        <div class="card-meta">
          <span class="meta-item">Time: ${escapeHtml(e.datetime)}</span>
          <span class="meta-item">Type: ${escapeHtml(e.checkType)}</span>
        </div>
        <div class="card-detail">${escapedDetail}</div>
      </div>`;
  }

  function buildEmptyState() {
    const msg = currentFilter !== 'all' || currentSearch
      ? 'No entries match your search or filter.'
      : 'No scan history yet. Check a URL on the main page!';
    return `
      <div class="empty-state">
        <div class="empty-icon">[ ]</div>
        <p>${msg}</p>
        ${(!currentSearch && currentFilter === 'all')
          ? '<a href="index.html" class="back-link">Go check a URL</a>'
          : ''}
      </div>`;
  }

  // ---- search ----
  searchEl.addEventListener('input', () => {
    currentSearch = searchEl.value.trim();
    render();
  });

  // ---- filter buttons ----
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      render();
    });
  });

  // ---- clear history ----
  clearBtn.addEventListener('click', () => {
    if (historyLoad().length === 0) return;
    modal.classList.add('visible');
  });

  modalCancel.addEventListener('click', () => {
    modal.classList.remove('visible');
  });

  modalConfirm.addEventListener('click', () => {
    historyClear();
    modal.classList.remove('visible');
    render();
  });

  // close modal on backdrop click
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.remove('visible');
  });

  // ---- initial render ----
  render();
});

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
