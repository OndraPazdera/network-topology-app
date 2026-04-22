(function () {
  const root = document.getElementById('admin-user-history');
  const endpoint = window.APP_USER_HISTORY_API;
  if (!root || !endpoint) return;

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function formatTimestamp(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
  }

  function formatValue(value) {
    if (value === null || value === undefined) return '(missing)';
    if (value === '') return '(empty)';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  function renderChanges(changes) {
    const fields = Object.keys(changes || {});
    if (!fields.length) return '<div class="muted">No field changes recorded.</div>';

    return `<div class="history-changes">${fields.map((field) => {
      const change = changes[field] || {};
      return `
        <div class="history-change">
          <span class="history-field">${escapeHtml(field)}</span>
          <span>${escapeHtml(formatValue(change.old))}</span>
          <span class="muted">-&gt;</span>
          <span>${escapeHtml(formatValue(change.new))}</span>
        </div>
      `;
    }).join('')}</div>`;
  }

  function render(events) {
    if (!events.length) {
      root.innerHTML = '<div class="muted">No account history recorded yet.</div>';
      return;
    }

    root.innerHTML = events.map((event) => `
      <div class="history-item">
        <div class="history-head">
          <span>${escapeHtml(event.eventType)}</span>
          <span class="muted">${escapeHtml(formatTimestamp(event.timestamp))}</span>
        </div>
        <div class="history-meta">
          ${escapeHtml((event.actor && event.actor.username) || 'system')} / ${escapeHtml((event.actor && event.actor.role) || 'system')}
          &middot; ${escapeHtml((event.target && event.target.identifier) || '')}
        </div>
        ${event.summary ? `<div class="history-summary">${escapeHtml(event.summary)}</div>` : ''}
        ${renderChanges(event.changes)}
      </div>
    `).join('');
  }

  fetch(endpoint, { cache: 'no-store' })
    .then((response) => response.json().then((payload) => ({ response, payload })))
    .then(({ response, payload }) => {
      if (payload && payload.error && payload.error.code === 'session_expired') {
        window.location.href = 'login.php?expired=1';
        return;
      }
      if (!response.ok || payload.ok === false) {
        throw new Error((payload.error && payload.error.message) || `HTTP ${response.status}`);
      }
      render(payload.events || []);
    })
    .catch((error) => {
      root.innerHTML = `<div class="muted">History unavailable: ${escapeHtml(error.message)}</div>`;
    });
}());
