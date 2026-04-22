class NetworkMapApp {
  constructor(config) {
    this.api = config.api;
    this.typeLabels = config.typeLabels;
    this.typeIcons = config.typeIcons;
    this.typeOrder = config.typeOrder;
    this.user = config.user || { role: 'viewer' };
    this.csrfToken = config.csrfToken || '';
    this.canEdit = ['editor', 'admin'].includes(this.user.role);

    this.devices = [];
    this.sortKey = 'ip';
    this.sortDir = 1;
    this.typeFilter = 'all';
    this.statusFilter = 'all';
    this.editingIp = null;
    this.elements = {};
  }

  async init() {
    this.cacheElements();
    this.bindEvents();
    this.renderLegend();
    await this.loadDevices();
    return this;
  }

  cacheElements() {
    this.elements.alert = document.getElementById('app-alert');
    this.elements.statsBar = document.getElementById('stats-bar');
    this.elements.legend = document.getElementById('legend');
    this.elements.topologyRoot = document.getElementById('topology-root');
    this.elements.topoSearch = document.getElementById('topo-search');
    this.elements.tableSearch = document.getElementById('table-search');
    this.elements.tableBody = document.getElementById('table-body');
    this.elements.modal = document.getElementById('modal');
    this.elements.modalTitle = document.getElementById('modal-title');
    this.elements.modalBody = document.getElementById('modal-body');
  }

  bindEvents() {
    this.elements.topoSearch.addEventListener('input', () => this.buildTopology());
    this.elements.tableSearch.addEventListener('input', () => this.renderTable());

    document.querySelectorAll('[data-tab]').forEach((button) => {
      button.addEventListener('click', () => this.switchTab(button.dataset.tab));
    });

    document.querySelectorAll('[data-status-filter]').forEach((button) => {
      button.addEventListener('click', () => this.setStatusFilter(button, button.dataset.statusFilter));
    });

    document.querySelectorAll('[data-type-filter]').forEach((button) => {
      button.addEventListener('click', () => this.setTypeFilter(button, button.dataset.typeFilter));
    });

    document.querySelectorAll('[data-export]').forEach((button) => {
      button.addEventListener('click', () => this.exportCSV());
    });

    document.querySelectorAll('[data-sort-key]').forEach((header) => {
      header.addEventListener('click', () => this.sortTable(header.dataset.sortKey));
    });

    this.elements.tableBody.addEventListener('click', (event) => {
      const button = event.target.closest('[data-edit-ip]');
      if (button) this.openModal(button.dataset.editIp);
    });

    this.elements.modal.addEventListener('click', (event) => {
      if (event.target === this.elements.modal) this.closeModal();
    });

    document.querySelector('[data-modal-close]').addEventListener('click', () => this.closeModal());

    this.elements.modalBody.addEventListener('click', (event) => {
      if (event.target.closest('[data-save-edit]')) this.saveEdit();
      if (event.target.closest('[data-close-modal]')) this.closeModal();
      const rollbackButton = event.target.closest('[data-rollback-event]');
      if (rollbackButton) this.rollbackDevice(rollbackButton.dataset.rollbackEvent);
    });
  }

  async loadDevices() {
    try {
      this.clearAlert();
      const response = await fetch(this.api.devices, { cache: 'no-store' });
      const payload = await this.readJsonResponse(response);

      if (!response.ok || payload.ok === false) {
        if (this.isSessionExpired(payload)) {
          this.handleSessionExpired(payload);
          return;
        }
        throw new Error(this.errorMessage(payload, `HTTP ${response.status}`));
      }

      const devices = Array.isArray(payload) ? payload : payload.devices;
      if (!Array.isArray(devices)) throw new Error('API response does not contain a devices array.');

      this.devices = devices;
      this.renderStats();
      this.buildTopology();
      this.renderTable();
    } catch (error) {
      console.error('Device load failed:', error);
      this.devices = [];
      this.renderStats();
      this.buildTopology();
      this.renderTable();
      this.showAlert(`Nepodarilo se nacist sdilena data: ${error.message}`);
    }
  }

  async readJsonResponse(response) {
    const text = await response.text();
    if (!text) return {};

    try {
      return JSON.parse(text);
    } catch (error) {
      console.error('Invalid JSON response:', text);
      throw new Error('Server returned invalid JSON.');
    }
  }

  errorMessage(payload, fallback) {
    if (payload && payload.error && payload.error.message) return payload.error.message;
    if (payload && payload.message) return payload.message;
    return fallback;
  }

  isSessionExpired(payload) {
    return payload && payload.error && payload.error.code === 'session_expired';
  }

  handleSessionExpired(payload) {
    const message = this.errorMessage(payload, 'Session expired. Please log in again.');
    this.showAlert(message);
    this.showModalError(message);
    window.setTimeout(() => {
      window.location.href = 'login.php?expired=1';
    }, 1200);
  }

  renderStats() {
    const counts = { online: 0, offline: 0, warn: 0 };
    this.typeOrder.forEach((type) => counts[type] = 0);

    this.devices.forEach((device) => {
      if (counts[device.type] !== undefined) counts[device.type]++;
      if (device.online) counts.online++;
      else counts.offline++;
      if (device.warn) counts.warn++;
    });

    const items = [
      { label: 'Celkem', value: this.devices.length, className: 'text-accent' },
      { label: 'Online', value: counts.online, className: 'text-green' },
      { label: 'Offline', value: counts.offline, className: 'muted' },
      { label: '⚠ Varování', value: counts.warn, className: 'text-yellow' },
      ...this.typeOrder
        .filter((type) => counts[type] > 0)
        .map((type) => ({ label: this.typeLabels[type], value: counts[type], className: `text-${type}` }))
    ];

    this.elements.statsBar.innerHTML = items.map((item, index) => {
      const divider = index > 0 ? '<div class="hdiv"></div>' : '';
      return `${divider}<div class="stat"><div class="stat-val ${item.className}">${item.value}</div><div class="stat-label">${item.label}</div></div>`;
    }).join('');
  }

  renderLegend() {
    const typeItems = this.typeOrder.map((type) => (
      `<div class="li"><div class="ld type-${type}"></div>${this.typeIcons[type]} ${this.typeLabels[type]}</div>`
    ));

    this.elements.legend.innerHTML = [
      ...typeItems,
      '<div class="li legend-alert">⚠ Vyžaduje pozornost</div>',
      '<div class="li muted">○ Offline</div>'
    ].join('');
  }

  buildTopology() {
    const query = this.elements.topoSearch.value.toLowerCase();
    const grouped = {};
    this.typeOrder.forEach((type) => grouped[type] = []);

    this.devices
      .filter((device) => this.matchesTopologyFilters(device, query))
      .forEach((device) => {
        if (grouped[device.type]) grouped[device.type].push(device);
      });

    this.elements.topologyRoot.innerHTML = '';

    this.typeOrder.forEach((type) => {
      const devices = grouped[type];
      if (!devices.length) return;

      const layer = document.createElement('div');
      layer.className = 'topo-layer';

      const title = document.createElement('div');
      title.className = 'layer-title';
      const onlineCount = devices.filter((device) => device.online).length;
      title.innerHTML = `${this.typeIcons[type]} ${this.typeLabels[type].toUpperCase()} <span class="layer-count">(${devices.length}, ${onlineCount} online)</span>`;
      layer.appendChild(title);

      const row = document.createElement('div');
      row.className = 'node-row';
      devices.forEach((device) => row.appendChild(this.createNode(device)));
      layer.appendChild(row);
      this.elements.topologyRoot.appendChild(layer);
    });
  }

  matchesTopologyFilters(device, query) {
    if (this.typeFilter !== 'all' && device.type !== this.typeFilter) return false;
    if (this.statusFilter === 'online' && !device.online) return false;
    if (this.statusFilter === 'offline' && device.online) return false;
    if (!query) return true;

    return [device.ip, device.hostname, device.comment, device.vendor, device.mac]
      .some((value) => String(value || '').toLowerCase().includes(query));
  }

  createNode(device) {
    const node = document.createElement('div');
    node.className = `node type-${device.type}${device.online ? '' : ' offline'}${device.warn ? ' warn' : ''}`;
    node.title = device.warn ? `⚠ ${device.warn}` : 'Klikněte pro detail / editaci';
    node.tabIndex = 0;
    node.setAttribute('role', 'button');
    if (this.canEdit) node.addEventListener('click', () => this.openModal(device.ip));
    node.addEventListener('keydown', (event) => {
      if (this.canEdit && (event.key === 'Enter' || event.key === ' ')) this.openModal(device.ip);
    });

    node.innerHTML = `
      <div class="node-head">
        <span class="node-icon">${this.typeIcons[device.type]}</span>
        <span class="node-name">${this.escapeHtml(device.hostname)}</span>
        ${device.warn ? '<span class="warn-icon">⚠</span>' : ''}
      </div>
      <div class="node-ip">${device.ip}</div>
      ${device.comment ? `<div class="node-comment">${this.escapeHtml(device.comment)}</div>` : ''}
      <span class="node-badge badge-${device.type}">${this.typeLabels[device.type]}</span>
    `;

    return node;
  }

  setTypeFilter(button, type) {
    document.querySelectorAll('[data-type-filter]').forEach((item) => item.classList.remove('active'));
    button.classList.add('active');
    this.typeFilter = type;
    this.buildTopology();
  }

  setStatusFilter(button, status) {
    document.querySelectorAll('[data-status-filter]').forEach((item) => item.classList.remove('active'));
    button.classList.add('active');
    this.statusFilter = status;
    this.buildTopology();
  }

  sortTable(key) {
    if (this.sortKey === key) this.sortDir *= -1;
    else {
      this.sortKey = key;
      this.sortDir = 1;
    }
    this.renderTable();
  }

  renderTable() {
    const query = this.elements.tableSearch.value.toLowerCase();
    const rows = this.devices
      .filter((device) => this.matchesTableSearch(device, query))
      .sort((left, right) => this.compareDevices(left, right));

    this.elements.tableBody.innerHTML = rows.map((device) => this.renderTableRow(device)).join('');
  }

  matchesTableSearch(device, query) {
    if (!query) return true;

    return [device.ip, device.hostname, device.comment, device.vendor, device.mac, this.typeLabels[device.type]]
      .some((value) => String(value || '').toLowerCase().includes(query));
  }

  compareDevices(left, right) {
    let leftValue = left[this.sortKey] || '';
    let rightValue = right[this.sortKey] || '';

    if (this.sortKey === 'ip') {
      leftValue = this.ipToNumber(left.ip);
      rightValue = this.ipToNumber(right.ip);
    }

    if (this.sortKey === 'rtt') {
      leftValue = left.rtt ?? 999;
      rightValue = right.rtt ?? 999;
    }

    if (this.sortKey === 'online') {
      leftValue = left.online ? 1 : 0;
      rightValue = right.online ? 1 : 0;
    }

    if (leftValue < rightValue) return -this.sortDir;
    if (leftValue > rightValue) return this.sortDir;
    return 0;
  }

  renderTableRow(device) {
    const rttClass = device.rtt == null ? 'rtt-off' : device.rtt <= 1 ? 'rtt-fast' : device.rtt <= 4 ? 'rtt-mid' : 'rtt-slow';
    const rttText = this.formatRtt(device.rtt);
    const rowClass = device.online ? '' : ' class="offline"';
    const warning = device.warn ? ` <span class="warn-icon" title="${this.escapeHtml(device.warn)}">⚠</span>` : '';
    const comment = device.comment ? this.escapeHtml(device.comment) : '<span class="muted">—</span>';

    return `
      <tr${rowClass}>
        <td><span class="status-dot ${device.online ? 'on' : 'off'}"></span></td>
        <td class="td-ip">${device.ip}</td>
        <td class="td-name">${this.escapeHtml(device.hostname)}${warning}</td>
        <td><span class="node-badge badge-${device.type}">${this.typeLabels[device.type]}</span></td>
        <td class="td-comment" title="${this.escapeHtml(device.comment || '')}">${comment}</td>
        <td class="td-vendor">${this.escapeHtml(device.vendor || '')}</td>
        <td class="td-mac">${device.mac}</td>
        <td class="${rttClass}">${rttText}</td>
        <td>${this.canEdit ? `<button class="edit-btn" type="button" data-edit-ip="${device.ip}">Editovat</button>` : ''}</td>
      </tr>
    `;
  }

  openModal(ip) {
    if (!this.canEdit) return;
    const device = this.devices.find((item) => item.ip === ip);
    if (!device) return;

    this.editingIp = ip;
    this.elements.modalTitle.innerHTML = `${this.typeIcons[device.type]} ${this.escapeHtml(device.hostname)} <span class="modal-title-ip">${device.ip}</span>`;
    this.elements.modalBody.innerHTML = this.renderEditForm(device);
    this.elements.modal.classList.add('open');
    this.loadDeviceHistory(ip);
  }

  renderEditForm(device) {
    const typeOptions = this.typeOrder.map((type) => (
      `<option value="${type}"${device.type === type ? ' selected' : ''}>${this.typeIcons[type]} ${this.typeLabels[type]}</option>`
    )).join('');

    const warning = device.warn
      ? `<div class="notice notice-warning"><b>⚠ Pozor:</b> ${this.escapeHtml(device.warn)}</div>`
      : '';

    return `
      ${warning}
      <div class="modal-error" id="modal-error" role="alert" hidden></div>
      <div class="edit-form">
        <div class="form-row"><label class="form-label">Hostname</label><input class="form-input" id="e-hostname" value="${this.escapeHtml(device.hostname)}"></div>
        <div class="form-row"><label class="form-label">Typ zařízení</label><select class="form-select" id="e-type">${typeOptions}</select></div>
        <div class="form-row"><label class="form-label">Výrobce</label><input class="form-input" id="e-vendor" value="${this.escapeHtml(device.vendor || '')}"></div>
        <div class="form-row"><label class="form-label">Komentář / uživatel / umístění</label><textarea class="form-textarea" id="e-comment">${this.escapeHtml(device.comment || '')}</textarea></div>
        <div class="form-row"><label class="form-label">MAC adresa</label><input class="form-input" id="e-mac" value="${this.escapeHtml(device.mac)}"></div>
        <div class="form-row"><label class="form-label">Varování (interní poznámka, ⚠)</label><input class="form-input" id="e-warn" value="${this.escapeHtml(device.warn || '')}" placeholder="např. nesoulad MAC, vysoká latence…"></div>
        <div class="modal-row modal-ip-row"><span class="modal-key">IP adresa</span><span class="modal-val">${device.ip}</span></div>
        <div class="modal-row"><span class="modal-key">Stav</span><span class="modal-val ${device.online ? 'text-green' : 'muted'}">${device.online ? '● Online' : '○ Offline'}</span></div>
        <div class="modal-row"><span class="modal-key">RTT latence</span><span class="modal-val">${this.formatRtt(device.rtt)}</span></div>
        <div class="form-actions">
          <button class="btn-save" type="button" data-save-edit>💾 Uložit změny</button>
          <button class="btn-cancel" type="button" data-close-modal>Zrušit</button>
        </div>
        <div class="history-panel">
          <div class="layer-title">Device history by IP</div>
          <div id="device-history" class="history-list">Loading history...</div>
        </div>
      </div>
    `;
  }

  async loadDeviceHistory(ip) {
    const historyRoot = document.getElementById('device-history');
    if (!historyRoot || !this.api.deviceHistory) return;

    historyRoot.textContent = 'Loading history...';
    try {
      const response = await fetch(`${this.api.deviceHistory}?ip=${encodeURIComponent(ip)}`, { cache: 'no-store' });
      const payload = await this.readJsonResponse(response);
      if (!response.ok || payload.ok === false) {
        if (this.isSessionExpired(payload)) {
          this.handleSessionExpired(payload);
          return;
        }
        throw new Error(this.errorMessage(payload, `HTTP ${response.status}`));
      }

      historyRoot.innerHTML = this.renderDeviceHistory(payload.events || [], !!payload.canRollback);
    } catch (error) {
      console.error('Device history load failed:', error);
      historyRoot.innerHTML = `<div class="muted">History unavailable: ${this.escapeHtml(error.message)}</div>`;
    }
  }

  renderDeviceHistory(events, canRollback) {
    if (!events.length) return '<div class="muted">No device history recorded yet.</div>';

    return events.map((event) => {
      const changes = this.renderAuditChanges(event.changes || {});
      const rollback = canRollback && Object.keys(event.changes || {}).length
        ? `<button class="edit-btn" type="button" data-rollback-event="${this.escapeHtml(event.id)}">Rollback</button>`
        : '';
      return `
        <div class="history-item">
          <div class="history-head">
            <span>${this.escapeHtml(event.eventType || '')}</span>
            <span class="muted">${this.escapeHtml(this.formatTimestamp(event.timestamp))}</span>
          </div>
          <div class="history-meta">${this.escapeHtml((event.actor && event.actor.username) || 'system')} / ${this.escapeHtml((event.actor && event.actor.role) || 'system')}</div>
          ${event.summary ? `<div class="history-summary">${this.escapeHtml(event.summary)}</div>` : ''}
          ${changes}
          <div class="history-actions">${rollback}</div>
        </div>
      `;
    }).join('');
  }

  renderAuditChanges(changes) {
    const fields = Object.keys(changes);
    if (!fields.length) return '<div class="muted">No field changes recorded.</div>';

    return `<div class="history-changes">${fields.map((field) => {
      const change = changes[field] || {};
      return `
        <div class="history-change">
          <span class="history-field">${this.escapeHtml(field)}</span>
          <span>${this.escapeHtml(this.formatAuditValue(change.old))}</span>
          <span class="muted">-&gt;</span>
          <span>${this.escapeHtml(this.formatAuditValue(change.new))}</span>
        </div>
      `;
    }).join('')}</div>`;
  }

  async rollbackDevice(eventId) {
    if (!eventId || !window.confirm('Rollback the fields from this audit event?')) return;

    try {
      this.clearAlert();
      const response = await fetch(this.api.rollbackDevice, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': this.csrfToken
        },
        body: JSON.stringify({ event_id: eventId })
      });
      const payload = await this.readJsonResponse(response);
      if (!response.ok || payload.ok === false) {
        if (this.isSessionExpired(payload)) {
          this.handleSessionExpired(payload);
          return;
        }
        throw new Error(this.errorMessage(payload, `HTTP ${response.status}`));
      }

      const savedDevice = payload.device;
      const index = this.devices.findIndex((item) => item.ip === savedDevice.ip);
      if (index >= 0) this.devices[index] = savedDevice;
      this.renderStats();
      this.buildTopology();
      this.renderTable();
      this.openModal(savedDevice.ip);
    } catch (error) {
      console.error('Device rollback failed:', error);
      this.showModalError(`Rollback failed: ${error.message}`);
    }
  }

  async saveEdit() {
    const originalDevice = this.devices.find((item) => item.ip === this.editingIp);
    if (!originalDevice) return;

    const editedDevice = {
      ip: originalDevice.ip,
      hostname: document.getElementById('e-hostname').value.trim() || originalDevice.hostname,
      type: document.getElementById('e-type').value,
      vendor: document.getElementById('e-vendor').value.trim(),
      comment: document.getElementById('e-comment').value.trim(),
      mac: document.getElementById('e-mac').value.trim(),
      warn: document.getElementById('e-warn').value.trim()
    };

    try {
      this.clearAlert();
      const response = await fetch(this.api.saveDevice, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': this.csrfToken
        },
        body: JSON.stringify(editedDevice)
      });
      const payload = await this.readJsonResponse(response);

      if (!response.ok || payload.ok === false) {
        if (this.isSessionExpired(payload)) {
          this.handleSessionExpired(payload);
          return;
        }
        throw new Error(this.errorMessage(payload, `HTTP ${response.status}`));
      }

      const savedDevice = payload.device || editedDevice;
      const index = this.devices.findIndex((item) => item.ip === savedDevice.ip);
      if (index >= 0) this.devices[index] = savedDevice;

      this.closeModal();
      this.renderStats();
      this.buildTopology();
      this.renderTable();
    } catch (error) {
      console.error('Device save failed:', error);
      this.showModalError(`Nepodarilo se ulozit zmeny: ${error.message}`);
    }
  }

  closeModal() {
    this.elements.modal.classList.remove('open');
    this.editingIp = null;
  }

  switchTab(tab) {
    document.querySelectorAll('[data-tab]').forEach((button) => {
      button.classList.toggle('active', button.dataset.tab === tab);
    });

    document.querySelectorAll('.view').forEach((view) => {
      view.classList.toggle('active', view.id === `view-${tab}`);
    });
  }

  exportCSV() {
    const header = ['IP', 'Hostname', 'Typ', 'Komentar', 'Vyrobce', 'MAC', 'RTT (ms)', 'Online', 'Varovani'];
    const rows = this.devices.map((device) => [
      device.ip,
      device.hostname,
      this.typeLabels[device.type],
      device.comment || '',
      device.vendor || '',
      device.mac,
      device.rtt == null ? '' : device.rtt,
      device.online ? 'ano' : 'ne',
      device.warn || ''
    ].map((value) => `"${String(value).replace(/"/g, '""')}"`).join(','));

    const blob = new Blob([`\uFEFF${header.join(',')}\n${rows.join('\n')}`], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `sit-kancelarzp-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
  }

  showAlert(message) {
    if (!this.elements.alert) return;
    this.elements.alert.textContent = message;
    this.elements.alert.hidden = false;
  }

  showModalError(message) {
    const modalError = document.getElementById('modal-error');
    if (modalError) {
      modalError.textContent = message;
      modalError.hidden = false;
      return;
    }

    this.showAlert(message);
  }

  clearAlert() {
    if (this.elements.alert) {
      this.elements.alert.textContent = '';
      this.elements.alert.hidden = true;
    }

    const modalError = document.getElementById('modal-error');
    if (modalError) {
      modalError.textContent = '';
      modalError.hidden = true;
    }
  }

  ipToNumber(ip) {
    return ip.split('.').reduce((total, part) => total * 256 + parseInt(part || 0, 10), 0);
  }

  formatRtt(rtt) {
    if (rtt == null) return '—';
    if (rtt === 0) return '<1 ms';
    return `${rtt.toFixed(2)} ms`;
  }

  formatTimestamp(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  }

  formatAuditValue(value) {
    if (value === null || value === undefined) return '(missing)';
    if (value === '') return '(empty)';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.networkMapApp = new NetworkMapApp({
    api: API_ENDPOINTS,
    typeLabels: TYPE_LABELS,
    typeIcons: TYPE_ICONS,
    typeOrder: TYPE_ORDER,
    user: window.APP_USER,
    csrfToken: window.APP_CSRF_TOKEN
  });

  window.networkMapApp.init();
});
