const API_ENDPOINTS = {
  devices: 'api/devices.php',
  saveDevice: 'api/save-device.php'
};

const TYPE_LABELS = {
  firewall: 'Firewall',
  router: 'Router/AP',
  switch: 'Switch',
  server: 'Server',
  vm: 'Virtuální stroj',
  pc: 'PC/Stanice',
  printer: 'Tiskárna',
  phone: 'IP Telefon',
  storage: 'Úložiště'
};

const TYPE_ICONS = {
  firewall: '🔒',
  router: '📡',
  switch: '🔀',
  server: '🖥',
  vm: '⚡',
  pc: '💻',
  printer: '🖨',
  phone: '📞',
  storage: '💾'
};

const TYPE_ORDER = ['firewall', 'router', 'switch', 'server', 'vm', 'storage', 'printer', 'phone', 'pc'];
const TYPE_COLORS = {firewall:'var(--red)',router:'var(--orange)',switch:'var(--yellow)',server:'var(--accent)',vm:'var(--accent2)',pc:'var(--green)',printer:'var(--purple)',phone:'var(--pink)',storage:'var(--teal)'};