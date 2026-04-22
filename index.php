<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
$currentUser = auth_require_page();
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Síťová Mapa - kancelarzp.local</title>
  <link rel="stylesheet" href="css/styles.css">
</head>
<body>
  <header>
    <div>
      <div class="logo">SÍŤOVÁ MAPA <span>// kancelarzp.local</span></div>
      <div class="subtitle">10.77.77.0/24 &nbsp;·&nbsp; DHCP (MikroTik) + nmap 7.98 &nbsp;·&nbsp; 2026-04-22</div>
    </div>
    <div class="stats-bar" id="stats-bar"></div><div class="session-bar"><span><?= htmlspecialchars((string) $currentUser['username'], ENT_QUOTES, 'UTF-8') ?> / <?= htmlspecialchars((string) $currentUser['role'], ENT_QUOTES, 'UTF-8') ?></span><?php if ($currentUser['role'] === 'admin'): ?><a href="users.php">Users</a><?php endif; ?><a href="change-password.php">Password</a><form method="post" action="logout.php" class="logout-form"><?= auth_csrf_input() ?><button class="auth-link-button" type="submit">Logout</button></form></div>
  </header>

  <nav class="tabs" aria-label="Přepnutí pohledu">
    <button class="tab active" type="button" data-tab="topology">🗺 Topologie</button>
    <button class="tab" type="button" data-tab="table">📋 Tabulka</button>
  </nav>

  <div class="app-alert" id="app-alert" role="alert" hidden></div>

  <main>
    <section id="view-topology" class="view active">
      <div class="notice">
        <b>Zdroj dat:</b> Primární zdroj pravdy = MikroTik DHCP. Aktivita (online/RTT) = nmap sken.
        Žlutě orámované uzly mají <b>nesoulad mezi DHCP a nmap MAC</b> nebo známý problém.
      </div>

      <div class="legend" id="legend"></div>

      <div class="bar">
        <input class="search-input" id="topo-search" placeholder="Filtrovat (IP, hostname, uživatel, komentář)…">
        <button class="filter-btn active" type="button" data-status-filter="all">Vše</button>
        <button class="filter-btn" type="button" data-status-filter="online">● Jen online</button>
        <button class="filter-btn" type="button" data-status-filter="offline">○ Jen offline</button>
        <button class="export-btn" type="button" data-export>⬇ Export CSV</button>
      </div>

      <div class="bar type-filter-bar">
        <button class="filter-btn t active" type="button" data-type-filter="all">Vše</button>
        <button class="filter-btn t" type="button" data-type-filter="firewall">🔒 Firewall</button>
        <button class="filter-btn t" type="button" data-type-filter="router">📡 Router/AP</button>
        <button class="filter-btn t" type="button" data-type-filter="switch">🔀 Switch</button>
        <button class="filter-btn t" type="button" data-type-filter="server">🖥 Server</button>
        <button class="filter-btn t" type="button" data-type-filter="vm">⚡ VM</button>
        <button class="filter-btn t" type="button" data-type-filter="storage">💾 Úložiště</button>
        <button class="filter-btn t" type="button" data-type-filter="printer">🖨 Tiskárna</button>
        <button class="filter-btn t" type="button" data-type-filter="phone">📞 Telefon</button>
        <button class="filter-btn t" type="button" data-type-filter="pc">💻 PC</button>
      </div>

      <div class="topology" id="topology-root"></div>
    </section>

    <section id="view-table" class="view">
      <div class="bar">
        <input class="search-input" id="table-search" placeholder="Hledat IP, hostname, MAC, komentář, uživatele…">
        <button class="export-btn" type="button" data-export>⬇ Export CSV</button>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th data-sort-key="online">●</th>
              <th data-sort-key="ip">IP ↕</th>
              <th data-sort-key="hostname">Hostname ↕</th>
              <th data-sort-key="type">Typ ↕</th>
              <th data-sort-key="comment">Komentář / Uživatel ↕</th>
              <th data-sort-key="vendor">Výrobce ↕</th>
              <th>MAC</th>
              <th data-sort-key="rtt">RTT ↕</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="table-body"></tbody>
        </table>
      </div>
    </section>
  </main>

  <div class="overlay" id="modal">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <button class="modal-close" type="button" data-modal-close>✕</button>
      <div class="modal-title" id="modal-title"></div>
      <div id="modal-body"></div>
    </div>
  </div>

  <script>
    window.APP_USER = <?= json_encode(['username' => $currentUser['username'], 'role' => $currentUser['role']], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
    window.APP_CSRF_TOKEN = <?= json_encode(auth_csrf_token(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
  </script>
  <script src="js/data.js"></script>
  <script src="js/app.js"></script>
  <script src="js/session-logout.js"></script>
</body>
</html>
