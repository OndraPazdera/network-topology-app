(function () {
  const csrfToken = window.APP_CSRF_TOKEN || '';
  if (!csrfToken) return;

  let internalNavigation = false;

  function isSameOriginUrl(url) {
    try {
      return new URL(url, window.location.href).origin === window.location.origin;
    } catch (error) {
      return false;
    }
  }

  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[href]');
    if (!link || link.target) return;
    if (isSameOriginUrl(link.href)) internalNavigation = true;
  }, true);

  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!form || !form.action) return;
    if (isSameOriginUrl(form.action)) internalNavigation = true;
  }, true);

  window.addEventListener('pagehide', () => {
    if (internalNavigation) return;

    const body = new FormData();
    body.append('csrf_token', csrfToken);
    body.append('beacon', '1');

    if (navigator.sendBeacon && navigator.sendBeacon('logout.php', body)) {
      return;
    }

    fetch('logout.php', {
      method: 'POST',
      body,
      credentials: 'same-origin',
      keepalive: true
    }).catch(() => {});
  });
}());
