<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
$logoutUser = auth_current_user();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo 'Logout requires a POST request.';
    exit;
}

$csrfError = auth_require_csrf_post();
if ($csrfError !== null) {
    http_response_code(403);
    echo htmlspecialchars($csrfError, ENT_QUOTES, 'UTF-8');
    exit;
}

if ($logoutUser !== null) {
    audit_append(
        audit_actor($logoutUser),
        'logout',
        'user',
        (string) $logoutUser['username'],
        [],
        !empty($_POST['beacon']) ? 'User session closed by browser pagehide beacon.' : 'User logged out.'
    );
}
auth_logout();
if (!empty($_POST['beacon'])) {
    http_response_code(204);
    exit;
}

header('Location: login.php');
exit;
