<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';

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

auth_logout();
header('Location: login.php');
exit;