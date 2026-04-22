<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
auth_require_json(['admin']);

function json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

$targetUsername = isset($_GET['username']) ? trim((string) $_GET['username']) : '';
$filters = ['eventTypes' => AUDIT_USER_EVENT_TYPES];
if ($targetUsername !== '') {
    $filters['targetType'] = 'user';
    $filters['targetIdentifier'] = $targetUsername;
}

json_response(200, [
    'ok' => true,
    'events' => audit_read_events($filters, 100),
]);
