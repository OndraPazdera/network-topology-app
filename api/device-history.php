<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
$currentUser = auth_require_json(['viewer', 'editor', 'admin']);

function json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

$ip = isset($_GET['ip']) ? trim((string) $_GET['ip']) : '';
if ($ip === '') {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'missing_ip',
            'message' => 'Device IP is required.',
        ],
    ]);
}

json_response(200, [
    'ok' => true,
    'identifierField' => 'ip',
    'targetIdentifier' => $ip,
    'canRollback' => ($currentUser['role'] ?? '') === 'admin',
    'events' => audit_read_events([
        'targetType' => 'device',
        'targetIdentifier' => $ip,
        'eventTypes' => ['device_update', 'device_rollback'],
    ], 25),
]);
