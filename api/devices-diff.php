<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/topology-refresh.php';
auth_require_json(['viewer', 'editor', 'admin']);

$devicesFile = __DIR__ . '/../data/devices.json';
$leasesFile = __DIR__ . '/../data/imports/mikrotik-leases.json';
$nmapFile = __DIR__ . '/../data/imports/nmap-scan.xml';

function json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    json_response(405, [
        'ok' => false,
        'error' => [
            'code' => 'method_not_allowed',
            'message' => 'Use GET for topology diff.',
        ],
    ]);
}

try {
    json_response(200, ['ok' => true] + topology_build_refresh_state($devicesFile, $leasesFile, $nmapFile));
} catch (RuntimeException $error) {
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'topology_refresh_failed',
            'message' => $error->getMessage(),
        ],
    ]);
}
