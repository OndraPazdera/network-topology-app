<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
auth_require_json(['viewer', 'editor', 'admin']);

header('Content-Type: application/json; charset=utf-8');

$dataFile = __DIR__ . '/../data/devices.json';

function json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

if (!is_file($dataFile)) {
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'devices_file_missing',
            'message' => 'Device data file is missing.'
        ]
    ]);
}

$raw = file_get_contents($dataFile);
if ($raw === false) {
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'devices_file_unreadable',
            'message' => 'Device data file cannot be read.'
        ]
    ]);
}

$devices = json_decode($raw, true);
if (!is_array($devices) || json_last_error() !== JSON_ERROR_NONE) {
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'devices_json_invalid',
            'message' => 'Device data file contains invalid JSON: ' . json_last_error_msg()
        ]
    ]);
}

json_response(200, [
    'ok' => true,
    'devices' => $devices
]);