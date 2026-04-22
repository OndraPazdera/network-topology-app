<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
auth_require_json(['editor', 'admin']);

header('Content-Type: application/json; charset=utf-8');

$dataFile = __DIR__ . '/../data/devices.json';
$lockFile = __DIR__ . '/../data/devices.json.lock';
$backupDir = __DIR__ . '/../data/backups';
$allowedTypes = ['firewall', 'router', 'switch', 'server', 'vm', 'storage', 'printer', 'phone', 'pc'];
$editableFields = ['hostname', 'type', 'vendor', 'comment', 'mac', 'warn'];
$maxLengths = [
    'hostname' => 128,
    'type' => 32,
    'vendor' => 128,
    'comment' => 1000,
    'mac' => 32,
    'warn' => 1000,
];

function json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function fail_validation(string $field, string $message): void
{
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'validation_failed',
            'field' => $field,
            'message' => $message,
        ],
    ]);
}

function cleanup_temp(?string $tempFile): void
{
    if ($tempFile !== null && is_file($tempFile)) {
        @unlink($tempFile);
    }
}

function value_length(string $value): int
{
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(405, [
        'ok' => false,
        'error' => [
            'code' => 'method_not_allowed',
            'message' => 'Use POST with a JSON request body.',
        ],
    ]);
}
auth_require_csrf_json();


$rawRequest = file_get_contents('php://input');
if ($rawRequest === false || trim($rawRequest) === '') {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'empty_request_body',
            'message' => 'Request body is empty.',
        ],
    ]);
}

$input = json_decode($rawRequest, true);
if (!is_array($input) || json_last_error() !== JSON_ERROR_NONE) {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'malformed_json',
            'message' => 'Request body contains malformed JSON: ' . json_last_error_msg(),
        ],
    ]);
}

$ip = isset($input['ip']) ? trim((string) $input['ip']) : '';
if ($ip === '') {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'missing_ip',
            'message' => 'Device IP is required.',
        ],
    ]);
}

$updates = [];
foreach ($editableFields as $field) {
    if (!array_key_exists($field, $input)) {
        continue;
    }

    if (!is_string($input[$field])) {
        fail_validation($field, ucfirst($field) . ' must be a string.');
    }

    $value = trim($input[$field]);
    if (value_length($value) > $maxLengths[$field]) {
        fail_validation($field, ucfirst($field) . ' is too long. Maximum length is ' . $maxLengths[$field] . ' characters.');
    }

    $updates[$field] = $value;
}

if (array_key_exists('hostname', $updates) && $updates['hostname'] === '') {
    fail_validation('hostname', 'Hostname cannot be empty.');
}

if (array_key_exists('type', $updates) && !in_array($updates['type'], $allowedTypes, true)) {
    fail_validation('type', 'Unknown device type.');
}

if (array_key_exists('mac', $updates) && $updates['mac'] !== '' && !preg_match('/^[0-9A-Fa-f:.-]+$/', $updates['mac'])) {
    fail_validation('mac', 'MAC address contains unsupported characters.');
}

if (!is_file($dataFile)) {
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'devices_file_missing',
            'message' => 'Device data file is missing.',
        ],
    ]);
}

$lockHandle = fopen($lockFile, 'c');
if ($lockHandle === false) {
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'lock_file_open_failed',
            'message' => 'Persistence lock file cannot be opened.',
        ],
    ]);
}

if (!flock($lockHandle, LOCK_EX)) {
    fclose($lockHandle);
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'lock_failed',
            'message' => 'Device data lock could not be acquired.',
        ],
    ]);
}

$tempFile = null;
try {
    $rawData = file_get_contents($dataFile);
    if ($rawData === false) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'devices_file_read_failed',
                'message' => 'Device data file could not be read.',
            ],
        ]);
    }

    $devices = json_decode($rawData, true);
    if (!is_array($devices) || json_last_error() !== JSON_ERROR_NONE) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'devices_json_invalid',
                'message' => 'Device data file contains invalid JSON: ' . json_last_error_msg(),
            ],
        ]);
    }

    $deviceIndex = null;
    foreach ($devices as $index => $device) {
        if (isset($device['ip']) && (string) $device['ip'] === $ip) {
            $deviceIndex = $index;
            break;
        }
    }

    if ($deviceIndex === null) {
        json_response(404, [
            'ok' => false,
            'error' => [
                'code' => 'device_not_found',
                'message' => 'No device exists with IP ' . $ip . '.',
            ],
        ]);
    }

    foreach ($updates as $field => $value) {
        $devices[$deviceIndex][$field] = $value;
    }

    if (!is_dir($backupDir) && !mkdir($backupDir, 0775, true) && !is_dir($backupDir)) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'backup_directory_create_failed',
                'message' => 'Backup directory could not be created.',
            ],
        ]);
    }

    $backupName = sprintf('devices-%s-%s.json', date('Ymd-His'), bin2hex(random_bytes(4)));
    $backupFile = $backupDir . '/' . $backupName;
    if (file_put_contents($backupFile, $rawData, LOCK_EX) === false) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'backup_write_failed',
                'message' => 'Backup file could not be written.',
            ],
        ]);
    }

    $newJson = json_encode($devices, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if ($newJson === false) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'json_encode_failed',
                'message' => 'Updated device data could not be encoded.',
            ],
        ]);
    }
    $newJson .= PHP_EOL;

    $dataDir = dirname($dataFile);
    $tempFile = tempnam($dataDir, 'devices.tmp.');
    if ($tempFile === false) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'temp_file_create_failed',
                'message' => 'Temporary data file could not be created.',
            ],
        ]);
    }

    $bytesWritten = file_put_contents($tempFile, $newJson, LOCK_EX);
    if ($bytesWritten === false || $bytesWritten < strlen($newJson)) {
        cleanup_temp($tempFile);
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'temp_file_write_failed',
                'message' => 'Temporary data file could not be written completely.',
            ],
        ]);
    }

    $verifyRaw = file_get_contents($tempFile);
    $verifyData = $verifyRaw === false ? null : json_decode($verifyRaw, true);
    if (!is_array($verifyData) || json_last_error() !== JSON_ERROR_NONE) {
        cleanup_temp($tempFile);
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'temp_file_verify_failed',
                'message' => 'Temporary data file failed JSON verification.',
            ],
        ]);
    }

    if (!rename($tempFile, $dataFile)) {
        cleanup_temp($tempFile);
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'atomic_replace_failed',
                'message' => 'Device data file could not be atomically replaced.',
            ],
        ]);
    }
    $tempFile = null;

    json_response(200, [
        'ok' => true,
        'device' => $devices[$deviceIndex],
    ]);
} finally {
    cleanup_temp($tempFile);
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}