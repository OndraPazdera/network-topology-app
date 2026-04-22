<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
$currentUser = auth_require_json(['admin']);

$dataFile = __DIR__ . '/../data/devices.json';
$lockFile = __DIR__ . '/../data/devices.json.lock';
$backupDir = __DIR__ . '/../data/backups';
$editableFields = ['hostname', 'type', 'vendor', 'comment', 'mac', 'warn'];

function json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function cleanup_temp(?string $tempFile): void
{
    if ($tempFile !== null && is_file($tempFile)) {
        @unlink($tempFile);
    }
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
$input = $rawRequest === false ? null : json_decode($rawRequest, true);
if (!is_array($input) || json_last_error() !== JSON_ERROR_NONE) {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'malformed_json',
            'message' => 'Request body contains malformed JSON.',
        ],
    ]);
}

$eventId = trim((string) ($input['event_id'] ?? ''));
if ($eventId === '') {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'missing_event_id',
            'message' => 'Audit event id is required.',
        ],
    ]);
}

$sourceEvent = audit_find_event($eventId);
if ($sourceEvent === null || ($sourceEvent['target']['type'] ?? '') !== 'device') {
    json_response(404, [
        'ok' => false,
        'error' => [
            'code' => 'audit_event_not_found',
            'message' => 'Rollback source audit event was not found.',
        ],
    ]);
}

if (!in_array((string) ($sourceEvent['eventType'] ?? ''), ['device_update', 'device_rollback'], true)) {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'event_not_rollback_supported',
            'message' => 'Only device update and rollback events can be rolled back.',
        ],
    ]);
}

$ip = (string) ($sourceEvent['target']['identifier'] ?? '');
$sourceChanges = isset($sourceEvent['changes']) && is_array($sourceEvent['changes']) ? $sourceEvent['changes'] : [];
if ($ip === '' || $sourceChanges === []) {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'event_has_no_changes',
            'message' => 'Selected audit event has no field changes to roll back.',
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
    $devices = $rawData === false ? null : json_decode($rawData, true);
    if (!is_array($devices) || json_last_error() !== JSON_ERROR_NONE) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'devices_json_invalid',
                'message' => 'Device data file is missing or invalid.',
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

    $rollbackChanges = [];
    foreach ($sourceChanges as $field => $change) {
        if (!in_array((string) $field, $editableFields, true) || !is_array($change) || !array_key_exists('old', $change)) {
            continue;
        }

        $oldCurrentValue = array_key_exists($field, $devices[$deviceIndex]) ? $devices[$deviceIndex][$field] : null;
        $rollbackValue = $change['old'];
        if ($oldCurrentValue === $rollbackValue) {
            continue;
        }

        $devices[$deviceIndex][$field] = $rollbackValue;
        $rollbackChanges[$field] = [
            'old' => $oldCurrentValue,
            'new' => $rollbackValue,
        ];
    }

    if ($rollbackChanges === []) {
        json_response(409, [
            'ok' => false,
            'error' => [
                'code' => 'nothing_to_rollback',
                'message' => 'Current device values already match the selected audit event rollback values.',
            ],
        ]);
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

    $backupName = sprintf('devices-rollback-%s-%s.json', date('Ymd-His'), bin2hex(random_bytes(4)));
    if (file_put_contents($backupDir . '/' . $backupName, (string) $rawData, LOCK_EX) === false) {
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

    $tempFile = tempnam(dirname($dataFile), 'devices.tmp.');
    if ($tempFile === false || file_put_contents($tempFile, $newJson, LOCK_EX) === false) {
        cleanup_temp($tempFile);
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'temp_file_write_failed',
                'message' => 'Temporary data file could not be written.',
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

    $auditEvent = audit_append(
        audit_actor($currentUser),
        'device_rollback',
        'device',
        $ip,
        $rollbackChanges,
        'Device fields rolled back from audit event.',
        [
            'identifierField' => 'ip',
            'rollbackOf' => $eventId,
        ]
    );

    json_response(200, [
        'ok' => true,
        'device' => $devices[$deviceIndex],
        'auditEvent' => $auditEvent,
    ]);
} finally {
    cleanup_temp($tempFile);
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}
