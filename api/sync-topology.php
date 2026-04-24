<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/topology-refresh.php';
$currentUser = auth_require_json(['editor', 'admin']);

$devicesFile = __DIR__ . '/../data/devices.json';
$lockFile = __DIR__ . '/../data/devices.json.lock';
$backupDir = __DIR__ . '/../data/backups';
$leasesFile = __DIR__ . '/../data/imports/mikrotik-leases.json';
$nmapFile = __DIR__ . '/../data/imports/nmap-scan.xml';

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

function write_devices_atomically(string $dataFile, array $devices): void
{
    $newJson = json_encode($devices, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if ($newJson === false) {
        throw new RuntimeException('Updated device data could not be encoded.');
    }
    $newJson .= PHP_EOL;

    $tempFile = tempnam(dirname($dataFile), 'devices.tmp.');
    try {
        if ($tempFile === false || file_put_contents($tempFile, $newJson, LOCK_EX) === false) {
            cleanup_temp($tempFile ?: null);
            throw new RuntimeException('Temporary data file could not be written.');
        }

        $verifyRaw = file_get_contents($tempFile);
        $verifyData = $verifyRaw === false ? null : json_decode($verifyRaw, true);
        if (!is_array($verifyData) || json_last_error() !== JSON_ERROR_NONE) {
            cleanup_temp($tempFile);
            throw new RuntimeException('Temporary data file failed JSON verification.');
        }

        if (!rename($tempFile, $dataFile)) {
            cleanup_temp($tempFile);
            throw new RuntimeException('Device data file could not be atomically replaced.');
        }
        $tempFile = null;
    } finally {
        cleanup_temp($tempFile ?: null);
    }
}

function backup_devices(string $backupDir, string $rawData, string $mode): string
{
    if (!is_dir($backupDir) && !mkdir($backupDir, 0775, true) && !is_dir($backupDir)) {
        throw new RuntimeException('Backup directory could not be created.');
    }

    $backupName = sprintf('devices-sync-%s-%s-%s.json', $mode, date('Ymd-His'), bin2hex(random_bytes(4)));
    $backupFile = $backupDir . '/' . $backupName;
    if (file_put_contents($backupFile, $rawData, LOCK_EX) === false) {
        throw new RuntimeException('Backup file could not be written.');
    }

    return $backupName;
}

function request_input(): array
{
    $rawRequest = file_get_contents('php://input');
    if ($rawRequest === false || trim($rawRequest) === '') {
        return [];
    }

    $input = json_decode($rawRequest, true);
    if (!is_array($input) || json_last_error() !== JSON_ERROR_NONE) {
        json_response(400, [
            'ok' => false,
            'error' => [
                'code' => 'malformed_json',
                'message' => 'Request body contains malformed JSON.',
            ],
        ]);
    }

    return $input;
}

function apply_single_sync(array $currentDevices, array $candidateDevices, string $ip): array
{
    $candidateByIp = topology_index_devices_by_ip($candidateDevices);
    $candidate = $candidateByIp[$ip] ?? null;
    $found = false;
    $updated = [];
    $current = null;

    foreach ($currentDevices as $device) {
        if (!is_array($device) || (string) ($device['ip'] ?? '') !== $ip) {
            $updated[] = $device;
            continue;
        }

        $found = true;
        $current = $device;
        if ($candidate !== null) {
            $updated[] = $candidate;
        }
    }

    if (!$found && $candidate !== null) {
        $updated[] = $candidate;
    }

    topology_sort_devices($updated);

    return [
        'devices' => $updated,
        'current' => $current,
        'candidate' => $candidate,
    ];
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

$input = request_input();
$mode = (string) ($input['mode'] ?? 'one');
$ip = topology_normalize_ip($input['ip'] ?? '');

if (!in_array($mode, ['one', 'all'], true)) {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'invalid_mode',
            'message' => 'Sync mode must be one or all.',
        ],
    ]);
}

if ($mode === 'one' && $ip === null) {
    json_response(400, [
        'ok' => false,
        'error' => [
            'code' => 'missing_ip',
            'message' => 'Device IP is required for single-device sync.',
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

try {
    $rawData = file_get_contents($devicesFile);
    $currentDevices = $rawData === false ? null : json_decode($rawData, true);
    if (!is_array($currentDevices) || json_last_error() !== JSON_ERROR_NONE) {
        json_response(500, [
            'ok' => false,
            'error' => [
                'code' => 'devices_json_invalid',
                'message' => 'Device data file is missing or invalid.',
            ],
        ]);
    }

    $state = topology_build_refresh_state($devicesFile, $leasesFile, $nmapFile, $currentDevices);
    $diff = $state['diff'];
    if ($diff === []) {
        json_response(409, [
            'ok' => false,
            'error' => [
                'code' => 'no_changes',
                'message' => 'No topology differences are available to sync.',
            ],
        ]);
    }

    $backupName = '';
    $auditEvent = null;
    $auditEvents = [];

    if ($mode === 'one') {
        $diffItem = null;
        foreach ($diff as $item) {
            if ((string) $item['ip'] === $ip) {
                $diffItem = $item;
                break;
            }
        }

        if ($diffItem === null) {
            json_response(404, [
                'ok' => false,
                'error' => [
                    'code' => 'device_diff_not_found',
                    'message' => 'No pending topology difference exists for IP ' . $ip . '.',
                ],
            ]);
        }

        $syncResult = apply_single_sync($currentDevices, $state['candidate'], (string) $ip);
        $changes = topology_audit_changes_for_device($syncResult['current'], $syncResult['candidate']);
        if ($changes === []) {
            json_response(409, [
                'ok' => false,
                'error' => [
                    'code' => 'no_device_changes',
                    'message' => 'Selected device already matches the candidate state.',
                ],
            ]);
        }

        $backupName = backup_devices($backupDir, (string) $rawData, 'one');
        write_devices_atomically($devicesFile, $syncResult['devices']);
        $auditEvent = audit_append(
            audit_actor($currentUser),
            'topology_sync_device',
            'device',
            (string) $ip,
            $changes,
            'Device synced from latest topology imports.',
            [
                'identifierField' => 'ip',
                'backup' => $backupName,
                'changeTypes' => $diffItem['changeTypes'] ?? [],
                'manualFieldsPreserved' => TOPOLOGY_REFRESH_MANUAL_FIELDS,
                'syncManagedFields' => TOPOLOGY_REFRESH_SYNC_FIELDS,
            ]
        );
    } else {
        $candidateByIp = topology_index_devices_by_ip($state['candidate']);
        $currentByIp = topology_index_devices_by_ip($currentDevices);
        $changesByIp = [];

        foreach ($diff as $item) {
            $itemIp = (string) $item['ip'];
            $changes = topology_audit_changes_for_device($currentByIp[$itemIp] ?? null, $candidateByIp[$itemIp] ?? null);
            if ($changes !== []) {
                $changesByIp[$itemIp] = $changes;
            }
        }

        if ($changesByIp === []) {
            json_response(409, [
                'ok' => false,
                'error' => [
                    'code' => 'no_device_changes',
                    'message' => 'Saved topology already matches the candidate state.',
                ],
            ]);
        }

        $backupName = backup_devices($backupDir, (string) $rawData, 'all');
        write_devices_atomically($devicesFile, $state['candidate']);
        $auditEvent = audit_append(
            audit_actor($currentUser),
            'topology_sync_all',
            'topology',
            'devices',
            $changesByIp,
            'All pending topology import differences synced.',
            [
                'backup' => $backupName,
                'deviceCount' => count($changesByIp),
                'manualFieldsPreserved' => TOPOLOGY_REFRESH_MANUAL_FIELDS,
                'syncManagedFields' => TOPOLOGY_REFRESH_SYNC_FIELDS,
            ]
        );
    }

    $updatedDevices = topology_load_json_array($devicesFile, 'devices');
    $updatedState = topology_build_refresh_state($devicesFile, $leasesFile, $nmapFile, $updatedDevices);

    json_response(200, [
        'ok' => true,
        'mode' => $mode,
        'backup' => $backupName,
        'auditEvent' => $auditEvent,
        'auditEvents' => $auditEvents,
        'devices' => $updatedDevices,
        'refresh' => $updatedState,
    ]);
} catch (RuntimeException $error) {
    json_response(500, [
        'ok' => false,
        'error' => [
            'code' => 'topology_sync_failed',
            'message' => $error->getMessage(),
        ],
    ]);
} finally {
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
}
