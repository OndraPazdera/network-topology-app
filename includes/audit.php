<?php
declare(strict_types=1);

const AUDIT_LOG_FILE = __DIR__ . '/../data/audit.log';
const AUDIT_LOCK_FILE = __DIR__ . '/../data/audit.log.lock';
const AUDIT_USER_EVENT_TYPES = [
    'user_create',
    'user_disable',
    'user_enable',
    'user_password_reset',
    'user_force_password_change',
    'user_delete',
    'password_change_self',
    'login_success',
    'logout',
];

function audit_actor(?array $user): array
{
    return [
        'username' => isset($user['username']) ? (string) $user['username'] : 'system',
        'role' => isset($user['role']) ? (string) $user['role'] : 'system',
    ];
}

function audit_event_id(): string
{
    return 'evt_' . gmdate('YmdHis') . '_' . bin2hex(random_bytes(8));
}

function audit_append(array $actor, string $eventType, string $targetType, string $targetIdentifier, array $changes = [], string $summary = '', array $metadata = []): array
{
    $dir = dirname(AUDIT_LOG_FILE);
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }

    $entry = [
        'id' => audit_event_id(),
        'timestamp' => date(DATE_ATOM),
        'actor' => [
            'username' => isset($actor['username']) ? (string) $actor['username'] : 'system',
            'role' => isset($actor['role']) ? (string) $actor['role'] : 'system',
        ],
        'eventType' => $eventType,
        'target' => [
            'type' => $targetType,
            'identifier' => $targetIdentifier,
        ],
        'changes' => $changes,
        'summary' => $summary,
    ];

    if ($metadata !== []) {
        $entry['metadata'] = $metadata;
    }

    $json = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('Could not encode audit event.');
    }

    $lock = fopen(AUDIT_LOCK_FILE, 'c');
    if ($lock === false) {
        throw new RuntimeException('Could not open audit lock file.');
    }

    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Could not lock audit file.');
        }
        if (file_put_contents(AUDIT_LOG_FILE, $json . PHP_EOL, FILE_APPEND | LOCK_EX) === false) {
            throw new RuntimeException('Could not write audit event.');
        }
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }

    return $entry;
}

function audit_read_events(array $filters = [], int $limit = 50): array
{
    if (!is_file(AUDIT_LOG_FILE)) {
        return [];
    }

    $lines = file(AUDIT_LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return [];
    }

    $events = [];
    for ($index = count($lines) - 1; $index >= 0 && count($events) < $limit; $index--) {
        $entry = json_decode($lines[$index], true);
        if (!is_array($entry) || !audit_event_matches($entry, $filters)) {
            continue;
        }
        $events[] = $entry;
    }

    return $events;
}

function audit_find_event(string $eventId): ?array
{
    if (!is_file(AUDIT_LOG_FILE)) {
        return null;
    }

    $lines = file(AUDIT_LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return null;
    }

    for ($index = count($lines) - 1; $index >= 0; $index--) {
        $entry = json_decode($lines[$index], true);
        if (is_array($entry) && (string) ($entry['id'] ?? '') === $eventId) {
            return $entry;
        }
    }

    return null;
}

function audit_event_matches(array $entry, array $filters): bool
{
    if (isset($filters['targetType']) && (string) ($entry['target']['type'] ?? '') !== (string) $filters['targetType']) {
        return false;
    }
    if (isset($filters['targetIdentifier']) && (string) ($entry['target']['identifier'] ?? '') !== (string) $filters['targetIdentifier']) {
        return false;
    }
    if (isset($filters['eventTypes']) && is_array($filters['eventTypes']) && !in_array((string) ($entry['eventType'] ?? ''), $filters['eventTypes'], true)) {
        return false;
    }

    return true;
}

function audit_changed_fields(array $before, array $after, array $fields): array
{
    $changes = [];
    foreach ($fields as $field) {
        $oldValue = array_key_exists($field, $before) ? $before[$field] : null;
        $newValue = array_key_exists($field, $after) ? $after[$field] : null;
        if ($oldValue === $newValue) {
            continue;
        }
        $changes[$field] = [
            'old' => $oldValue,
            'new' => $newValue,
        ];
    }

    return $changes;
}
