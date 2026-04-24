<?php
declare(strict_types=1);

const TOPOLOGY_REFRESH_MANUAL_FIELDS = ['hostname', 'comment', 'type', 'vendor', 'warn'];
const TOPOLOGY_REFRESH_SYNC_FIELDS = ['mac', 'online', 'rtt'];

function topology_load_json_array(string $file, string $label): array
{
    if (!is_file($file)) {
        throw new RuntimeException(ucfirst($label) . ' file is missing.');
    }

    $raw = file_get_contents($file);
    if ($raw === false) {
        throw new RuntimeException(ucfirst($label) . ' file cannot be read.');
    }

    $data = json_decode($raw, true);
    if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
        throw new RuntimeException(ucfirst($label) . ' file contains invalid JSON: ' . json_last_error_msg());
    }

    return $data;
}

function topology_normalize_ip(mixed $value): ?string
{
    $ip = trim((string) $value);
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? $ip : null;
}

function topology_normalize_mac(mixed $value): string
{
    $mac = strtoupper(trim((string) $value));
    $mac = str_replace(['-', '.'], ':', $mac);
    return preg_replace('/[^0-9A-F:]/', '', $mac) ?? '';
}

function topology_index_devices_by_ip(array $devices): array
{
    $indexed = [];
    foreach ($devices as $device) {
        if (!is_array($device)) {
            continue;
        }

        $ip = topology_normalize_ip($device['ip'] ?? '');
        if ($ip !== null) {
            $indexed[$ip] = $device;
        }
    }

    return $indexed;
}

function topology_ip_to_number(string $ip): int
{
    $parts = array_map('intval', explode('.', $ip));
    return ($parts[0] * 16777216) + ($parts[1] * 65536) + ($parts[2] * 256) + $parts[3];
}

function topology_sort_devices(array &$devices): void
{
    usort($devices, static function (array $left, array $right): int {
        return topology_ip_to_number((string) $left['ip']) <=> topology_ip_to_number((string) $right['ip']);
    });
}

function topology_load_enabled_leases(array $leases): array
{
    $indexed = [];
    foreach ($leases as $lease) {
        if (!is_array($lease) || !empty($lease['disabled'])) {
            continue;
        }

        $ip = topology_normalize_ip($lease['ip'] ?? '');
        if ($ip === null) {
            continue;
        }

        $indexed[$ip] = [
            'ip' => $ip,
            'mac' => topology_normalize_mac($lease['mac'] ?? ''),
            'comment' => isset($lease['comment']) ? trim((string) $lease['comment']) : '',
        ];
    }

    return $indexed;
}

function topology_load_nmap_hosts(string $file): array
{
    if (!is_file($file)) {
        throw new RuntimeException('Nmap scan file is missing.');
    }

    $xml = @simplexml_load_file($file);
    if ($xml === false) {
        throw new RuntimeException('Nmap scan file contains invalid XML.');
    }

    $hosts = [];
    foreach ($xml->host as $host) {
        $ip = null;
        $mac = '';
        foreach ($host->address as $address) {
            $attrs = $address->attributes();
            $type = (string) ($attrs['addrtype'] ?? '');
            $addr = (string) ($attrs['addr'] ?? '');
            if ($type === 'ipv4') {
                $ip = topology_normalize_ip($addr);
            } elseif ($type === 'mac') {
                $mac = topology_normalize_mac($addr);
            }
        }

        if ($ip === null) {
            continue;
        }

        $statusAttrs = $host->status->attributes();
        $state = (string) ($statusAttrs['state'] ?? '');
        $hostname = '';
        foreach ($host->hostnames->hostname as $name) {
            $hostname = trim((string) ($name->attributes()['name'] ?? ''));
            if ($hostname !== '') {
                break;
            }
        }

        $rtt = null;
        if (isset($host->times)) {
            $timeAttrs = $host->times->attributes();
            if (isset($timeAttrs['srtt']) && is_numeric((string) $timeAttrs['srtt'])) {
                $rtt = round(((float) $timeAttrs['srtt']) / 1000, 2);
            }
        }

        $hosts[$ip] = [
            'ip' => $ip,
            'online' => $state === 'up',
            'rtt' => $rtt,
            'mac' => $mac,
            'hostname' => $hostname,
        ];
    }

    return $hosts;
}

function topology_default_hostname(string $ip, ?array $lease, ?array $nmap): string
{
    if ($nmap !== null && $nmap['hostname'] !== '') {
        return (string) $nmap['hostname'];
    }

    if ($lease !== null && $lease['comment'] !== '') {
        $firstToken = preg_split('/\s+/', (string) $lease['comment']);
        if (is_array($firstToken) && isset($firstToken[0]) && trim($firstToken[0]) !== '') {
            return trim($firstToken[0]);
        }
    }

    return '?' . $ip;
}

function topology_build_candidate_device(string $ip, ?array $current, ?array $lease, ?array $nmap): array
{
    $sourceMac = '';
    if ($lease !== null && $lease['mac'] !== '') {
        $sourceMac = (string) $lease['mac'];
    } elseif ($nmap !== null && $nmap['mac'] !== '') {
        $sourceMac = (string) $nmap['mac'];
    }

    if ($current !== null) {
        $candidate = $current;
        $candidate['ip'] = $ip;
        if ($sourceMac !== '') {
            $candidate['mac'] = $sourceMac;
        }
        $candidate['online'] = $nmap !== null ? (bool) $nmap['online'] : false;
        $candidate['rtt'] = $nmap !== null ? $nmap['rtt'] : null;

        foreach (TOPOLOGY_REFRESH_MANUAL_FIELDS as $field) {
            if (array_key_exists($field, $current)) {
                $candidate[$field] = $current[$field];
            }
        }

        return $candidate;
    }

    return [
        'ip' => $ip,
        'mac' => $sourceMac,
        'hostname' => topology_default_hostname($ip, $lease, $nmap),
        'type' => 'pc',
        'vendor' => '',
        'comment' => $lease !== null ? (string) $lease['comment'] : '',
        'rtt' => $nmap !== null ? $nmap['rtt'] : null,
        'online' => $nmap !== null ? (bool) $nmap['online'] : false,
        'warn' => '',
    ];
}

function topology_changed_value(mixed $from, mixed $to): array
{
    return [
        'from' => $from,
        'to' => $to,
    ];
}

function topology_build_diff(array $currentDevices, array $candidateDevices, array $sourcesByIp): array
{
    $currentByIp = topology_index_devices_by_ip($currentDevices);
    $candidateByIp = topology_index_devices_by_ip($candidateDevices);
    $allIps = array_unique(array_merge(array_keys($currentByIp), array_keys($candidateByIp)));
    usort($allIps, static fn(string $left, string $right): int => topology_ip_to_number($left) <=> topology_ip_to_number($right));

    $diff = [];
    foreach ($allIps as $ip) {
        $current = $currentByIp[$ip] ?? null;
        $candidate = $candidateByIp[$ip] ?? null;
        $changeTypes = [];
        $changes = [];

        if ($current === null && $candidate !== null) {
            $changeTypes[] = 'new_device';
        } elseif ($current !== null && $candidate === null) {
            $changeTypes[] = 'missing_device';
        } elseif ($current !== null && $candidate !== null) {
            $currentOnline = (bool) ($current['online'] ?? false);
            $candidateOnline = (bool) ($candidate['online'] ?? false);
            if ($currentOnline !== $candidateOnline) {
                $changeTypes[] = 'changed_status';
                $changes['online'] = topology_changed_value($currentOnline, $candidateOnline);
            }

            $sourceMac = (string) ($sourcesByIp[$ip]['sourceMac'] ?? '');
            if ($sourceMac !== '' && topology_normalize_mac($current['mac'] ?? '') !== topology_normalize_mac($candidate['mac'] ?? '')) {
                $changeTypes[] = 'changed_mac';
                $changes['mac'] = topology_changed_value($current['mac'] ?? null, $candidate['mac'] ?? null);
                $changes['mac']['source'] = $sourcesByIp[$ip]['macSource'] ?? null;
            }

            if (($sourcesByIp[$ip]['hasRtt'] ?? false) === true) {
                $currentRtt = isset($current['rtt']) && is_numeric($current['rtt']) ? round((float) $current['rtt'], 2) : null;
                $candidateRtt = isset($candidate['rtt']) && is_numeric($candidate['rtt']) ? round((float) $candidate['rtt'], 2) : null;
                if ($currentRtt !== $candidateRtt) {
                    $changeTypes[] = 'changed_rtt';
                    $changes['rtt'] = topology_changed_value($current['rtt'] ?? null, $candidate['rtt'] ?? null);
                }
            }
        }

        if ($changeTypes === []) {
            continue;
        }

        $diff[] = [
            'ip' => $ip,
            'changeTypes' => $changeTypes,
            'changes' => $changes,
            'current' => $current,
            'candidate' => $candidate,
            'sources' => $sourcesByIp[$ip]['sources'] ?? [],
        ];
    }

    return $diff;
}

function topology_build_refresh_state(string $devicesFile, string $leasesFile, string $nmapFile, ?array $currentDevices = null): array
{
    $currentDevices ??= topology_load_json_array($devicesFile, 'devices');
    $leasesByIp = topology_load_enabled_leases(topology_load_json_array($leasesFile, 'mikrotik_leases'));
    $nmapByIp = topology_load_nmap_hosts($nmapFile);
    $sourceIps = array_unique(array_merge(array_keys($leasesByIp), array_keys($nmapByIp)));
    usort($sourceIps, static fn(string $left, string $right): int => topology_ip_to_number($left) <=> topology_ip_to_number($right));

    $currentByIp = topology_index_devices_by_ip($currentDevices);
    $candidateDevices = [];
    $sourcesByIp = [];

    foreach ($sourceIps as $ip) {
        $lease = $leasesByIp[$ip] ?? null;
        $nmap = $nmapByIp[$ip] ?? null;
        $candidateDevices[] = topology_build_candidate_device($ip, $currentByIp[$ip] ?? null, $lease, $nmap);

        $sourceMac = '';
        $macSource = null;
        if ($lease !== null && $lease['mac'] !== '') {
            $sourceMac = (string) $lease['mac'];
            $macSource = 'mikrotik';
        } elseif ($nmap !== null && $nmap['mac'] !== '') {
            $sourceMac = (string) $nmap['mac'];
            $macSource = 'nmap';
        }

        $sourcesByIp[$ip] = [
            'sources' => array_values(array_filter([
                $lease !== null ? 'mikrotik' : null,
                $nmap !== null ? 'nmap' : null,
            ])),
            'sourceMac' => $sourceMac,
            'macSource' => $macSource,
            'hasRtt' => $nmap !== null && $nmap['rtt'] !== null,
        ];
    }

    topology_sort_devices($candidateDevices);

    return [
        'current' => $currentDevices,
        'candidate' => $candidateDevices,
        'diff' => topology_build_diff($currentDevices, $candidateDevices, $sourcesByIp),
        'meta' => [
            'generatedAt' => date(DATE_ATOM),
            'currentCount' => count($currentDevices),
            'candidateCount' => count($candidateDevices),
            'leaseCount' => count($leasesByIp),
            'nmapHostCount' => count($nmapByIp),
            'manualFieldsPreserved' => TOPOLOGY_REFRESH_MANUAL_FIELDS,
            'syncManagedFields' => TOPOLOGY_REFRESH_SYNC_FIELDS,
        ],
    ];
}

function topology_audit_changes_for_device(?array $current, ?array $candidate): array
{
    if ($current === null && $candidate !== null) {
        return [
            'exists' => ['old' => false, 'new' => true],
            'device' => ['old' => null, 'new' => $candidate],
        ];
    }

    if ($current !== null && $candidate === null) {
        return [
            'exists' => ['old' => true, 'new' => false],
            'device' => ['old' => $current, 'new' => null],
        ];
    }

    if ($current === null || $candidate === null) {
        return [];
    }

    $changes = [];
    foreach (TOPOLOGY_REFRESH_SYNC_FIELDS as $field) {
        $oldValue = array_key_exists($field, $current) ? $current[$field] : null;
        $newValue = array_key_exists($field, $candidate) ? $candidate[$field] : null;
        if ($oldValue !== $newValue) {
            $changes[$field] = [
                'old' => $oldValue,
                'new' => $newValue,
            ];
        }
    }

    return $changes;
}
