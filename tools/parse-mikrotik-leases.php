<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line.\n");
    exit(1);
}

$rootDir = dirname(__DIR__);
$inputFile = $argv[1] ?? ($rootDir . '/data/imports/mikrotik-leases.raw');
$outputFile = $argv[2] ?? ($rootDir . '/data/imports/mikrotik-leases.json');

function fail(string $message, int $exitCode = 1): never
{
    fwrite(STDERR, $message . PHP_EOL);
    exit($exitCode);
}

function is_valid_utf8(string $value): bool
{
    if (function_exists('mb_check_encoding')) {
        return mb_check_encoding($value, 'UTF-8');
    }

    return preg_match('//u', $value) === 1;
}

function convert_windows_1250_to_utf8(string $value): string
{
    if (function_exists('mb_convert_encoding')) {
        foreach (['CP1250', 'Windows-1250', 'ISO-8859-2'] as $encoding) {
            try {
                return mb_convert_encoding($value, 'UTF-8', $encoding);
            } catch (ValueError) {
                continue;
            }
        }
    }

    if (function_exists('iconv')) {
        foreach (['CP1250', 'Windows-1250', 'ISO-8859-2'] as $encoding) {
            $converted = iconv($encoding, 'UTF-8//IGNORE', $value);
            if ($converted !== false) {
                return $converted;
            }
        }
    }

    return $value;
}

function decode_mikrotik_value(string $value): string
{
    $decoded = preg_replace_callback('/\\\\([0-9A-Fa-f]{2}|.)/s', static function (array $matches): string {
        $token = $matches[1];
        if (strlen($token) === 2 && ctype_xdigit($token)) {
            return chr(hexdec($token));
        }

        return match ($token) {
            '"' => '"',
            '\\' => '\\',
            'n' => "\n",
            'r' => "\r",
            't' => "\t",
            default => $token,
        };
    }, $value);

    if ($decoded === null) {
        return $value;
    }

    return is_valid_utf8($decoded) ? $decoded : convert_windows_1250_to_utf8($decoded);
}

function normalize_mac(string $value): string
{
    $mac = strtoupper(trim($value));
    $mac = str_replace(['-', '.'], ':', $mac);
    $mac = preg_replace('/[^0-9A-F:]/', '', $mac) ?? '';
    return $mac;
}

function is_valid_mac(string $value): bool
{
    return preg_match('/^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/', $value) === 1;
}

function normalize_routeros_lines(string $raw): array
{
    $sourceLines = preg_split("/\r\n|\n|\r/", $raw) ?: [];
    $lines = [];
    $buffer = '';

    foreach ($sourceLines as $line) {
        $trimmedRight = rtrim($line);
        if ($buffer !== '') {
            $buffer .= ' ' . ltrim($trimmedRight);
        } else {
            $buffer = trim($trimmedRight);
        }

        if ($buffer === '') {
            continue;
        }

        if (substr($trimmedRight, -1) === '\\') {
            $buffer = rtrim(substr($buffer, 0, -1));
            continue;
        }

        $lines[] = $buffer;
        $buffer = '';
    }

    if ($buffer !== '') {
        $lines[] = $buffer;
    }

    return $lines;
}

function parse_routeros_assignments(string $line): array
{
    $fields = [];
    preg_match_all('/([A-Za-z0-9-]+)=("([^"\\\\]|\\\\.)*"|\S+)/', $line, $matches, PREG_SET_ORDER);

    foreach ($matches as $match) {
        $key = $match[1];
        $rawValue = $match[2];
        if (str_starts_with($rawValue, '"') && str_ends_with($rawValue, '"')) {
            $rawValue = substr($rawValue, 1, -1);
        }
        $fields[$key] = decode_mikrotik_value($rawValue);
    }

    return $fields;
}

function is_routeros_lease_section_line(string $line): bool
{
    return preg_match('/^\/ip\s+dhcp-server\s+lease\s*$/i', $line) === 1;
}

function is_lease_like_line(string $line): bool
{
    return preg_match('/^add\b/i', $line) === 1
        || preg_match('/^\/ip\s+dhcp-server\s+lease\s+add\b/i', $line) === 1
        || preg_match('/dhcp-server\s+lease\s+add\b/i', $line) === 1;
}

function normalize_lease_command_line(string $line): ?string
{
    if (preg_match('/^add\b/i', $line) === 1) {
        return $line;
    }

    if (preg_match('/^\/ip\s+dhcp-server\s+lease\s+add\b(.*)$/i', $line, $matches) === 1) {
        return 'add' . $matches[1];
    }

    return null;
}

function increment_reason(array &$reasons, string $reason): void
{
    $reasons[$reason] = ($reasons[$reason] ?? 0) + 1;
}

if (!is_file($inputFile)) {
    fail('Input raw lease export file not found: ' . $inputFile);
}

$raw = file_get_contents($inputFile);
if ($raw === false) {
    fail('Input raw lease export file could not be read: ' . $inputFile);
}

$leases = [];
$skipReasons = [];
$disabledCount = 0;
$skippedCount = 0;

foreach (normalize_routeros_lines($raw) as $line) {
    $trimmed = trim($line);
    if ($trimmed === '' || str_starts_with($trimmed, '#')) {
        continue;
    }

    if (is_routeros_lease_section_line($trimmed)) {
        continue;
    }

    $leaseLike = is_lease_like_line($trimmed);
    $normalizedLine = normalize_lease_command_line($trimmed);

    if (!$leaseLike) {
        $skippedCount++;
        increment_reason($skipReasons, 'unsupported_command');
        continue;
    }

    if ($normalizedLine === null) {
        $skippedCount++;
        increment_reason($skipReasons, 'unsupported_lease_format');
        continue;
    }

    $fields = parse_routeros_assignments($normalizedLine);
    if ($fields === []) {
        $skippedCount++;
        increment_reason($skipReasons, 'unparsed_entry');
        continue;
    }

    $ip = isset($fields['address']) ? trim((string) $fields['address']) : '';
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $skippedCount++;
        increment_reason($skipReasons, 'invalid_ip');
        continue;
    }

    if (!isset($fields['mac-address']) || trim((string) $fields['mac-address']) === '') {
        $skippedCount++;
        increment_reason($skipReasons, 'missing_mac');
        continue;
    }

    $mac = normalize_mac((string) $fields['mac-address']);
    if (!is_valid_mac($mac)) {
        $skippedCount++;
        increment_reason($skipReasons, 'invalid_mac');
        continue;
    }

    $disabled = strtolower(trim((string) ($fields['disabled'] ?? 'no'))) === 'yes';
    if ($disabled) {
        $disabledCount++;
    }

    $leases[] = [
        'ip' => $ip,
        'mac' => $mac,
        'comment' => isset($fields['comment']) ? trim((string) $fields['comment']) : '',
        'disabled' => $disabled,
    ];
}

$json = json_encode($leases, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
if ($json === false) {
    fail('Parsed lease data could not be encoded to JSON.');
}
$json .= PHP_EOL;

$verified = json_decode($json, true);
if (!is_array($verified) || json_last_error() !== JSON_ERROR_NONE) {
    fail('Generated JSON failed verification.');
}

$outputDir = dirname($outputFile);
if (!is_dir($outputDir) && !mkdir($outputDir, 0775, true) && !is_dir($outputDir)) {
    fail('Output directory could not be created: ' . $outputDir);
}

$tempFile = tempnam($outputDir, 'mikrotik-leases.tmp.');
if ($tempFile === false) {
    fail('Temporary output file could not be created in: ' . $outputDir);
}

try {
    $written = file_put_contents($tempFile, $json, LOCK_EX);
    if ($written === false || $written < strlen($json)) {
        fail('Temporary output file could not be written completely.');
    }

    $verifyRaw = file_get_contents($tempFile);
    $verifyData = $verifyRaw === false ? null : json_decode($verifyRaw, true);
    if (!is_array($verifyData) || json_last_error() !== JSON_ERROR_NONE) {
        fail('Temporary output file failed JSON verification.');
    }

    if (!rename($tempFile, $outputFile)) {
        fail('Temporary output file could not replace target JSON file.');
    }
    $tempFile = null;
} finally {
    if ($tempFile !== null && is_file($tempFile)) {
        @unlink($tempFile);
    }
}

echo 'MikroTik lease export parsed successfully.' . PHP_EOL;
echo 'Input: ' . $inputFile . PHP_EOL;
echo 'Output: ' . $outputFile . PHP_EOL;
echo 'Valid parsed count: ' . count($leases) . PHP_EOL;
echo 'Disabled count: ' . $disabledCount . PHP_EOL;
echo 'Skipped count: ' . $skippedCount . PHP_EOL;
echo 'Skip reasons:' . PHP_EOL;

if ($skipReasons === []) {
    echo "  - none\n";
} else {
    ksort($skipReasons);
    foreach ($skipReasons as $reason => $count) {
        echo '  - ' . $reason . ': ' . $count . PHP_EOL;
    }
}
