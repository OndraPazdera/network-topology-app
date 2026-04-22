<?php
declare(strict_types=1);
require_once __DIR__ . '/audit.php';

const AUTH_ROLES = ['viewer', 'editor', 'admin'];
const AUTH_USERS_FILE = __DIR__ . '/../data/users.json';
const AUTH_USERS_LOCK = __DIR__ . '/../data/users.json.lock';
const AUTH_IDLE_TIMEOUT_SECONDS = 300;
const AUTH_PASSWORD_HISTORY_LIMIT = 3;
$GLOBALS['auth_session_expired'] = false;

function auth_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_lifetime', '0');
    ini_set('session.gc_maxlifetime', (string) AUTH_IDLE_TIMEOUT_SECONDS);
    session_set_cookie_params([
        'lifetime' => 0,
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    ]);
    session_start();
}

function auth_json_response(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function auth_csrf_token(): string
{
    auth_start_session();
    if (empty($_SESSION['csrfToken']) || !is_string($_SESSION['csrfToken'])) {
        $_SESSION['csrfToken'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrfToken'];
}

function auth_csrf_input(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(auth_csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

function auth_validate_csrf(?string $token): bool
{
    auth_start_session();
    return is_string($token)
        && $token !== ''
        && isset($_SESSION['csrfToken'])
        && is_string($_SESSION['csrfToken'])
        && hash_equals($_SESSION['csrfToken'], $token);
}

function auth_csrf_error_message(): string
{
    return 'Security token is missing or expired. Refresh the page and try again.';
}

function auth_require_csrf_post(): ?string
{
    $token = isset($_POST['csrf_token']) ? (string) $_POST['csrf_token'] : '';
    return auth_validate_csrf($token) ? null : auth_csrf_error_message();
}

function auth_require_csrf_json(): void
{
    $token = isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? (string) $_SERVER['HTTP_X_CSRF_TOKEN'] : '';
    if (auth_validate_csrf($token)) {
        return;
    }

    auth_json_response(403, [
        'ok' => false,
        'error' => [
            'code' => 'csrf_failed',
            'message' => auth_csrf_error_message(),
        ],
    ]);
}

function auth_bootstrap_users(): void
{
    $dir = dirname(AUTH_USERS_FILE);
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }

    if (!is_file(AUTH_USERS_FILE)) {
        auth_write_users([
            [
                'username' => 'admin',
                'passwordHash' => password_hash('admin', PASSWORD_DEFAULT),
                'passwordHistory' => [],
                'role' => 'admin',
                'disabled' => false,
                'mustChangePassword' => true,
                'createdAt' => date(DATE_ATOM),
                'updatedAt' => date(DATE_ATOM),
            ],
        ]);
        return;
    }

    $raw = file_get_contents(AUTH_USERS_FILE);
    $users = $raw === false ? [] : json_decode($raw, true);
    if (!is_array($users)) {
        return;
    }

    $changed = false;
    $hasAdmin = false;
    foreach ($users as &$user) {
        if (!isset($user['passwordHistory']) || !is_array($user['passwordHistory'])) {
            $user['passwordHistory'] = [];
            $changed = true;
        }
        $filteredHistory = array_values(array_filter($user['passwordHistory'], 'is_string'));
        if ($filteredHistory !== $user['passwordHistory'] || count($filteredHistory) > AUTH_PASSWORD_HISTORY_LIMIT) {
            $user['passwordHistory'] = array_slice($filteredHistory, 0, AUTH_PASSWORD_HISTORY_LIMIT);
            $changed = true;
        }
        if (!array_key_exists('disabled', $user)) {
            $user['disabled'] = false;
            $changed = true;
        }

        if (($user['username'] ?? '') !== 'admin') {
            continue;
        }

        $hasAdmin = true;
        $user['role'] = 'admin';
        if (isset($user['passwordHash']) && password_verify('admin', (string) $user['passwordHash']) && empty($user['mustChangePassword'])) {
            $user['mustChangePassword'] = true;
            $user['updatedAt'] = date(DATE_ATOM);
            $changed = true;
        }
    }
    unset($user);

    if (!$hasAdmin) {
        $users[] = [
            'username' => 'admin',
            'passwordHash' => password_hash('admin', PASSWORD_DEFAULT),
            'passwordHistory' => [],
            'role' => 'admin',
            'disabled' => false,
            'mustChangePassword' => true,
            'createdAt' => date(DATE_ATOM),
            'updatedAt' => date(DATE_ATOM),
        ];
        $changed = true;
    }

    if ($changed) {
        auth_write_users($users);
    }
}

function auth_read_users(): array
{
    auth_bootstrap_users();
    $raw = file_get_contents(AUTH_USERS_FILE);
    if ($raw === false) {
        return [];
    }

    $users = json_decode($raw, true);
    return is_array($users) ? $users : [];
}

function auth_write_users(array $users): void
{
    $json = json_encode($users, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if ($json === false) {
        throw new RuntimeException('Could not encode users JSON.');
    }

    $lock = fopen(AUTH_USERS_LOCK, 'c');
    if ($lock === false) {
        throw new RuntimeException('Could not open users lock file.');
    }

    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Could not lock users file.');
        }

        $tmp = tempnam(dirname(AUTH_USERS_FILE), 'users.tmp.');
        if ($tmp === false) {
            throw new RuntimeException('Could not create users temp file.');
        }

        if (file_put_contents($tmp, $json . PHP_EOL, LOCK_EX) === false) {
            @unlink($tmp);
            throw new RuntimeException('Could not write users temp file.');
        }

        if (!rename($tmp, AUTH_USERS_FILE)) {
            @unlink($tmp);
            throw new RuntimeException('Could not replace users file.');
        }
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function auth_find_user(string $username): ?array
{
    foreach (auth_read_users() as $user) {
        if (isset($user['username']) && strtolower((string) $user['username']) === strtolower($username)) {
            return $user;
        }
    }

    return null;
}

function auth_current_user(): ?array
{
    auth_start_session();
    $GLOBALS['auth_session_expired'] = false;
    if (empty($_SESSION['username'])) {
        return null;
    }

    $now = time();
    if (!isset($_SESSION['lastSeen'])) {
        $GLOBALS['auth_session_expired'] = true;
        auth_logout();
        return null;
    }

    $lastSeen = (int) $_SESSION['lastSeen'];
    if ($now - $lastSeen > AUTH_IDLE_TIMEOUT_SECONDS) {
        $GLOBALS['auth_session_expired'] = true;
        auth_logout();
        return null;
    }

    $user = auth_find_user((string) $_SESSION['username']);
    if ($user === null) {
        auth_logout();
        return null;
    }

    if (!empty($user['disabled'])) {
        auth_logout();
        return null;
    }

    $_SESSION['lastSeen'] = $now;
    return $user;
}

function auth_session_was_expired(): bool
{
    return !empty($GLOBALS['auth_session_expired']);
}

function auth_login(string $username, string $password): bool
{
    auth_start_session();
    $user = auth_find_user($username);
    if ($user === null || !isset($user['passwordHash']) || !empty($user['disabled']) || !password_verify($password, (string) $user['passwordHash'])) {
        return false;
    }

    audit_append(
        audit_actor($user),
        'login_success',
        'user',
        (string) $user['username'],
        [],
        'User logged in.'
    );
    session_regenerate_id(true);
    $_SESSION['username'] = $user['username'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['lastSeen'] = time();
    return true;
}

function auth_logout(): void
{
    auth_start_session();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'] ?? '/',
            'domain' => $params['domain'] ?? '',
            'secure' => (bool) ($params['secure'] ?? false),
            'httponly' => (bool) ($params['httponly'] ?? true),
            'samesite' => $params['samesite'] ?? 'Lax',
        ]);
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

function auth_require_page(bool $allowPasswordChange = false): array
{
    $user = auth_current_user();
    if ($user === null) {
        header('Location: login.php' . (auth_session_was_expired() ? '?expired=1' : ''));
        exit;
    }

    if (!$allowPasswordChange && !empty($user['mustChangePassword'])) {
        header('Location: change-password.php');
        exit;
    }

    return $user;
}

function auth_require_role_page(array $roles): array
{
    $user = auth_require_page();
    if (!in_array($user['role'], $roles, true)) {
        http_response_code(403);
        echo 'Forbidden';
        exit;
    }

    return $user;
}

function auth_require_json(array $roles, bool $allowPasswordChange = false): array
{
    $user = auth_current_user();
    if ($user === null) {
        $expired = auth_session_was_expired();
        auth_json_response(401, [
            'ok' => false,
            'error' => [
                'code' => $expired ? 'session_expired' : 'not_authenticated',
                'message' => $expired ? 'Session expired after 5 minutes of inactivity.' : 'Login is required.',
            ],
        ]);
    }

    if (!$allowPasswordChange && !empty($user['mustChangePassword'])) {
        auth_json_response(403, [
            'ok' => false,
            'error' => [
                'code' => 'password_change_required',
                'message' => 'Password change is required before using the app.',
            ],
        ]);
    }

    if (!in_array($user['role'], $roles, true)) {
        auth_json_response(403, [
            'ok' => false,
            'error' => [
                'code' => 'forbidden',
                'message' => 'Your role is not allowed to perform this action.',
            ],
        ]);
    }

    return $user;
}

function auth_password_policy_error(string $password): ?string
{
    if (strlen($password) < 12) {
        return 'Password must be at least 12 characters long.';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        return 'Password must include at least one uppercase letter.';
    }
    if (!preg_match('/[a-z]/', $password)) {
        return 'Password must include at least one lowercase letter.';
    }
    if (!preg_match('/[0-9]/', $password)) {
        return 'Password must include at least one number.';
    }

    return null;
}

function auth_password_reuse_error(array $user, string $newPassword): ?string
{
    if (isset($user['passwordHash']) && password_verify($newPassword, (string) $user['passwordHash'])) {
        return 'New password must be different from the current password.';
    }

    $history = isset($user['passwordHistory']) && is_array($user['passwordHistory']) ? $user['passwordHistory'] : [];
    foreach ($history as $hash) {
        if (is_string($hash) && password_verify($newPassword, $hash)) {
            return 'New password cannot reuse any of the last 3 previous passwords.';
        }
    }

    return null;
}

function auth_update_password(string $username, string $newPassword, ?array $actor = null, ?string $eventType = null): void
{
    $users = auth_read_users();
    foreach ($users as &$user) {
        if (strtolower((string) $user['username']) === strtolower($username)) {
            $policyError = auth_password_policy_error($newPassword);
            if ($policyError !== null) {
                throw new InvalidArgumentException($policyError);
            }

            $reuseError = auth_password_reuse_error($user, $newPassword);
            if ($reuseError !== null) {
                throw new InvalidArgumentException($reuseError);
            }

            $history = isset($user['passwordHistory']) && is_array($user['passwordHistory']) ? $user['passwordHistory'] : [];
            if (isset($user['passwordHash']) && is_string($user['passwordHash'])) {
                array_unshift($history, $user['passwordHash']);
            }
            $user['passwordHash'] = password_hash($newPassword, PASSWORD_DEFAULT);
            $user['passwordHistory'] = array_slice(array_values(array_filter($history, 'is_string')), 0, AUTH_PASSWORD_HISTORY_LIMIT);
            $user['mustChangePassword'] = false;
            $user['updatedAt'] = date(DATE_ATOM);
            auth_write_users($users);
            if ($actor !== null && $eventType !== null) {
                audit_append(
                    audit_actor($actor),
                    $eventType,
                    'user',
                    (string) $user['username'],
                    [],
                    $eventType === 'password_change_self' ? 'User changed own password.' : 'Password was changed.'
                );
            }
            return;
        }
    }

    throw new RuntimeException('User not found.');
}

function auth_create_user(string $username, string $password, string $role, bool $mustChangePassword, ?array $actor = null): void
{
    $username = trim($username);
    if (!preg_match('/^[A-Za-z0-9._-]{3,64}$/', $username)) {
        throw new InvalidArgumentException('Username must be 3-64 characters and may contain letters, numbers, dot, underscore, or dash.');
    }
    if (!in_array($role, AUTH_ROLES, true)) {
        throw new InvalidArgumentException('Invalid role.');
    }
    if (auth_find_user($username) !== null) {
        throw new InvalidArgumentException('Username already exists.');
    }

    $policyError = auth_password_policy_error($password);
    if ($policyError !== null) {
        throw new InvalidArgumentException($policyError);
    }

    $users = auth_read_users();
    $users[] = [
        'username' => $username,
        'passwordHash' => password_hash($password, PASSWORD_DEFAULT),
        'passwordHistory' => [],
        'role' => $role,
        'disabled' => false,
        'mustChangePassword' => $mustChangePassword,
        'createdAt' => date(DATE_ATOM),
        'updatedAt' => date(DATE_ATOM),
    ];
    auth_write_users($users);
    if ($actor !== null) {
        audit_append(
            audit_actor($actor),
            'user_create',
            'user',
            $username,
            [
                'role' => ['old' => null, 'new' => $role],
                'disabled' => ['old' => null, 'new' => false],
                'mustChangePassword' => ['old' => null, 'new' => $mustChangePassword],
            ],
            'User account created.'
        );
    }
}

function auth_enabled_admin_count(array $users, ?string $excludingUsername = null): int
{
    $count = 0;
    foreach ($users as $user) {
        if ($excludingUsername !== null && strtolower((string) ($user['username'] ?? '')) === strtolower($excludingUsername)) {
            continue;
        }
        if (($user['role'] ?? '') === 'admin' && empty($user['disabled'])) {
            $count++;
        }
    }

    return $count;
}

function auth_admin_count(array $users, ?string $excludingUsername = null): int
{
    $count = 0;
    foreach ($users as $user) {
        if ($excludingUsername !== null && strtolower((string) ($user['username'] ?? '')) === strtolower($excludingUsername)) {
            continue;
        }
        if (($user['role'] ?? '') === 'admin') {
            $count++;
        }
    }

    return $count;
}

function auth_set_user_disabled(string $targetUsername, bool $disabled, string $actingUsername, ?array $actor = null): void
{
    $users = auth_read_users();
    foreach ($users as &$user) {
        if (strtolower((string) ($user['username'] ?? '')) !== strtolower($targetUsername)) {
            continue;
        }

        if ($disabled && strtolower((string) $user['username']) === strtolower($actingUsername)) {
            throw new InvalidArgumentException('You cannot disable your own active account.');
        }
        if ($disabled && ($user['role'] ?? '') === 'admin' && auth_enabled_admin_count($users, (string) $user['username']) < 1) {
            throw new InvalidArgumentException('Cannot disable the last enabled admin account.');
        }

        $oldDisabled = !empty($user['disabled']);
        $user['disabled'] = $disabled;
        $user['updatedAt'] = date(DATE_ATOM);
        auth_write_users($users);
        if ($actor !== null && $oldDisabled !== $disabled) {
            audit_append(
                audit_actor($actor),
                $disabled ? 'user_disable' : 'user_enable',
                'user',
                (string) $user['username'],
                ['disabled' => ['old' => $oldDisabled, 'new' => $disabled]],
                $disabled ? 'User account disabled.' : 'User account enabled.'
            );
        }
        return;
    }

    throw new RuntimeException('User not found.');
}

function auth_delete_user(string $targetUsername, string $actingUsername, ?array $actor = null): void
{
    $users = auth_read_users();
    foreach ($users as $index => $user) {
        if (strtolower((string) ($user['username'] ?? '')) !== strtolower($targetUsername)) {
            continue;
        }

        if (strtolower((string) $user['username']) === strtolower($actingUsername)) {
            throw new InvalidArgumentException('You cannot delete your own active account.');
        }
        if (empty($user['disabled'])) {
            throw new InvalidArgumentException('User must be disabled before deletion.');
        }
        if (($user['role'] ?? '') === 'admin' && auth_admin_count($users, (string) $user['username']) < 1) {
            throw new InvalidArgumentException('Cannot delete the last remaining admin account.');
        }

        $deletedUsername = (string) $user['username'];
        $deletedRole = (string) ($user['role'] ?? '');
        array_splice($users, $index, 1);
        auth_write_users($users);
        if ($actor !== null) {
            audit_append(
                audit_actor($actor),
                'user_delete',
                'user',
                $deletedUsername,
                [
                    'exists' => ['old' => true, 'new' => false],
                    'role' => ['old' => $deletedRole, 'new' => null],
                ],
                'Disabled user account deleted.'
            );
        }
        return;
    }

    throw new RuntimeException('User not found.');
}

function auth_force_password_change(string $targetUsername, ?array $actor = null): void
{
    $users = auth_read_users();
    foreach ($users as &$user) {
        if (strtolower((string) ($user['username'] ?? '')) !== strtolower($targetUsername)) {
            continue;
        }
        if (($user['role'] ?? '') === 'admin') {
            throw new InvalidArgumentException('Force password change is only available for non-admin users.');
        }

        $oldMustChange = !empty($user['mustChangePassword']);
        $user['mustChangePassword'] = true;
        $user['updatedAt'] = date(DATE_ATOM);
        auth_write_users($users);
        if ($actor !== null && !$oldMustChange) {
            audit_append(
                audit_actor($actor),
                'user_force_password_change',
                'user',
                (string) $user['username'],
                ['mustChangePassword' => ['old' => false, 'new' => true]],
                'User marked for password change on next login.'
            );
        }
        return;
    }

    throw new RuntimeException('User not found.');
}

function auth_admin_reset_password(string $targetUsername, string $newPassword, ?array $actor = null): void
{
    $before = auth_find_user($targetUsername);
    if ($before === null) {
        throw new RuntimeException('User not found.');
    }
    if (($before['role'] ?? '') === 'admin' && empty($before['disabled'])) {
        throw new InvalidArgumentException('Active admin accounts cannot be reset by another admin. Disable the target admin first, then reset the password for recovery.');
    }

    auth_update_password($targetUsername, $newPassword);

    $users = auth_read_users();
    foreach ($users as &$user) {
        if (strtolower((string) ($user['username'] ?? '')) === strtolower($targetUsername)) {
            $oldMustChange = $before !== null ? !empty($before['mustChangePassword']) : null;
            $user['mustChangePassword'] = true;
            $user['updatedAt'] = date(DATE_ATOM);
            auth_write_users($users);
            if ($actor !== null) {
                $changes = [];
                if ($oldMustChange !== true) {
                    $changes['mustChangePassword'] = ['old' => $oldMustChange, 'new' => true];
                }
                audit_append(
                    audit_actor($actor),
                    'user_password_reset',
                    'user',
                    (string) $user['username'],
                    $changes,
                    'Admin reset user password. Plaintext password was not recorded.'
                );
            }
            return;
        }
    }
}

auth_bootstrap_users();
