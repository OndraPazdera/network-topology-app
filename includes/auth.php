<?php
declare(strict_types=1);

const AUTH_ROLES = ['viewer', 'editor', 'admin'];
const AUTH_USERS_FILE = __DIR__ . '/../data/users.json';
const AUTH_USERS_LOCK = __DIR__ . '/../data/users.json.lock';
const AUTH_IDLE_TIMEOUT_SECONDS = 1800;

function auth_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_only_cookies', '1');
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
                'role' => 'admin',
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
            'role' => 'admin',
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
    if (empty($_SESSION['username'])) {
        return null;
    }

    $now = time();
    $lastSeen = isset($_SESSION['lastSeen']) ? (int) $_SESSION['lastSeen'] : $now;
    if ($now - $lastSeen > AUTH_IDLE_TIMEOUT_SECONDS) {
        auth_logout();
        return null;
    }

    $user = auth_find_user((string) $_SESSION['username']);
    if ($user === null) {
        auth_logout();
        return null;
    }

    $_SESSION['lastSeen'] = $now;
    return $user;
}

function auth_login(string $username, string $password): bool
{
    auth_start_session();
    $user = auth_find_user($username);
    if ($user === null || !isset($user['passwordHash']) || !password_verify($password, (string) $user['passwordHash'])) {
        return false;
    }

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
        header('Location: login.php');
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
        auth_json_response(401, [
            'ok' => false,
            'error' => [
                'code' => 'not_authenticated',
                'message' => 'Login is required or the session has expired.',
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

function auth_update_password(string $username, string $newPassword): void
{
    $users = auth_read_users();
    foreach ($users as &$user) {
        if (strtolower((string) $user['username']) === strtolower($username)) {
            $user['passwordHash'] = password_hash($newPassword, PASSWORD_DEFAULT);
            $user['mustChangePassword'] = false;
            $user['updatedAt'] = date(DATE_ATOM);
            auth_write_users($users);
            return;
        }
    }

    throw new RuntimeException('User not found.');
}

function auth_create_user(string $username, string $password, string $role, bool $mustChangePassword): void
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
        'role' => $role,
        'mustChangePassword' => $mustChangePassword,
        'createdAt' => date(DATE_ATOM),
        'updatedAt' => date(DATE_ATOM),
    ];
    auth_write_users($users);
}

auth_bootstrap_users();