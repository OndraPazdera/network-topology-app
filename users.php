<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
$currentUser = auth_require_role_page(['admin']);
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfError = auth_require_csrf_post();
    if ($csrfError !== null) {
        $error = $csrfError;
    } else {
        try {
            $action = (string) ($_POST['action'] ?? 'create');
            $targetUsername = (string) ($_POST['target_username'] ?? '');

            if ($action === 'create') {
                auth_create_user(
                    (string) ($_POST['username'] ?? ''),
                    (string) ($_POST['password'] ?? ''),
                    (string) ($_POST['role'] ?? 'viewer'),
                    !empty($_POST['must_change_password']),
                    $currentUser
                );
                $success = 'User created.';
            } elseif ($action === 'disable') {
                auth_set_user_disabled($targetUsername, true, (string) $currentUser['username'], $currentUser);
                $success = 'User disabled.';
            } elseif ($action === 'enable') {
                auth_set_user_disabled($targetUsername, false, (string) $currentUser['username'], $currentUser);
                $success = 'User enabled.';
            } elseif ($action === 'delete') {
                auth_delete_user($targetUsername, (string) $currentUser['username'], $currentUser);
                $success = 'User deleted.';
            } elseif ($action === 'force_password_change') {
                auth_force_password_change($targetUsername, $currentUser);
                $success = 'User will be required to change password on next login.';
            } elseif ($action === 'reset_password') {
                auth_admin_reset_password($targetUsername, (string) ($_POST['new_password'] ?? ''), $currentUser);
                $success = 'Password reset. User must change it on next login.';
            } else {
                throw new InvalidArgumentException('Unknown user action.');
            }
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }
    }
}
$users = auth_read_users();
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Users - Topologie</title>
  <link rel="stylesheet" href="css/styles.css">
</head>
<body>
  <header>
    <div><div class="logo">SITOVA MAPA <span>// users</span></div><div class="subtitle">Admin user management</div></div>
    <div class="session-bar"><span><?= htmlspecialchars($currentUser['username'], ENT_QUOTES, 'UTF-8') ?> / admin</span><a href="index.php">App</a><a href="change-password.php">Password</a><form method="post" action="logout.php" class="logout-form"><?= auth_csrf_input() ?><button class="auth-link-button" type="submit">Logout</button></form></div>
  </header>
  <main>
    <?php if ($error !== ''): ?><div class="app-alert" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <?php if ($success !== ''): ?><div class="notice"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <div class="auth-admin-grid">
      <section>
        <div class="layer-title">Create user</div>
        <form method="post" class="edit-form auth-inline-form">
          <?= auth_csrf_input() ?>
          <input type="hidden" name="action" value="create">
          <div class="form-row"><label class="form-label" for="username">Username</label><input class="form-input" id="username" name="username" required></div>
          <div class="form-row"><label class="form-label" for="password">Initial password</label><input class="form-input" id="password" name="password" type="password" required></div>
          <div class="form-row"><label class="form-label" for="role">Role</label><select class="form-select" id="role" name="role"><option value="viewer">viewer</option><option value="editor">editor</option><option value="admin">admin</option></select></div>
          <label class="auth-checkbox"><input type="checkbox" name="must_change_password" value="1" checked> Force password change on first login</label>
          <div class="notice">Password policy: minimum 12 characters, uppercase, lowercase, and number.</div>
          <div class="form-actions"><button class="btn-save" type="submit">Create user</button></div>
        </form>
      </section>
      <section>
        <div class="layer-title">Existing users</div>
        <div class="table-wrap"><table><thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Must change password</th><th>Reset password</th><th>Actions</th></tr></thead><tbody>
        <?php foreach ($users as $user): ?>
          <?php
            $username = (string) $user['username'];
            $role = (string) $user['role'];
            $disabled = !empty($user['disabled']);
            $canResetPassword = $role !== 'admin' || $disabled;
          ?>
          <tr class="<?= $disabled ? 'user-disabled' : '' ?>">
            <td class="td-name"><?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= htmlspecialchars($role, ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= $disabled ? 'disabled' : 'enabled' ?></td>
            <td><?= !empty($user['mustChangePassword']) ? 'yes' : 'no' ?></td>
            <td>
              <?php if ($canResetPassword): ?>
                <form method="post" class="user-action-form">
                  <?= auth_csrf_input() ?>
                  <input type="hidden" name="action" value="reset_password">
                  <input type="hidden" name="target_username" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>">
                  <input class="form-input user-password-input" name="new_password" type="password" autocomplete="new-password" placeholder="New password" required>
                  <button class="edit-btn" type="submit">Reset</button>
                </form>
              <?php else: ?>
                <span class="muted">Disable admin first</span>
              <?php endif; ?>
            </td>
            <td>
              <div class="user-actions">
                <form method="post" class="logout-form">
                  <?= auth_csrf_input() ?>
                  <input type="hidden" name="action" value="<?= $disabled ? 'enable' : 'disable' ?>">
                  <input type="hidden" name="target_username" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>">
                  <button class="edit-btn" type="submit"><?= $disabled ? 'Enable' : 'Disable' ?></button>
                </form>
                <?php if ($role !== 'admin'): ?>
                  <form method="post" class="logout-form">
                    <?= auth_csrf_input() ?>
                    <input type="hidden" name="action" value="force_password_change">
                    <input type="hidden" name="target_username" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>">
                    <button class="edit-btn" type="submit">Force change</button>
                  </form>
                <?php endif; ?>
                <?php if ($disabled): ?>
                  <form method="post" class="logout-form">
                    <?= auth_csrf_input() ?>
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="target_username" value="<?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>">
                    <button class="edit-btn danger-btn" type="submit" onclick="return confirm('Delete this disabled user?')">Delete</button>
                  </form>
                <?php endif; ?>
              </div>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody></table></div>
      </section>
    </div>
    <section class="history-panel admin-history-panel">
      <div class="layer-title">Recent account history</div>
      <div id="admin-user-history" class="history-list">Loading history...</div>
    </section>
  </main>
  <script>
    window.APP_CSRF_TOKEN = <?= json_encode(auth_csrf_token(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
    window.APP_USER_HISTORY_API = 'api/user-history.php';
  </script>
  <script src="js/user-history.js"></script>
  <script src="js/session-logout.js"></script>
</body>
</html>
