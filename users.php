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
            auth_create_user(
                (string) ($_POST['username'] ?? ''),
                (string) ($_POST['password'] ?? ''),
                (string) ($_POST['role'] ?? 'viewer'),
                !empty($_POST['must_change_password'])
            );
            $success = 'User created.';
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
        <div class="table-wrap"><table><thead><tr><th>Username</th><th>Role</th><th>Must change password</th></tr></thead><tbody>
        <?php foreach ($users as $user): ?>
          <tr><td class="td-name"><?= htmlspecialchars((string) $user['username'], ENT_QUOTES, 'UTF-8') ?></td><td><?= htmlspecialchars((string) $user['role'], ENT_QUOTES, 'UTF-8') ?></td><td><?= !empty($user['mustChangePassword']) ? 'yes' : 'no' ?></td></tr>
        <?php endforeach; ?>
        </tbody></table></div>
      </section>
    </div>
  </main>
</body>
</html>