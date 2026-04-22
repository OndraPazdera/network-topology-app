<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';
$user = auth_require_page(true);
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfError = auth_require_csrf_post();
    if ($csrfError !== null) {
        $error = $csrfError;
    } else {
        $current = (string) ($_POST['current_password'] ?? '');
        $new = (string) ($_POST['new_password'] ?? '');
        $confirm = (string) ($_POST['confirm_password'] ?? '');

        if (!password_verify($current, (string) $user['passwordHash'])) {
            $error = 'Current password is incorrect.';
        } elseif ($new !== $confirm) {
            $error = 'New passwords do not match.';
        } else {
            $policyError = auth_password_policy_error($new);
            if ($policyError !== null) {
                $error = $policyError;
            } else {
                try {
                    auth_update_password((string) $user['username'], $new, $user, 'password_change_self');
                    header('Location: index.php');
                    exit;
                } catch (Throwable $e) {
                    $error = $e->getMessage();
                }
            }
        }
    }
}
$mustChange = !empty($user['mustChangePassword']);
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Change Password - Topologie</title>
  <link rel="stylesheet" href="css/styles.css">
</head>
<body>
  <header>
    <div>
      <div class="logo">SITOVA MAPA <span>// change password</span></div>
      <div class="subtitle">Password policy: minimum 12 characters, uppercase, lowercase, and number.</div>
    </div>
    <div class="session-bar">
      <span><?= htmlspecialchars((string) $user['username'], ENT_QUOTES, 'UTF-8') ?> / <?= htmlspecialchars((string) $user['role'], ENT_QUOTES, 'UTF-8') ?></span>
      <?php if (!$mustChange): ?><a href="index.php">App</a><?php endif; ?>
      <?php if (!$mustChange && $user['role'] === 'admin'): ?><a href="users.php">Users</a><?php endif; ?>
      <form method="post" action="logout.php" class="logout-form"><?= auth_csrf_input() ?><button class="auth-link-button" type="submit">Logout</button></form>
    </div>
  </header>

  <main class="auth-page-main">
    <section class="auth-panel">
      <?php if ($mustChange): ?><div class="notice">You must change your temporary password before continuing.</div><?php endif; ?>
      <?php if ($error !== ''): ?><div class="app-alert" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
      <form method="post" class="edit-form">
        <?= auth_csrf_input() ?>
        <div class="form-row"><label class="form-label" for="current_password">Current password</label><input class="form-input" id="current_password" name="current_password" type="password" autocomplete="current-password" required autofocus></div>
        <div class="form-row"><label class="form-label" for="new_password">New password</label><input class="form-input" id="new_password" name="new_password" type="password" autocomplete="new-password" required></div>
        <div class="form-row"><label class="form-label" for="confirm_password">Confirm new password</label><input class="form-input" id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required></div>
        <div class="form-actions"><button class="btn-save" type="submit">Change password</button><button class="btn-cancel auth-link-button" type="submit" formaction="logout.php" formmethod="post" formnovalidate>Logout</button></div>
      </form>
    </section>
  </main>
  <script>
    window.APP_CSRF_TOKEN = <?= json_encode(auth_csrf_token(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
  </script>
  <script src="js/session-logout.js"></script>
</body>
</html>
