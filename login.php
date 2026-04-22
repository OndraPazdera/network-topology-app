<?php
declare(strict_types=1);
require_once __DIR__ . '/includes/auth.php';

$user = auth_current_user();
if ($user !== null) {
    header('Location: ' . (!empty($user['mustChangePassword']) ? 'change-password.php' : 'index.php'));
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfError = auth_require_csrf_post();
    if ($csrfError !== null) {
        $error = $csrfError;
    } else {
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        if (auth_login($username, $password)) {
            $user = auth_current_user();
            header('Location: ' . (!empty($user['mustChangePassword']) ? 'change-password.php' : 'index.php'));
            exit;
        }
        $error = 'Invalid username or password.';
    }
}
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - Topologie</title>
  <link rel="stylesheet" href="css/styles.css">
</head>
<body class="auth-page">
  <main class="auth-panel">
    <div class="logo">SITOVA MAPA <span>// login</span></div>
    <?php if ($error !== ''): ?><div class="app-alert" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
    <form method="post" class="edit-form">
      <?= auth_csrf_input() ?>
      <div class="form-row"><label class="form-label" for="username">Username</label><input class="form-input" id="username" name="username" autocomplete="username" required autofocus></div>
      <div class="form-row"><label class="form-label" for="password">Password</label><input class="form-input" id="password" name="password" type="password" autocomplete="current-password" required></div>
      <div class="form-actions"><button class="btn-save" type="submit">Login</button></div>
    </form>
  </main>
</body>
</html>