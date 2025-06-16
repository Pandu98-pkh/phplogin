<?php
// index.php
require_once 'config.php';
session_start();

// Redirect to HTTPS if not already
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    $redirectURL = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirectURL");
    exit();
}

// Set HSTS header
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h2>Login</h2>
<form method="POST" action="authenticate.php">
  <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
  <label>Username:</label><input type="text" name="username" required><br>
  <label>Password:</label><input type="password" name="password" required><br>
  <button type="submit">Login</button>
</form>
<p>Belum punya akun? <a href="register.php">Register di sini</a></p>
</body>
</html>
