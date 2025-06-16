<?php
require_once 'config.php';
session_start();
require 'db.php';

// Brute force protection
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt'] = 0;
}

// Check for brute force attempts
if ($_SESSION['login_attempts'] >= 5) {
    $time_diff = time() - $_SESSION['last_attempt'];
    if ($time_diff < 300) { // 5 minutes lockout
        die('Too many failed attempts. Please try again in 5 minutes.');
    } else {
        $_SESSION['login_attempts'] = 0;
    }
}

// Verify CSRF token
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Invalid CSRF token');
}

$user = $_POST['username'] ?? '';
$pass = $_POST['password'] ?? '';

if (empty($user) || empty($pass)) {
    $_SESSION['login_attempts']++;
    $_SESSION['last_attempt'] = time();
    die('Username and password are required');
}

// Use prepared statement to prevent SQL injection
$stmt = mysqli_prepare($con, "SELECT id, password FROM accounts WHERE username = ?");
if (!$stmt) {
    error_log('Database prepare failed: ' . mysqli_error($con));
    die('Database error occurred');
}

mysqli_stmt_bind_param($stmt, "s", $user);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if ($result && mysqli_num_rows($result) === 1) {
    $row = mysqli_fetch_assoc($result);
    
    // Verify password using password_verify()
    if (password_verify($pass, $row['password'])) {
        // Reset login attempts on successful login
        $_SESSION['login_attempts'] = 0;
        
        // Regenerate session ID to prevent session fixation
        session_regenerate_id(true);
        
        $_SESSION['account_loggedin'] = true;
        $_SESSION['account_id'] = $row['id'];
        $_SESSION['account_name'] = $user;
        
        // Generate new CSRF token
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        
        header('Location: home.php');
        exit;
    }
}

// Increment failed login attempts
$_SESSION['login_attempts']++;
$_SESSION['last_attempt'] = time();

mysqli_stmt_close($stmt);
echo 'Username / password salah';
?>
