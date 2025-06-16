<?php
require_once 'config.php';
require 'db.php';
session_start();

// Check if user is logged in
if (!isset($_SESSION['account_loggedin'])) {
    header('Location: index.php');
    exit;
}

$id = $_GET['id'] ?? 0;

// Ensure user can only view their own profile
if ((int)$id !== (int)$_SESSION['account_id']) {
    die('Access denied: You can only view your own profile');
}

// Use prepared statement to prevent SQL injection
$stmt = mysqli_prepare($con, "SELECT fullname, email FROM accounts WHERE id = ?");
if (!$stmt) {
    error_log('Database prepare failed: ' . mysqli_error($con));
    die('Database error occurred');
}

mysqli_stmt_bind_param($stmt, "i", $id);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (!$result || mysqli_num_rows($result) === 0) {
    die('Profile not found');
}

$row = mysqli_fetch_assoc($result);
mysqli_stmt_close($stmt);
?>
<!DOCTYPE html>
<html>
<head><title>Profil</title></head>
<body>
<h2>Profil Pengguna</h2>
<p>Nama Lengkap: <?php echo htmlspecialchars($row['fullname'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
<p>Email: <?php echo htmlspecialchars($row['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
<p><a href="home.php">Kembali</a></p>
</body>
</html>
