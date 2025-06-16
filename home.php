<?php
require_once 'config.php';
session_start();
require 'db.php';

if (!isset($_SESSION['account_loggedin'])) {
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html>
<head><title>Home</title></head>
<body>
<h2>Selamat datang, <?php echo htmlspecialchars($_SESSION['account_name'], ENT_QUOTES, 'UTF-8'); ?></h2>
<p><a href="profile.php?id=<?php echo urlencode($_SESSION['account_id']); ?>">Lihat Profil</a></p>
<p><a href="logout.php">Logout</a></p>
</body>
</html>
