<?php
require_once 'config.php';
session_start();

// Clear all session data
$_SESSION = array();

// Delete the session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Regenerate session ID to invalidate old session
session_regenerate_id(true);

// Destroy the session
session_destroy();

header('Location: index.php');
exit;
?>
