<?php
require_once 'config.php';
require 'db.php';
session_start();

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_POST['username'], $_POST['password'], $_POST['confirm_password'], $_POST['fullname'], $_POST['email'])) {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('Invalid CSRF token');
    }
    
    $user = trim($_POST['username']);
    $pass = $_POST['password'];
    $confirm_pass = $_POST['confirm_password'];
    $fullname = trim($_POST['fullname']);
    $email = trim($_POST['email']);
      // Input validation
    if (empty($user) || empty($pass) || empty($confirm_pass) || empty($fullname) || empty($email)) {
        $error = 'All fields are required';
    } elseif ($pass !== $confirm_pass) {
        $error = 'Passwords do not match';
    } elseif (strlen($user) < 3 || strlen($user) > 50) {
        $error = 'Username must be between 3 and 50 characters';
    } elseif (strlen($pass) < 6) {
        $error = 'Password must be at least 6 characters';
    } elseif (strlen($fullname) < 2 || strlen($fullname) > 100) {
        $error = 'Full name must be between 2 and 100 characters';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address';
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $user)) {
        $error = 'Username can only contain letters, numbers, and underscores';
    } else {        // Check if username already exists
        $stmt = mysqli_prepare($con, "SELECT id FROM accounts WHERE username = ? OR email = ?");
        if (!$stmt) {
            error_log('Database prepare failed: ' . mysqli_error($con));
            $error = 'Database error occurred';
        } else {
            mysqli_stmt_bind_param($stmt, "ss", $user, $email);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            
            if (mysqli_num_rows($result) > 0) {
                $error = 'Username or email already exists';
                mysqli_stmt_close($stmt);
            } else {
                mysqli_stmt_close($stmt);
                
                // Hash password before storing
                $hashed_password = password_hash($pass, PASSWORD_DEFAULT);
                  // Insert new user with prepared statement
                $stmt = mysqli_prepare($con, "INSERT INTO accounts (username, password, fullname, email) VALUES (?, ?, ?, ?)");
                if (!$stmt) {
                    error_log('Database prepare failed: ' . mysqli_error($con));
                    $error = 'Database error occurred';
                } else {
                    mysqli_stmt_bind_param($stmt, "ssss", $user, $hashed_password, $fullname, $email);
                    
                    if (mysqli_stmt_execute($stmt)) {
                        mysqli_stmt_close($stmt);
                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // Generate new token
                        header('Location: index.php?registered=1');
                        exit;
                    } else {
                        error_log('User registration failed: ' . mysqli_stmt_error($stmt));
                        $error = 'Registration failed. Please try again.';
                        mysqli_stmt_close($stmt);
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Register</title></head>
<body>
<h2>Register</h2>
<?php if (isset($error)): ?>
    <p style="color: red;"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
<?php endif; ?>
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <label>Full Name:</label><input type="text" name="fullname" required minlength="2" maxlength="100"><br>
    <label>Email:</label><input type="email" name="email" required maxlength="100"><br>
    <label>Username:</label><input type="text" name="username" required minlength="3" maxlength="50"><br>
    <label>Password:</label><input type="password" name="password" required minlength="6"><br>
    <label>Confirm Password:</label><input type="password" name="confirm_password" required minlength="6"><br>
    <button type="submit">Register</button>
</form>
<p><a href="index.php">Already have an account? Login here</a></p>
</body>
</html>
