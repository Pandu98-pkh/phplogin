<?php
// Database configuration with secure connection settings
$host = 'localhost';
$username = 'admin'; // Use dedicated user with minimum privileges
$password = 'admin123'; // Use strong password in production
$database = 'phplogin';

$con = mysqli_connect($host, $username, $password, $database);

if (!$con) {
    error_log('Database connection failed: ' . mysqli_connect_error());
    die('Database connection error. Please try again later.');
}

// Set charset to prevent character set confusion attacks
mysqli_set_charset($con, 'utf8');
?>
