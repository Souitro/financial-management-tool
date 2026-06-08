<?php
/**
 * db.php — Souitro Global Database Connection Core
 */

// Force Africa/Johannesburg timezone to keep DATETIME sync locks aligned with TIMESTAMP signatures
date_default_timezone_set('Africa/Johannesburg');

$host    = '127.0.0.1';
$db      = 'souitro_db';
$user    = 'root';       // Update with your actual local MySQL username
$pass    = '';           // Update with your actual local MySQL password
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

$options = [
    // Throw explicit, catchable PDOExceptions if an internal syntax structure fails
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    
    // Fetch query results natively into clean associative key arrays
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    
    // Disable emulated prepares to prevent dangerous SQL injection variants
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    // Fail-safe handling block
    header('Content-Type: application/json');
    
    // In production environments, log the raw $e->getMessage() to a hidden error log file
    // instead of echoing technical parameters directly to a client user window.
    echo json_encode([
        'ok' => false, 
        'message' => 'System Engine dropped database connection synchronization capabilities.'
    ]);
    exit;
}