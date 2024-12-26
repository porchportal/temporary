<?php
session_start();
require_once 'config.php';

// Set headers for JSON response
header('Content-Type: application/json');

// CSRF protection
if (!isset($_SESSION['csrf_token']) || !isset($_POST['csrf_token']) || 
    $_SESSION['csrf_token'] !== $_POST['csrf_token']) {
    echo json_encode(['success' => false, 'message' => 'Invalid request']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $remember_me = isset($_POST['remember_me']);

    // Input validation
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Please fill in all fields']);
        exit;
    }

    try {
        // Check if input is email or username
        $isEmail = filter_var($username, FILTER_VALIDATE_EMAIL);
        $sql = $isEmail 
            ? "SELECT * FROM users WHERE email = ?" 
            : "SELECT * FROM users WHERE username = ?";
        
        $stmt = $conn->prepare($sql);
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Set session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            
            // Update last login timestamp
            $updateStmt = $conn->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
            $updateStmt->execute([$user['id']]);

            // Set remember me cookie if requested
            if ($remember_me) {
                $token = bin2hex(random_bytes(32));
                $hash = password_hash($token, PASSWORD_DEFAULT);
                
                // Store token in database
                $tokenStmt = $conn->prepare("UPDATE users SET remember_token = ? WHERE id = ?");
                $tokenStmt->execute([$hash, $user['id']]);
                
                // Set cookie for 30 days
                setcookie('remember_token', $token, time() + (86400 * 30), '/', '', true, true);
            }

            // Log successful login
            $logStmt = $conn->prepare("INSERT INTO login_logs (user_id, status, ip_address) VALUES (?, 'success', ?)");
            $logStmt->execute([$user['id'], $_SERVER['REMOTE_ADDR']]);

            echo json_encode([
                'success' => true,
                'message' => 'Login successful',
                'redirect' => 'dashboard.php'
            ]);
        } else {
            // Log failed login attempt
            if ($user) {
                $logStmt = $conn->prepare("INSERT INTO login_logs (user_id, status, ip_address) VALUES (?, 'failed', ?)");
                $logStmt->execute([$user['id'], $_SERVER['REMOTE_ADDR']]);
            }

            echo json_encode([
                'success' => false,
                'message' => 'Invalid username/email or password'
            ]);
        }
    } catch (PDOException $e) {
        error_log("Login error: " . $e->getMessage());
        echo json_encode([
            'success' => false,
            'message' => 'An error occurred. Please try again later.'
        ]);
    }
} else {
    echo json_encode([
        'success' => false,
        'message' => 'Invalid request method'
    ]);
}