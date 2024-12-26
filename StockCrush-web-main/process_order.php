<?php
session_start();
require_once 'config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    $plan = $_POST['plan'];
    $quantity = $_POST['quantity'];
    $total_amount = $_POST['total_amount'];
    $payment_method = $_POST['payment_method'];

    try {
        // Start transaction
        $conn->beginTransaction();

        // Create order
        $stmt = $conn->prepare("INSERT INTO orders (user_id, total_amount, payment_method) VALUES (?, ?, ?)");
        $stmt->execute([$user_id, $total_amount, $payment_method]);
        $order_id = $conn->lastInsertId();

        // Get product details
        $stmt = $conn->prepare("SELECT * FROM products WHERE name = ?");
        $stmt->execute([$plan]);
        $product = $stmt->fetch();

        // Create order item
        $stmt = $conn->prepare("INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)");
        $stmt->execute([$order_id, $product['id'], $quantity, $product['price']]);

        // Commit transaction
        $conn->commit();
        
        echo json_encode(['success' => true, 'message' => 'Order placed successfully']);
    } catch(PDOException $e) {
        $conn->rollBack();
        echo json_encode(['success' => false, 'message' => $e->getMessage()]);
    }
}
?>