<?php
require_once 'config.php';

// Create notifications table
$sql = "CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    user_type ENUM('admin', 'attorney', 'employee', 'client') NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    type ENUM('info', 'success', 'warning', 'error') DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_form(id) ON DELETE CASCADE
)";

if ($conn->query($sql) === TRUE) {
    echo "Notifications table created successfully\n";
} else {
    echo "Error creating notifications table: " . $conn->error . "\n";
}

// Add some sample notifications
$sample_notifications = [
    ['Welcome to Opiña Law Office!', 'Your account has been successfully created.', 'success'],
    ['System Update', 'New features have been added to the document management system.', 'info'],
    ['Document Upload', 'Your document has been successfully uploaded.', 'success']
];

foreach ($sample_notifications as $notification) {
    $user_id = $_SESSION['user_id'] ?? 1;
    $user_type = $_SESSION['user_type'] ?? 'admin';
    $title = $notification[0];
    $message = $notification[1];
    $type = $notification[2];
    
    $stmt = $conn->prepare("INSERT INTO notifications (user_id, user_type, title, message, type) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param('issss', $user_id, $user_type, $title, $message, $type);
    $stmt->execute();
}

echo "Sample notifications added successfully\n";
?> 