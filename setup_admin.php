<?php
require_once 'config.php';

// Check if admin already exists
$check_admin = $conn->query("SELECT COUNT(*) as count FROM user_form WHERE user_type = 'admin'");
$admin_count = $check_admin->fetch_assoc()['count'];

if ($admin_count == 0) {
    // Create default admin account
    $admin_name = "System Administrator";
    $admin_email = "admin@lawfirm.com";
    $admin_password = "admin123"; // Change this to a secure password
    $hashed_password = password_hash($admin_password, PASSWORD_DEFAULT);
    $admin_phone = "09123456789";
    
    $stmt = $conn->prepare("INSERT INTO user_form (name, email, password, user_type, phone_number) VALUES (?, ?, ?, 'admin', ?)");
    $stmt->bind_param("ssss", $admin_name, $admin_email, $hashed_password, $admin_phone);
    
    if ($stmt->execute()) {
        echo "<h2>✅ Admin Account Created Successfully!</h2>";
        echo "<p><strong>Email:</strong> $admin_email</p>";
        echo "<p><strong>Password:</strong> $admin_password</p>";
        echo "<p><strong>⚠️ IMPORTANT:</strong> Please change this password immediately after first login!</p>";
        echo "<p><a href='login_form.php'>Go to Login</a></p>";
    } else {
        echo "<h2>❌ Error creating admin account</h2>";
        echo "<p>Error: " . $stmt->error . "</p>";
    }
} else {
    echo "<h2>ℹ️ Admin account already exists</h2>";
    echo "<p>No need to create another admin account.</p>";
    echo "<p><a href='login_form.php'>Go to Login</a></p>";
}
?> 