<?php
require_once 'config.php';

echo "<h2>Employee Registration Debug</h2>";

// Check if employee_documents table exists
echo "<h3>1. Checking employee_documents table:</h3>";
$result = $conn->query("SHOW TABLES LIKE 'employee_documents'");
if ($result && $result->num_rows > 0) {
    echo "✅ employee_documents table exists<br>";
} else {
    echo "❌ employee_documents table does not exist<br>";
}

// Check if employee_document_activity table exists
echo "<h3>2. Checking employee_document_activity table:</h3>";
$result = $conn->query("SHOW TABLES LIKE 'employee_document_activity'");
if ($result && $result->num_rows > 0) {
    echo "✅ employee_document_activity table exists<br>";
} else {
    echo "❌ employee_document_activity table does not exist<br>";
}

// Check user_type enum
echo "<h3>3. Checking user_type enum:</h3>";
$result = $conn->query("SHOW COLUMNS FROM user_form LIKE 'user_type'");
if ($result && $row = $result->fetch_assoc()) {
    echo "user_type column: " . $row['Type'] . "<br>";
    if (strpos($row['Type'], 'employee') !== false) {
        echo "✅ 'employee' is in the enum<br>";
    } else {
        echo "❌ 'employee' is NOT in the enum<br>";
    }
} else {
    echo "❌ Error checking user_type column<br>";
}

// Check all users in database
echo "<h3>4. All users in database:</h3>";
$result = $conn->query("SELECT id, name, email, user_type, created_at FROM user_form ORDER BY id DESC");
if ($result && $result->num_rows > 0) {
    echo "<table border='1' style='border-collapse: collapse; width: 100%;'>";
    echo "<tr><th>ID</th><th>Name</th><th>Email</th><th>User Type</th><th>Created</th></tr>";
    while ($row = $result->fetch_assoc()) {
        echo "<tr>";
        echo "<td>" . $row['id'] . "</td>";
        echo "<td>" . htmlspecialchars($row['name']) . "</td>";
        echo "<td>" . htmlspecialchars($row['email']) . "</td>";
        echo "<td>" . htmlspecialchars($row['user_type']) . "</td>";
        echo "<td>" . htmlspecialchars($row['created_at'] ?? 'N/A') . "</td>";
        echo "</tr>";
    }
    echo "</table>";
} else {
    echo "No users found in database<br>";
}

// Test employee insertion
echo "<h3>5. Testing employee user insertion:</h3>";
$test_email = 'test_employee_' . time() . '@gmail.com';
$test_password = password_hash('Test123!', PASSWORD_DEFAULT);

$stmt = $conn->prepare("INSERT INTO user_form (name, email, phone_number, password, user_type) VALUES (?, ?, ?, ?, ?)");
$name = 'Test Employee';
$phone = '12345678901';
$user_type = 'employee';

if ($stmt) {
    $stmt->bind_param('sssss', $name, $test_email, $phone, $test_password, $user_type);
    if ($stmt->execute()) {
        echo "✅ Successfully inserted test employee user<br>";
        echo "Test email: " . $test_email . "<br>";
        echo "Test password: Test123!<br>";
        
        // Test login
        echo "<h3>6. Testing employee login:</h3>";
        $login_stmt = $conn->prepare("SELECT * FROM user_form WHERE email = ? AND user_type = 'employee'");
        $login_stmt->bind_param('s', $test_email);
        $login_stmt->execute();
        $login_result = $login_stmt->get_result();
        
        if ($login_result->num_rows > 0) {
            $user = $login_result->fetch_assoc();
            echo "✅ Employee login test successful<br>";
            echo "User ID: " . $user['id'] . "<br>";
            echo "User Type: " . $user['user_type'] . "<br>";
        } else {
            echo "❌ Employee login test failed<br>";
        }
        
        // Clean up - delete the test user
        $conn->query("DELETE FROM user_form WHERE email = '$test_email'");
        echo "Test user cleaned up<br>";
    } else {
        echo "❌ Failed to insert test employee user: " . $stmt->error . "<br>";
    }
} else {
    echo "❌ Failed to prepare statement: " . $conn->error . "<br>";
}

// Check session handling
echo "<h3>7. Session test:</h3>";
session_start();
if (isset($_SESSION['employee_name'])) {
    echo "✅ Employee session exists: " . $_SESSION['employee_name'] . "<br>";
} else {
    echo "❌ No employee session found<br>";
}

echo "<br><h3>If you see any ❌ errors above, please fix them in phpMyAdmin.</h3>";
echo "<h3>If all tests pass ✅, the issue might be in the registration process.</h3>";
?> 