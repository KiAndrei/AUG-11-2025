<?php
require_once 'config.php';

echo "<h2>Database Test - Employee Role</h2>";

// Test 1: Check user_type enum
echo "<h3>1. Checking user_type enum values:</h3>";
$result = $conn->query("SHOW COLUMNS FROM user_form LIKE 'user_type'");
if ($result && $row = $result->fetch_assoc()) {
    echo "user_type column: " . $row['Type'] . "<br>";
} else {
    echo "Error checking user_type column<br>";
}

// Test 2: Check if employee_documents table exists
echo "<h3>2. Checking employee_documents table:</h3>";
$result = $conn->query("SHOW TABLES LIKE 'employee_documents'");
if ($result && $result->num_rows > 0) {
    echo "✅ employee_documents table exists<br>";
} else {
    echo "❌ employee_documents table does not exist<br>";
}

// Test 3: Check if employee_document_activity table exists
echo "<h3>3. Checking employee_document_activity table:</h3>";
$result = $conn->query("SHOW TABLES LIKE 'employee_document_activity'");
if ($result && $result->num_rows > 0) {
    echo "✅ employee_document_activity table exists<br>";
} else {
    echo "❌ employee_document_activity table does not exist<br>";
}

// Test 4: Try to insert a test employee user
echo "<h3>4. Testing employee user insertion:</h3>";
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
        
        // Clean up - delete the test user
        $conn->query("DELETE FROM user_form WHERE email = '$test_email'");
        echo "Test user cleaned up<br>";
    } else {
        echo "❌ Failed to insert test employee user: " . $stmt->error . "<br>";
    }
} else {
    echo "❌ Failed to prepare statement: " . $conn->error . "<br>";
}

echo "<br><h3>If you see any ❌ errors above, please fix them in phpMyAdmin.</h3>";
echo "<h3>If all tests pass ✅, try refreshing your registration page.</h3>";
?> 