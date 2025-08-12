<?php
require_once 'config.php';

echo "<h2>Database Fix for Employee Support</h2>";

// Fix 1: Update user_type enum to include 'employee'
echo "<h3>1. Fixing user_type enum:</h3>";
$result = $conn->query("ALTER TABLE user_form MODIFY user_type enum('admin','attorney','client','employee') DEFAULT 'client'");
if ($result) {
    echo "✅ Successfully updated user_type enum to include 'employee'<br>";
} else {
    echo "❌ Failed to update user_type enum: " . $conn->error . "<br>";
}

// Fix 2: Create employee_documents table if it doesn't exist
echo "<h3>2. Creating employee_documents table:</h3>";
$result = $conn->query("CREATE TABLE IF NOT EXISTS employee_documents (
    id int(11) NOT NULL AUTO_INCREMENT,
    file_name varchar(255) NOT NULL,
    file_path varchar(255) NOT NULL,
    category varchar(100) NOT NULL,
    uploaded_by int(11) NOT NULL,
    upload_date datetime NOT NULL DEFAULT current_timestamp(),
    form_number int(11) DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci");
if ($result) {
    echo "✅ Successfully created employee_documents table<br>";
} else {
    echo "❌ Failed to create employee_documents table: " . $conn->error . "<br>";
}

// Fix 3: Create employee_document_activity table if it doesn't exist
echo "<h3>3. Creating employee_document_activity table:</h3>";
$result = $conn->query("CREATE TABLE IF NOT EXISTS employee_document_activity (
    id int(11) NOT NULL AUTO_INCREMENT,
    document_id int(11) NOT NULL,
    action varchar(50) NOT NULL,
    user_id int(11) NOT NULL,
    form_number int(11) DEFAULT NULL,
    file_name varchar(255) NOT NULL,
    timestamp timestamp NOT NULL DEFAULT current_timestamp(),
    user_name varchar(100) DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci");
if ($result) {
    echo "✅ Successfully created employee_document_activity table<br>";
} else {
    echo "❌ Failed to create employee_document_activity table: " . $conn->error . "<br>";
}

// Fix 4: Add created_at column if it doesn't exist
echo "<h3>4. Adding created_at column to user_form:</h3>";
$result = $conn->query("SHOW COLUMNS FROM user_form LIKE 'created_at'");
if ($result && $result->num_rows == 0) {
    $result = $conn->query("ALTER TABLE user_form ADD created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
    if ($result) {
        echo "✅ Successfully added created_at column<br>";
    } else {
        echo "❌ Failed to add created_at column: " . $conn->error . "<br>";
    }
} else {
    echo "✅ created_at column already exists<br>";
}

// Test employee insertion
echo "<h3>5. Testing employee user creation:</h3>";
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
        
        // Verify the user was created
        $verify_stmt = $conn->prepare("SELECT * FROM user_form WHERE email = ? AND user_type = 'employee'");
        $verify_stmt->bind_param('s', $test_email);
        $verify_stmt->execute();
        $verify_result = $verify_stmt->get_result();
        
        if ($verify_result->num_rows > 0) {
            $user = $verify_result->fetch_assoc();
            echo "✅ Employee user verified in database<br>";
            echo "User ID: " . $user['id'] . "<br>";
            echo "User Type: " . $user['user_type'] . "<br>";
        } else {
            echo "❌ Employee user not found in database<br>";
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

// Show current database structure
echo "<h3>6. Current user_form table structure:</h3>";
$result = $conn->query("DESCRIBE user_form");
if ($result) {
    echo "<table border='1' style='border-collapse: collapse; width: 100%;'>";
    echo "<tr><th>Field</th><th>Type</th><th>Null</th><th>Key</th><th>Default</th><th>Extra</th></tr>";
    while ($row = $result->fetch_assoc()) {
        echo "<tr>";
        echo "<td>" . $row['Field'] . "</td>";
        echo "<td>" . $row['Type'] . "</td>";
        echo "<td>" . $row['Null'] . "</td>";
        echo "<td>" . $row['Key'] . "</td>";
        echo "<td>" . $row['Default'] . "</td>";
        echo "<td>" . $row['Extra'] . "</td>";
        echo "</tr>";
    }
    echo "</table>";
}

echo "<br><h3>✅ Database fix completed! Try registering an employee account again.</h3>";
?> 