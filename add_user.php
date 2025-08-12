<?php
session_start();
require_once 'config.php';

// Check if admin is logged in
if (!isset($_SESSION['admin_name']) || $_SESSION['user_type'] !== 'admin') {
    header('Location: login_form.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $phone_number = trim($_POST['phone_number']);
    $user_type = $_POST['user_type'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    
    // Validation
    $errors = [];
    
    if (empty($name)) {
        $errors[] = "Name is required";
    }
    
    if (empty($email)) {
        $errors[] = "Email is required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format";
    }
    
    if (empty($phone_number)) {
        $errors[] = "Phone number is required";
    }
    
    if (empty($user_type)) {
        $errors[] = "User type is required";
    }
    
    // Prevent creating admin accounts through this form
    if ($user_type === 'admin') {
        $errors[] = "Admin accounts cannot be created through this interface";
    }
    
    if (empty($password)) {
        $errors[] = "Password is required";
    } elseif (strlen($password) < 6) {
        $errors[] = "Password must be at least 6 characters";
    }
    
    if ($password !== $confirm_password) {
        $errors[] = "Passwords do not match";
    }
    
    // Check if email already exists
    $stmt = $conn->prepare("SELECT id FROM user_form WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $errors[] = "Email already exists";
    }
    
    // If no errors, proceed with user creation
    if (empty($errors)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        $stmt = $conn->prepare("INSERT INTO user_form (name, email, phone_number, password, user_type) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $name, $email, $phone_number, $hashed_password, $user_type);
        
        if ($stmt->execute()) {
            // Log the activity
            $admin_id = $_SESSION['user_id'];
            $admin_name = $_SESSION['admin_name'];
            $action = "Created new $user_type account: $email";
            
            // You can add this to your audit trail if you have one
            // For now, we'll just redirect with success message
            
            $_SESSION['success_message'] = "User '$name' has been successfully created as $user_type!";
            header('Location: admin_usermanagement.php');
            exit();
        } else {
            $errors[] = "Database error: " . $stmt->error;
        }
    }
    
    // If there are errors, store them in session and redirect back
    if (!empty($errors)) {
        $_SESSION['error_message'] = implode(", ", $errors);
        header('Location: admin_usermanagement.php');
        exit();
    }
} else {
    // If not POST request, redirect to user management
    header('Location: admin_usermanagement.php');
    exit();
}
?> 