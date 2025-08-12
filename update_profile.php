<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'client') {
    echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
    exit();
}

require_once 'config.php';

$client_id = $_SESSION['user_id'];
$response = ['success' => false, 'message' => ''];

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        
        if (empty($name) || empty($email)) {
            $response['message'] = "Name and email are required.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $response['message'] = "Please enter a valid email address.";
        } else {
            // Check if email already exists for another user
            $stmt = $conn->prepare("SELECT id FROM user_form WHERE email = ? AND id != ?");
            $stmt->bind_param('si', $email, $client_id);
            $stmt->execute();
            if ($stmt->get_result()->num_rows > 0) {
                $response['message'] = "Email address is already in use.";
            } else {
                // Get current profile image
                $stmt = $conn->prepare("SELECT profile_image FROM user_form WHERE id = ?");
                $stmt->bind_param('i', $client_id);
                $stmt->execute();
                $result = $stmt->get_result();
                $current_data = $result->fetch_assoc();
                $profile_image = $current_data['profile_image'];
                
                // Handle profile image upload
                if (isset($_FILES['profile_image']) && $_FILES['profile_image']['error'] === UPLOAD_ERR_OK) {
                    $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
                    $file_type = $_FILES['profile_image']['type'];
                    
                    if (in_array($file_type, $allowed_types)) {
                        $file_extension = pathinfo($_FILES['profile_image']['name'], PATHINFO_EXTENSION);
                        $new_filename = $client_id . '_' . time() . '.' . $file_extension;
                        $upload_path = 'uploads/client/' . $new_filename;
                        
                        if (move_uploaded_file($_FILES['profile_image']['tmp_name'], $upload_path)) {
                            // Delete old profile image if it exists and is not the default
                            if ($profile_image && $profile_image !== 'assets/images/client-avatar.png' && file_exists($profile_image)) {
                                unlink($profile_image);
                            }
                            $profile_image = $upload_path;
                        }
                    }
                }
                
                // Update user data
                $stmt = $conn->prepare("UPDATE user_form SET name = ?, email = ?, profile_image = ? WHERE id = ?");
                $stmt->bind_param('sssi', $name, $email, $profile_image, $client_id);
                
                if ($stmt->execute()) {
                    $_SESSION['client_name'] = $name;
                    $response['success'] = true;
                    $response['message'] = "Profile updated successfully!";
                } else {
                    $response['message'] = "Failed to update profile. Please try again.";
                }
            }
        }
    } else {
        $response['message'] = "Invalid request method.";
    }
} catch (Exception $e) {
    $response['message'] = "An error occurred: " . $e->getMessage();
}

echo json_encode($response);
?>
