<?php
session_start();
if (!isset($_SESSION['employee_name']) || $_SESSION['user_type'] !== 'employee') {
    header('Location: login_form.php');
    exit();
}
require_once 'config.php';
$employee_id = $_SESSION['user_id'];
$res = $conn->query("SELECT profile_image FROM user_form WHERE id=$employee_id");
$profile_image = '';
if ($res && $row = $res->fetch_assoc()) {
    $profile_image = $row['profile_image'];
}
if (!$profile_image || !file_exists($profile_image)) {
    $profile_image = 'assets/images/employee-avatar.png';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Generation - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css">
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
        <img src="images/logo.jpg" alt="Logo">
            <h2>Opiña Law Office</h2>
        </div>
        <ul class="sidebar-menu">
            <li><a href="employee_dashboard.php"><i class="fas fa-home"></i><span>Dashboard</span></a></li>
            <li><a href="employee_documents.php"><i class="fas fa-file-alt"></i><span>Document Storage</span></a></li>
            <li><a href="employee_document_generation.php" class="active"><i class="fas fa-file-alt"></i><span>Document Generations</span></a></li>
            <li><a href="employee_schedule.php"><i class="fas fa-calendar-alt"></i><span>Schedule</span></a></li>
            <li><a href="employee_clients.php"><i class="fas fa-users"></i><span>Client Management</span></a></li>
            <li><a href="employee_audit.php"><i class="fas fa-history"></i><span>Audit Trail</span></a></li>
            <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a></li>
        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>Document Generation</h1>
                <p>Generate document storage and forms</p>
            </div>
            <div class="user-info">
                <img src="<?= htmlspecialchars($profile_image) ?>" alt="Employee" style="object-fit:cover;width:60px;height:60px;border-radius:50%;border:2px solid #1976d2;">
                <div class="user-details">
                    <h3><?php echo $_SESSION['employee_name']; ?></h3>
                    <p>Employee</p>
                </div>
            </div>
        </div>

        <!-- Document Generation Grid -->
        <div class="document-grid">
            <!-- Row 1 -->
            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-file-contract"></i>
                </div>
                <h3>Affidavit of Loss</h3>
                <p>Generate affidavit of loss document</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-gavel"></i>
                </div>
                <h3>Deed of Sale</h3>
                <p>Generate deed of sale document</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-handshake"></i>
                </div>
                <h3>Sworn Affidavit of Solo Parent</h3>
                <p>Generate sworn affidavit of solo parent</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <!-- Row 2 -->
            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-file-signature"></i>
                </div>
                <h3>Affidavit of Two Disinterested Persons</h3>
                <p>Generate affidavit of two disinterested persons</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-user-tie"></i>
                </div>
                <h3>Affidavit of Change of Name</h3>
                <p>Generate affidavit of change of name</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <h3>Affidavit of Delayed Registration</h3>
                <p>Generate affidavit of delayed registration</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <!-- Row 3 -->
            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-file-contract"></i>
                </div>
                <h3>Affidavit of One and the Same Person</h3>
                <p>Generate affidavit of one and the same person</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-gavel"></i>
                </div>
                <h3>Affidavit of Marriage</h3>
                <p>Generate affidavit of marriage</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-handshake"></i>
                </div>
                <h3>Affidavit of Death</h3>
                <p>Generate affidavit of death</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <!-- Row 4 -->
            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-file-signature"></i>
                </div>
                <h3>Affidavit of Birth</h3>
                <p>Generate affidavit of birth</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-user-tie"></i>
                </div>
                <h3>Affidavit of Residency</h3>
                <p>Generate affidavit of residency</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>

            <div class="document-box">
                <div class="document-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <h3>Affidavit of Guardianship</h3>
                <p>Generate affidavit of guardianship</p>
                <button class="btn btn-primary generate-btn">
                    <i class="fas fa-magic"></i> Generate
                </button>
            </div>
        </div>
    </div>

    <style>
        .document-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            padding: 24px;
        }

        .document-box {
            background: #fff;
            border-radius: 12px;
            padding: 32px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .document-box:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }

        .document-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
        }

        .document-icon i {
            font-size: 32px;
            color: white;
        }

        .document-box h3 {
            color: #333;
            margin-bottom: 12px;
            font-size: 18px;
            font-weight: 600;
        }

        .document-box p {
            color: #666;
            margin-bottom: 24px;
            font-size: 14px;
            line-height: 1.5;
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, #5a6fd8 0%, #6a4190 100%);
            transform: translateY(-2px);
        }

        .generate-btn {
            width: 100%;
            justify-content: center;
        }

        @media (max-width: 768px) {
            .document-grid {
                grid-template-columns: 1fr;
                padding: 16px;
            }
        }
    </style>
</body>
</html> 