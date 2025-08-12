<?php
session_start();
if (!isset($_SESSION['employee_name']) || $_SESSION['user_type'] !== 'employee') {
    header('Location: login_form.php');
    exit();
}
require_once 'config.php';

// Total cases
$total_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases")->fetch_row()[0];
// Total documents
$total_documents = $conn->query("SELECT COUNT(*) FROM employee_documents")->fetch_row()[0] + $conn->query("SELECT COUNT(*) FROM attorney_documents")->fetch_row()[0];
// Total users
$total_users = $conn->query("SELECT COUNT(*) FROM user_form")->fetch_row()[0];
// Upcoming hearings (next 7 days)
$today = date('Y-m-d');
$next_week = date('Y-m-d', strtotime('+7 days'));
$upcoming_hearings = $conn->query("SELECT COUNT(*) FROM case_schedules WHERE date BETWEEN '$today' AND '$next_week'")->fetch_row()[0];
// Case status distribution
$status_counts = [];
$res = $conn->query("SELECT status, COUNT(*) as cnt FROM attorney_cases GROUP BY status");
while ($row = $res->fetch_assoc()) {
    $status_counts[$row['status'] ?? 'Unknown'] = (int)$row['cnt'];
}

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
    <title>Employee Dashboard - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .dashboard-cards { display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }
        .card { background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.07); padding: 24px 32px; flex: 1; min-width: 220px; }
        .card-title { font-size: 1.1em; color: #1976d2; margin-bottom: 8px; }
        .card-value { font-size: 2.2em; font-weight: 700; color: #222; }
        .card-description { color: #888; font-size: 1em; }
        .dashboard-graph { background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.07); padding: 24px 32px; margin-bottom: 32px; }
        @media (max-width: 900px) { .dashboard-cards { flex-direction: column; } }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <img src="images/logo.jpg" alt="Logo">
            <h2>Opiña Law Office</h2>
        </div>
        <ul class="sidebar-menu">
            <li><a href="employee_dashboard.php" class="active"><i class="fas fa-home"></i><span>Dashboard</span></a></li>
            <li><a href="employee_documents.php"><i class="fas fa-file-alt"></i><span>Document Storage</span></a></li>
            <li><a href="employee_document_generation.php"><i class="fas fa-file-alt"></i><span>Document Generations</span></a></li>
            <li><a href="employee_schedule.php"><i class="fas fa-calendar-alt"></i><span>Schedule</span></a></li>
            <li><a href="employee_clients.php"><i class="fas fa-users"></i><span>Client Management</span></a></li>
            <li><a href="employee_audit.php"><i class="fas fa-history"></i><span>Audit Trail</span></a></li>
            <li><a href="logout.php"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a></li>
        </ul>
    </div>
    <div class="main-content">
        <?php 
        $page_title = 'Dashboard';
        $page_subtitle = 'Overview of your activities and statistics';
        include 'components/profile_header.php'; 
        ?>
        <div class="dashboard-cards">
            <div class="card">
                <div class="card-title">Total Cases</div>
                <div class="card-value"><?= $total_cases ?></div>
                <div class="card-description">All cases in the system</div>
            </div>
            <div class="card">
                <div class="card-title">Total Documents</div>
                <div class="card-value"><?= $total_documents ?></div>
                <div class="card-description">All documents stored</div>
            </div>
            <div class="card">
                <div class="card-title">Total Users</div>
                <div class="card-value"><?= $total_users ?></div>
                <div class="card-description">Registered users</div>
            </div>
            <div class="card">
                <div class="card-title">Upcoming Hearings</div>
                <div class="card-value"><?= $upcoming_hearings ?></div>
                <div class="card-description">Next 7 days</div>
            </div>
        </div>
        <div class="dashboard-graph">
            <h3>Case Status Distribution</h3>
            <canvas id="caseStatusChart" width="400" height="200"></canvas>
        </div>
    </div>

    <script>
        // Case Status Chart
        const ctx = document.getElementById('caseStatusChart').getContext('2d');
        const caseStatusData = <?= json_encode($status_counts) ?>;
        
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(caseStatusData),
                datasets: [{
                    data: Object.values(caseStatusData),
                    backgroundColor: [
                        '#FF6384',
                        '#36A2EB',
                        '#FFCE56',
                        '#4BC0C0',
                        '#9966FF'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    </script>
</body>
</html> 