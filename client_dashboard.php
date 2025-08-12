<?php
session_start();
if (!isset($_SESSION['client_name']) || $_SESSION['user_type'] !== 'client') {
    header('Location: login_form.php');
    exit();
}
require_once 'config.php';
$client_id = $_SESSION['user_id'];
$res = $conn->query("SELECT profile_image FROM user_form WHERE id=$client_id");
$profile_image = '';
if ($res && $row = $res->fetch_assoc()) {
    $profile_image = $row['profile_image'];
}
if (!$profile_image || !file_exists($profile_image)) {
    $profile_image = 'assets/images/client-avatar.png';
}
// Total cases
$total_cases = $conn->query("SELECT COUNT(*) FROM attorney_cases WHERE client_id=$client_id")->fetch_row()[0];
// Total documents (remove client_documents)
$total_documents = $conn->query("SELECT COUNT(*) FROM client_cases WHERE client_id=$client_id")->fetch_row()[0];
// Upcoming hearings (next 7 days)
$today = date('Y-m-d');
$next_week = date('Y-m-d', strtotime('+7 days'));
$upcoming_hearings = $conn->query("SELECT COUNT(*) FROM case_schedules WHERE client_id=$client_id AND date BETWEEN '$today' AND '$next_week'")->fetch_row()[0];
// Recent chat: get the latest message between this client and any attorney
$recent_chat = null;
$sql = "SELECT message, sent_at, 'client' as sender, recipient_id as attorney_id FROM client_messages WHERE client_id=$client_id
        UNION ALL
        SELECT message, sent_at, 'attorney' as sender, attorney_id as attorney_id FROM attorney_messages WHERE recipient_id=$client_id
        ORDER BY sent_at DESC LIMIT 1";
$res = $conn->query($sql);
if ($res && $row = $res->fetch_assoc()) {
    $recent_chat = $row;
}
// Case status distribution for this client
$status_counts = [];
$res = $conn->query("SELECT status, COUNT(*) as cnt FROM attorney_cases WHERE client_id=$client_id GROUP BY status");
while ($row = $res->fetch_assoc()) {
    $status_counts[$row['status'] ?? 'Unknown'] = (int)$row['cnt'];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Client Dashboard - Opiña Law Office</title>
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
            <li><a href="client_dashboard.php" class="active"><i class="fas fa-home"></i><span>Dashboard</span></a></li>
            <li><a href="client_documents.php"><i class="fas fa-file-alt"></i><span>Document Generation</span></a></li>
            <li><a href="client_cases.php"><i class="fas fa-gavel"></i><span>My Cases</span></a></li>
            <li><a href="client_schedule.php"><i class="fas fa-calendar-alt"></i><span>My Schedule</span></a></li>
            <li><a href="client_messages.php"><i class="fas fa-envelope"></i><span>Messages</span></a></li>
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
                <div class="card-description">Your cases</div>
            </div>
            <div class="card">
                <div class="card-title">Total Documents</div>
                <div class="card-value"><?= $total_documents ?></div>
                <div class="card-description">Your uploaded documents</div>
            </div>
            <div class="card">
                <div class="card-title">Upcoming Hearings (7 days)</div>
                <div class="card-value"><?= $upcoming_hearings ?></div>
                <div class="card-description">Hearings scheduled this week</div>
            </div>
            <div class="card">
                <div class="card-title">Recent Chat</div>
                <?php if ($recent_chat): ?>
                    <div style="font-size:1.1em;margin-bottom:4px;"><b><?= $recent_chat['sender'] === 'client' ? 'You' : 'Attorney' ?>:</b> <?= htmlspecialchars($recent_chat['message']) ?></div>
                    <div style="color:#888;font-size:0.95em;">Sent at: <?= htmlspecialchars($recent_chat['sent_at']) ?></div>
                <?php else: ?>
                    <div style="color:#888;">No recent chat yet.</div>
                <?php endif; ?>
            </div>
        </div>
        <div class="dashboard-graph">
            <h2 style="margin-bottom:18px;">Case Status Distribution</h2>
            <canvas id="caseStatusChart" height="100"></canvas>
        </div>
    </div>
    <script>
    const ctx = document.getElementById('caseStatusChart').getContext('2d');
    const data = {
        labels: <?= json_encode(array_keys($status_counts)) ?>,
        datasets: [{
            label: 'Cases',
            data: <?= json_encode(array_values($status_counts)) ?>,
            backgroundColor: [
                '#1976d2', '#43a047', '#fbc02d', '#e53935', '#8e24aa', '#00acc1', '#f57c00', '#757575'
            ],
        }]
    };
    new Chart(ctx, {
        type: 'pie',
        data: data,
        options: {
            responsive: true,
            plugins: { legend: { position: 'bottom' } }
        }
    });
    </script>
</body>
</html> 