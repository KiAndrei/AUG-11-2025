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
// Fetch all events with joins
$events = [];
$res = $conn->query("SELECT cs.*, ac.title as case_title, ac.attorney_id, uf1.name as attorney_name, uf2.name as client_name FROM case_schedules cs
    LEFT JOIN attorney_cases ac ON cs.case_id = ac.id
    LEFT JOIN user_form uf1 ON ac.attorney_id = uf1.id
    LEFT JOIN user_form uf2 ON cs.client_id = uf2.id
    ORDER BY cs.date, cs.time");
while ($row = $res->fetch_assoc()) $events[] = $row;
$js_events = [];
foreach ($events as $ev) {
    $js_events[] = [
        'title' => $ev['type'] . ': ' . ($ev['case_title'] ?? ''),
        'start' => $ev['date'] . 'T' . $ev['time'],
        'type' => $ev['type'],
        'description' => $ev['description'],
        'location' => $ev['location'],
        'case' => $ev['case_title'],
        'attorney' => $ev['attorney_name'],
        'client' => $ev['client_name'],
        'color' => $ev['type'] === 'Hearing' ? '#1976d2' : '#43a047',
    ];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Schedule Management - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.3/main.min.css">
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
            <li><a href="employee_document_generation.php"><i class="fas fa-file-alt"></i><span>Document Generations</span></a></li>
            <li><a href="employee_schedule.php" class="active"><i class="fas fa-calendar-alt"></i><span>Schedule</span></a></li>
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
                <h1>Schedule Management</h1>
                <p>View court hearings, meetings, and appointments</p>
            </div>
            <div class="user-info">
                <img src="<?= htmlspecialchars($profile_image) ?>" alt="Employee" style="object-fit:cover;width:60px;height:60px;border-radius:50%;border:2px solid #1976d2;">
                <div class="user-details">
                    <h3><?php echo $_SESSION['employee_name']; ?></h3>
                    <p>Employee</p>
                </div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="action-buttons">
            <div class="view-options">
                <button class="btn btn-secondary active" data-view="month">
                    <i class="fas fa-calendar"></i> Month
                </button>
                <button class="btn btn-secondary" data-view="week">
                    <i class="fas fa-calendar-week"></i> Week
                </button>
                <button class="btn btn-secondary" data-view="day">
                    <i class="fas fa-calendar-day"></i> Day
                </button>
            </div>
        </div>
        
        <!-- Calendar Container -->
        <div class="calendar-container">
            <div id="calendar"></div>
        </div>
    </div>

    <!-- Event Details Modal -->
    <div id="eventModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h3 id="eventTitle"></h3>
            <div class="event-details">
                <p><strong>Type:</strong> <span id="eventType"></span></p>
                <p><strong>Date:</strong> <span id="eventDate"></span></p>
                <p><strong>Time:</strong> <span id="eventTime"></span></p>
                <p><strong>Location:</strong> <span id="eventLocation"></span></p>
                <p><strong>Case:</strong> <span id="eventCase"></span></p>
                <p><strong>Attorney:</strong> <span id="eventAttorney"></span></p>
                <p><strong>Client:</strong> <span id="eventClient"></span></p>
                <p><strong>Description:</strong> <span id="eventDescription"></span></p>
            </div>
        </div>
    </div>

    <style>
        .action-buttons {
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.07);
            padding: 20px;
            margin-bottom: 24px;
        }
        
        .view-options {
            display: flex;
            gap: 12px;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-secondary {
            background: #f8f9fa;
            color: #6c757d;
            border: 1px solid #dee2e6;
        }
        
        .btn-secondary:hover, .btn-secondary.active {
            background: #1976d2;
            color: white;
            border-color: #1976d2;
        }
        
        .calendar-container {
            background: #fff;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.07);
            padding: 24px;
            margin-bottom: 24px;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: #fefefe;
            margin: 15% auto;
            padding: 20px;
            border-radius: 10px;
            width: 80%;
            max-width: 500px;
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #000;
        }
        
        .event-details p {
            margin: 8px 0;
        }
        
        .event-details strong {
            color: #333;
        }
        
        @media (max-width: 768px) {
            .view-options {
                flex-direction: column;
            }
        }
    </style>

    <script src="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.3/main.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var calendarEl = document.getElementById('calendar');
            var calendar = new FullCalendar.Calendar(calendarEl, {
                initialView: 'dayGridMonth',
                headerToolbar: {
                    left: 'prev,next today',
                    center: 'title',
                    right: 'dayGridMonth,timeGridWeek,timeGridDay'
                },
                events: <?= json_encode($js_events) ?>,
                eventClick: function(info) {
                    showEventDetails(info.event);
                },
                eventColor: '#1976d2',
                height: 'auto'
            });
            calendar.render();
            
            // View buttons functionality
            document.querySelectorAll('.view-options .btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    document.querySelectorAll('.view-options .btn').forEach(b => b.classList.remove('active'));
                    this.classList.add('active');
                    
                    const view = this.dataset.view;
                    if (view === 'month') {
                        calendar.changeView('dayGridMonth');
                    } else if (view === 'week') {
                        calendar.changeView('timeGridWeek');
                    } else if (view === 'day') {
                        calendar.changeView('timeGridDay');
                    }
                });
            });
        });
        
        function showEventDetails(event) {
            document.getElementById('eventTitle').textContent = event.title;
            document.getElementById('eventType').textContent = event.extendedProps.type || 'N/A';
            document.getElementById('eventDate').textContent = event.start.toLocaleDateString();
            document.getElementById('eventTime').textContent = event.start.toLocaleTimeString();
            document.getElementById('eventLocation').textContent = event.extendedProps.location || 'N/A';
            document.getElementById('eventCase').textContent = event.extendedProps.case || 'N/A';
            document.getElementById('eventAttorney').textContent = event.extendedProps.attorney || 'N/A';
            document.getElementById('eventClient').textContent = event.extendedProps.client || 'N/A';
            document.getElementById('eventDescription').textContent = event.extendedProps.description || 'N/A';
            
            document.getElementById('eventModal').style.display = 'block';
        }
        
        // Close modal
        document.querySelector('.close').addEventListener('click', function() {
            document.getElementById('eventModal').style.display = 'none';
        });
        
        window.addEventListener('click', function(event) {
            var modal = document.getElementById('eventModal');
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        });
    </script>
</body>
</html> 