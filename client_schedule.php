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
// Fetch all events for this client
$events = [];
$res = $conn->query("SELECT cs.*, ac.title as case_title, uf.name as attorney_name FROM case_schedules cs LEFT JOIN attorney_cases ac ON cs.case_id = ac.id LEFT JOIN user_form uf ON ac.attorney_id = uf.id WHERE cs.client_id=$client_id ORDER BY cs.date, cs.time");
while ($row = $res->fetch_assoc()) $events[] = $row;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Schedule - Opiña Law Office</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/dashboard.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.3/main.min.css">
    <script src="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.3/main.min.js"></script>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-header">
        <img src="images/logo.jpg" alt="Logo">
            <h2>Opiña Law Office</h2>
        </div>
        <ul class="sidebar-menu">
            <li>
                <a href="client_dashboard.php">
                    <i class="fas fa-home"></i>
                    <span>Dashboard</span>
                </a>
            </li>
            <li>
                <a href="client_documents.php">
                    <i class="fas fa-file-alt"></i>
                    <span>Document Generation</span>
                </a>
            </li>
            <li>
                <a href="client_cases.php">
                    <i class="fas fa-gavel"></i>
                    <span>My Cases</span>
                </a>
            </li>
            <li>
                <a href="client_schedule.php" class="active">
                    <i class="fas fa-calendar-alt"></i>
                    <span>My Schedule</span>
                </a>
            </li>
            <li>
                <a href="client_messages.php">
                    <i class="fas fa-envelope"></i>
                    <span>Messages</span>
                </a>
            </li>

        </ul>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>My Schedule</h1>
                <p>View your upcoming appointments and court hearings</p>
            </div>
            <div class="user-info">
                <div class="topbar-notification">
                    <i class="fas fa-bell"></i>
                    <span class="notification-badge">0</span>
                </div>
                <div class="profile-dropdown" style="display: flex; align-items: center; gap: 12px;">
                    <img src="<?= htmlspecialchars($profile_image) ?>" alt="Client" style="object-fit:cover;width:42px;height:42px;border-radius:50%;border:2px solid #1976d2;cursor:pointer;" onclick="toggleProfileDropdown()">
                    <div class="user-details">
                        <h3><?php echo $_SESSION['client_name']; ?></h3>
                        <p>Client</p>
                    </div>
                    
                    <!-- Profile Dropdown Menu -->
                    <div class="profile-dropdown-content" id="profileDropdown">
                        <a href="#" onclick="editProfile()">
                            <i class="fas fa-user-edit"></i>
                            Edit Profile
                        </a>
                        <a href="logout.php" class="logout">
                            <i class="fas fa-sign-out-alt"></i>
                            Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="action-buttons">
            <div class="calendar-views">
                <button class="btn btn-secondary active" data-view="month">
                    <i class="fas fa-calendar"></i> Month
                </button>
                <button class="btn btn-secondary" data-view="week">
                    <i class="fas fa-calendar-week"></i> Week
                </button>
            </div>
            <div class="search-box">
                <i class="fas fa-search"></i>
                <input type="text" placeholder="Search appointments...">
            </div>
        </div>

        <!-- Calendar Container -->
        <div class="calendar-container">
            <div id="calendar"></div>
        </div>

        <!-- Upcoming Events -->
        <div class="table-container">
            <div class="table-header">
                <h2 class="table-title">Upcoming Appointments</h2>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Location</th>
                        <th>Case</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($events as $i => $ev): ?>
                    <tr>
                        <td><?= htmlspecialchars($ev['date']) ?></td>
                        <td><?= htmlspecialchars(date('h:i A', strtotime($ev['time']))) ?></td>
                        <td><?= htmlspecialchars($ev['type']) ?></td>
                        <td><?= htmlspecialchars($ev['location']) ?></td>
                        <td><?= htmlspecialchars($ev['case_title'] ?? '-') ?></td>
                        <td>
                            <span class="status-badge status-upcoming"><?= htmlspecialchars($ev['status']) ?></span>
                            <button class="btn btn-info btn-xs view-info-btn" 
                                data-type="<?= htmlspecialchars($ev['type']) ?>"
                                data-date="<?= htmlspecialchars($ev['date']) ?>"
                                data-time="<?= htmlspecialchars($ev['time']) ?>"
                                data-location="<?= htmlspecialchars($ev['location']) ?>"
                                data-case="<?= htmlspecialchars($ev['case_title'] ?? '-') ?>"
                                data-attorney="<?= htmlspecialchars($ev['attorney_name'] ?? '-') ?>"
                                data-description="<?= htmlspecialchars($ev['description'] ?? '-') ?>"
                                style="margin-left:8px; font-size:0.95em; padding:3px 10px; border-radius:6px; background:#1976d2; color:#fff; border:none; cursor:pointer;">View Info</button>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- Event Details Modal -->
        <div class="modal" id="eventModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Appointment Details</h2>
                    <button class="close-modal">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="event-info">
                        <div class="info-group">
                            <h3>Appointment Information</h3>
                            <div class="info-item"><span class="label">Type:</span><span class="value" id="modalType"></span></div>
                            <div class="info-item"><span class="label">Date:</span><span class="value" id="modalDate"></span></div>
                            <div class="info-item"><span class="label">Time:</span><span class="value" id="modalTime"></span></div>
                            <div class="info-item"><span class="label">Location:</span><span class="value" id="modalLocation"></span></div>
                            <div class="info-item"><span class="label">Case:</span><span class="value" id="modalCase"></span></div>
                            <div class="info-item"><span class="label">Attorney:</span><span class="value" id="modalAttorney"></span></div>
                            <div class="info-item"><span class="label">Description:</span><span class="value" id="modalDescription"></span></div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" id="closeEventModal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <style>
        /* Professional Theme Styling */
        .action-buttons {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: white;
            padding: 16px 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(93, 14, 38, 0.08);
            margin-bottom: 20px;
        }

        .calendar-views {
            display: flex;
            gap: 8px;
        }

        .calendar-views .btn {
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 500;
            transition: all 0.3s ease;
            border: 1px solid #e0e0e0;
            background: white;
            color: var(--primary-color);
        }

        .calendar-views .btn:hover {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }

        .calendar-views .btn.active {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
            box-shadow: 0 2px 8px rgba(93, 14, 38, 0.2);
        }

        .search-box {
            position: relative;
            display: flex;
            align-items: center;
        }

        .search-box i {
            position: absolute;
            left: 12px;
            color: #666;
            font-size: 0.9rem;
        }

        .search-box input {
            padding: 8px 12px 8px 36px;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            font-size: 0.9rem;
            width: 250px;
            transition: border-color 0.3s ease;
        }

        .search-box input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(93, 14, 38, 0.1);
        }

        .calendar-container {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0 40px 0;
            box-shadow: 0 2px 12px rgba(93, 14, 38, 0.08);
            border: 1px solid #f0f0f0;
            overflow: hidden;
        }

        /* Make calendar properly sized and contained */
        #calendar {
            max-height: 600px;
            width: 100%;
            overflow: hidden;
        }

        .fc {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 100%;
        }

        .fc-view-harness {
            overflow: hidden;
        }

        .fc-scroller {
            overflow: hidden !important;
        }

        /* Ensure calendar content stays within bounds */
        .fc-daygrid-day-frame {
            min-height: 80px !important;
            max-height: 100px !important;
        }

        .fc-daygrid-day-events {
            min-height: 0 !important;
            max-height: 80px !important;
            overflow: hidden !important;
        }

        .fc-daygrid-more-link {
            font-size: 0.8rem !important;
            padding: 1px 4px !important;
        }

        /* Fix calendar header spacing */
        .fc-header-toolbar {
            margin-bottom: 16px;
            padding: 0 0 16px 0;
        }

        .fc-toolbar-title {
            font-size: 1.2rem !important;
            font-weight: 600 !important;
            color: var(--primary-color) !important;
        }

        /* Add spacing between navigation and view buttons */
        .fc-prev-button,
        .fc-next-button {
            margin-right: 8px !important;
        }

        .fc-today-button {
            margin-right: 16px !important;
        }

        .fc-dayGridMonth-button,
        .fc-timeGridWeek-button {
            margin-left: 8px !important;
        }

        /* Ensure proper button spacing in header */
        .fc-toolbar-chunk {
            display: flex !important;
            align-items: center !important;
            gap: 8px !important;
        }

        .fc-toolbar-chunk:last-child {
            gap: 4px !important;
        }

        .fc {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        .fc-header-toolbar {
            margin-bottom: 16px;
        }

        .fc-button {
            background: var(--primary-color) !important;
            border-color: var(--primary-color) !important;
            border-radius: 6px !important;
            font-weight: 500 !important;
            padding: 6px 12px !important;
            font-size: 0.9rem !important;
        }

        .fc-button:hover {
            background: var(--secondary-color) !important;
            border-color: var(--secondary-color) !important;
        }

        .fc-button:focus {
            box-shadow: 0 0 0 3px rgba(93, 14, 38, 0.2) !important;
        }

        .fc-daygrid-day {
            min-height: 80px !important;
        }

        .fc-event {
            border-radius: 4px !important;
            font-size: 0.85rem !important;
            padding: 2px 4px !important;
        }

        .table-container {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-top: 24px;
            box-shadow: 0 2px 12px rgba(93, 14, 38, 0.08);
            border: 1px solid #f0f0f0;
        }

        .table-header {
            margin-bottom: 20px;
        }

        .table-title {
            font-size: 1.4rem;
            font-weight: 600;
            color: var(--primary-color);
            margin: 0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }

        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #f0f0f0;
        }

        th {
            background: #f8f9fa;
            color: var(--primary-color);
            font-weight: 600;
            font-size: 0.9rem;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
            display: inline-block;
        }

        .status-upcoming {
            background: var(--primary-color);
            color: white;
        }

        .btn-info {
            background: var(--accent-color);
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-info:hover {
            background: var(--secondary-color);
            transform: translateY(-1px);
        }

        .event-info {
            display: grid;
            gap: 20px;
        }

        .info-group {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #e9ecef;
        }

        .info-group h3 {
            margin-bottom: 16px;
            color: var(--primary-color);
            font-size: 1.1rem;
            font-weight: 600;
        }

        .info-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 12px;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }

        .info-item:last-child {
            margin-bottom: 0;
            border-bottom: none;
        }

        .label {
            color: #666;
            font-weight: 500;
            font-size: 0.9rem;
        }

        .value {
            color: var(--text-color);
            font-weight: 500;
            text-align: right;
        }

        @media (max-width: 768px) {
            .action-buttons {
                flex-direction: column;
                gap: 16px;
                align-items: stretch;
            }

            .calendar-views {
                justify-content: center;
            }

            .search-box {
                width: 100%;
            }

            .search-box input {
                width: 100%;
            }

            .info-item {
                flex-direction: column;
                gap: 4px;
                text-align: left;
            }

            .value {
                text-align: left;
            }

            #calendar {
                max-height: 400px;
            }
        }
    </style>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Replace hardcoded events with PHP-generated events
            var calendarEl = document.getElementById('calendar');
            var calendar = new FullCalendar.Calendar(calendarEl, {
                initialView: 'dayGridMonth',
                height: 550,
                width: '100%',
                headerToolbar: {
                    left: 'prev,next today',
                    center: 'title',
                    right: 'dayGridMonth,timeGridWeek'
                },
                buttonText: {
                    today: 'Today',
                    month: 'Month',
                    week: 'Week'
                },
                dayMaxEvents: 3,
                moreLinkClick: 'popover',
                events: [
                    <?php foreach ($events as $ev): ?>
                    {
                        title: '<?= addslashes($ev['type']) ?>: <?= addslashes($ev['case_title'] ?? '') ?>',
                        start: '<?= $ev['date'] . 'T' . $ev['time'] ?>',
                        description: '<?= addslashes($ev['description'] ?? '') ?>',
                        location: '<?= addslashes($ev['location'] ?? '') ?>',
                        case: '<?= addslashes($ev['case_title'] ?? '') ?>',
                        attorney: '<?= addslashes($ev['attorney_name'] ?? '') ?>',
                        color: '<?= $ev['type'] === 'Hearing' ? '#dc3545' : '#28a745' ?>',
                        textColor: 'white',
                        borderColor: '<?= $ev['type'] === 'Hearing' ? '#dc3545' : '#28a745' ?>'
                    },
                    <?php endforeach; ?>
                ],
                eventClick: function(info) {
                    // Fill modal with event details
                    document.getElementById('modalType').innerText = info.event.title.split(':')[0] || '';
                    document.getElementById('modalDate').innerText = info.event.start ? info.event.start.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }) : '';
                    document.getElementById('modalTime').innerText = info.event.start ? info.event.start.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '';
                    document.getElementById('modalLocation').innerText = info.event.extendedProps.location || '';
                    document.getElementById('modalCase').innerText = info.event.extendedProps.case || '';
                    document.getElementById('modalAttorney').innerText = info.event.extendedProps.attorney || '';
                    document.getElementById('modalDescription').innerText = info.event.extendedProps.description || '';
                    document.getElementById('eventModal').style.display = "block";
                }
            });
            calendar.render();

            // Calendar view switching
            document.querySelectorAll('.calendar-views .btn').forEach(button => {
                button.addEventListener('click', function() {
                    document.querySelectorAll('.calendar-views .btn').forEach(btn => {
                        btn.classList.remove('active');
                    });
                    this.classList.add('active');
                    
                    const view = this.dataset.view;
                    calendar.changeView(view === 'month' ? 'dayGridMonth' : 'timeGridWeek');
                    
                    // Update button states
                    document.querySelectorAll('.calendar-views .btn').forEach(btn => {
                        btn.classList.remove('active');
                    });
                    this.classList.add('active');
                });
            });

            // Modal functionality
            const modal = document.getElementById('eventModal');
            const closeModal = document.querySelector('.close-modal');
            const closeEventModal = document.getElementById('closeEventModal');

            // Add click event to calendar events
            calendar.on('eventClick', function(info) {
                // Fill modal with event details
                document.getElementById('modalType').innerText = info.event.extendedProps.type || info.event.title.split(':')[0] || '';
                document.getElementById('modalDate').innerText = info.event.start ? info.event.start.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }) : '';
                document.getElementById('modalTime').innerText = info.event.start ? info.event.start.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '';
                document.getElementById('modalLocation').innerText = info.event.extendedProps.location || '';
                document.getElementById('modalCase').innerText = info.event.extendedProps.case || '';
                document.getElementById('modalAttorney').innerText = info.event.extendedProps.attorney || '';
                document.getElementById('modalDescription').innerText = info.event.extendedProps.description || '';
                document.getElementById('eventModal').style.display = "block";
            });

            closeModal.onclick = function() {
                modal.style.display = "none";
            }

            closeEventModal.onclick = function() {
                modal.style.display = "none";
            }

            window.onclick = function(event) {
                if (event.target == modal) {
                    modal.style.display = "none";
                }
            }

            // Populate event table with PHP events
            document.querySelectorAll('.view-info-btn').forEach(function(btn) {
                btn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    document.getElementById('modalType').innerText = this.dataset.type || '';
                    document.getElementById('modalDate').innerText = this.dataset.date || '';
                    document.getElementById('modalTime').innerText = this.dataset.time ? new Date('1970-01-01T' + this.dataset.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
                    document.getElementById('modalLocation').innerText = this.dataset.location || '';
                    document.getElementById('modalCase').innerText = this.dataset.case || '';
                    document.getElementById('modalAttorney').innerText = this.dataset.attorney || '';
                    document.getElementById('modalDescription').innerText = this.dataset.description || '';
                    document.getElementById('eventModal').style.display = "block";
                });
            });
        });
        
        // Profile Dropdown Functions
        function toggleProfileDropdown() {
            const dropdown = document.getElementById('profileDropdown');
            dropdown.classList.toggle('show');
        }
        
        function editProfile() {
            document.getElementById('editProfileModal').style.display = 'block';
            // Close dropdown when opening modal
            document.getElementById('profileDropdown').classList.remove('show');
        }

        function closeEditProfileModal() {
            document.getElementById('editProfileModal').style.display = 'none';
        }
        
        // Close dropdown when clicking outside
        window.onclick = function(event) {
            if (!event.target.matches('img') && !event.target.closest('.profile-dropdown')) {
                const dropdowns = document.getElementsByClassName('profile-dropdown-content');
                for (let dropdown of dropdowns) {
                    if (dropdown.classList.contains('show')) {
                        dropdown.classList.remove('show');
                    }
                }
            }
        }
    </script>
</body>
</html> 