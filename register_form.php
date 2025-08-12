<?php
session_start();
@include 'config.php';

// Handle closing OTP modal
if (isset($_POST['close_otp_modal'])) {
    unset($_SESSION['show_otp_modal']);
    unset($_SESSION['pending_registration']);
    exit();
}

// Handle OTP verification
if (isset($_POST['verify_otp']) && isset($_SESSION['pending_registration'])) {
    $input_otp = $_POST['otp'] ?? '';
    $pending = $_SESSION['pending_registration'];
    
    if (time() > $pending['otp_expires']) {
        $_SESSION['error'] = 'OTP expired. Please register again.';
        unset($_SESSION['pending_registration']);
        unset($_SESSION['show_otp_modal']);
    } elseif ($input_otp == $pending['otp']) {
        // Insert user
        $hashed_password = password_hash($pending['password'], PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO user_form(name, email, phone_number, password, user_type) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param('sssss', $pending['name'], $pending['email'], $pending['phone'], $hashed_password, $pending['user_type']);
        if ($stmt->execute()) {
            unset($_SESSION['pending_registration']);
            unset($_SESSION['show_otp_modal']);
            $_SESSION['success'] = 'Registration successful! You can now login.';
            header('Location: login_form.php');
            exit();
        } else {
            $_SESSION['error'] = 'Registration failed. Please try again.';
        }
    } else {
        $_SESSION['error'] = 'Invalid OTP. Please check your email and try again.';
    }
}

// Handle registration form submission
if (isset($_POST['submit'])) {
    $lastname = mysqli_real_escape_string($conn, $_POST['lastname']);
    $firstname = mysqli_real_escape_string($conn, $_POST['firstname']);
    $middlename = mysqli_real_escape_string($conn, $_POST['middlename']);
    $name = trim($lastname . ', ' . $firstname . ' ' . $middlename); // Format: Lastname, Firstname Middlename
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $phone = mysqli_real_escape_string($conn, $_POST['phone']);
    $pass = $_POST['password'];
    $cpass = $_POST['cpassword'];
    $user_type = 'client'; // Only clients can register through this form

    // Phone number validation (server-side)
    if (!preg_match('/^\d{11}$/', $phone)) {
        $_SESSION['error'] = "Phone number must be exactly 11 digits.";
        header("Location: register_form.php");
        exit();
    }

    // Email must be @gmail.com only (server-side)
    if (!preg_match('/^[a-zA-Z0-9._%+-]+@gmail\.com$/', $email)) {
        $_SESSION['error'] = "Email address must be a valid @gmail.com address only.";
        header("Location: register_form.php");
        exit();
    }

    // Password requirements check (server-side)
    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@#*%])[A-Za-z\d_@#*%]{8,}$/', $pass)) {
        $_SESSION['error'] = "Password must be at least 8 characters, include uppercase and lowercase letters, at least one number, and at least one special character (_ @ # * %).";
        header("Location: register_form.php");
        exit();
    }

    // Password match check
    if ($pass != $cpass) {
        $_SESSION['error'] = "Passwords do not match!";
        header("Location: register_form.php");
        exit();
    }

    // Check if user already exists (email only)
    $select = "SELECT * FROM user_form WHERE email = ?";
    $stmt = mysqli_prepare($conn, $select);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if (mysqli_num_rows($result) > 0) {
        $_SESSION['error'] = "User already exists!";
        header("Location: register_form.php");
        exit();
    }

    // OTP logic
    require_once __DIR__ . '/vendor/autoload.php';
    $otp = rand(100000, 999999);
    $_SESSION['pending_registration'] = [
        'name' => $name,
        'email' => $email,
        'phone' => $phone,
        'password' => $pass,
        'user_type' => $user_type,
        'otp' => $otp,
        'otp_expires' => time() + 300 // 5 minutes
    ];
    // Send OTP email
    require_once 'send_otp_email.php';
    send_otp_email($email, $otp);
    $_SESSION['show_otp_modal'] = true;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register Form</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Poppins', sans-serif;
        }

        body {
            display: flex;
            min-height: 100vh;
            background: #f5f5f5;
        }

        .left-container {
            width: 45%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            padding: 20px;
            position: relative;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.3);
        }

        .title-container {
            display: flex;
            align-items: center;
            position: absolute;
            top: 20px;
            left: 30px;
        }

        .title-container img {
            width: 45px;
            height: 45px;
            margin-right: 8px;
        }

        .title {
            font-size: 24px;
            font-weight: 600;
            color: #ffffff;
            letter-spacing: 1px;
        }

        .header-container {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 15px;
            gap: 6px;
            
        }

        .header-container img {
            width: 35px;
            height: 35px;
        }

        .law-office-title {
            margin-top: 50px;
            text-align: center;
            font-size: 32px;
            font-weight: 800;
            color: #ffffff;
            font-family: "Playfair Display", serif;
            letter-spacing: 1.8px;
            text-shadow: 0 3px 8px rgba(0, 0, 0, 0.5);
            line-height: 1.2;
        }

        .form-header {
            font-size: 22px;
            font-weight: 600;
            text-align: center;
            margin-bottom: 15px;
            color: #ffffff;
        }

        .form-container {
            width: 100%;
            max-width: 380px;
            margin: 0 auto;
        }

        .form-container label {
            font-size: 12px;
            font-weight: 500;
            display: block;
            margin: 8px 0 2px;
            color: #ffffff;
            text-align: left;
        }

        .form-container input, .form-container select {
            width: 100%;
            padding: 8px 10px;
            font-size: 13px;
            border: none;
            border-bottom: 2px solid rgba(255, 255, 255, 0.3);
            background: transparent;
            color: #ffffff;
            outline: none;
            transition: all 0.3s ease;
        }

        .form-container input:focus, .form-container select:focus {
            border-bottom: 2px solid #ffffff;
        }

        .form-container input::placeholder {
            color: rgba(255, 255, 255, 0.6);
        }

        .form-container select option {
            background: #5D0E26;
            color: #ffffff;
        }

        .password-container {
            position: relative;
            width: 100%;
        }

        .password-container i {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(255, 255, 255, 0.7);
            cursor: pointer;
            transition: color 0.3s ease;
        }

        .password-container i:hover {
            color: #ffffff;
        }

        .form-container .form-btn {
            background: #ffffff;
            color: #5D0E26;
            border: none;
            cursor: pointer;
            padding: 10px;
            font-size: 14px;
            font-weight: 600;
            width: 100%;
            margin-top: 15px;
            border-radius: 8px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .form-container .form-btn:hover {
            background: #f8f8f8;
            color: #8B1538;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
        }

        .right-container {
            width: 55%;
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            color: #5D0E26;
            text-align: center;
            padding: 20px;
            background: #ffffff;
            background-image: url('images/atty3.jpg');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            backdrop-filter: blur(5px);
            position: relative;
        }

        .right-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url('images/atty3.jpg');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            filter: blur(3px);
            z-index: -1;
        }

        .error-popup {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: #ff6b6b;
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            text-align: center;
            z-index: 1000;
            width: 90%;
            max-width: 400px;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                transform: translate(-50%, -20px);
                opacity: 0;
            }
            to {
                transform: translate(-50%, 0);
                opacity: 1;
            }
        }

        .error-popup p {
            margin: 0;
            font-size: 14px;
        }

        .error-popup button {
            background: white;
            border: none;
            padding: 8px 15px;
            color: #ff6b6b;
            font-weight: 500;
            margin-top: 10px;
            cursor: pointer;
            border-radius: 4px;
            transition: background 0.3s ease;
        }

        .error-popup button:hover {
            background: #f0f0f0;
        }

        .login-box h1 {
            font-size: 48px;
            font-weight: 700;
            color: #5D0E26;
            margin-bottom: 20px;
            line-height: 1.3;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            position: relative;
            overflow: hidden;
        }

        .mirror-shine {
            position: relative;
            display: inline-block;
            background: linear-gradient(
                90deg,
                #5D0E26 0%,
                #5D0E26 45%,
                #ffffff 50%,
                #5D0E26 55%,
                #5D0E26 100%
            );
            background-size: 200% 100%;
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: mirrorShine 3s ease-in-out infinite;
        }

        @keyframes mirrorShine {
            0% {
                background-position: -100% 0;
            }
            100% {
                background-position: 100% 0;
            }
        }

        .login-btn {
            display: inline-block;
            background: linear-gradient(135deg, #5D0E26, #8B1538);
            color: white;
            text-decoration: none;
            padding: 18px 40px;
            font-size: 20px;
            font-weight: 600;
            border-radius: 8px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(93, 14, 38, 0.4);
        }

        .login-btn:hover {
            background: linear-gradient(135deg, #8B1538, #5D0E26);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(93, 14, 38, 0.5);
        }

        @media (max-width: 1024px) {
            .left-container {
                width: 50%;
            }

            .right-container {
                width: 50%;
            }
        }

        @media (max-width: 768px) {
            body {
                flex-direction: column;
            }

            .left-container, .right-container {
                width: 100%;
                padding: 40px 20px;
            }

            .law-office-title {
                font-size: 34px;
            }

            .form-header {
                font-size: 24px;
            }

            .login-box h1 {
                font-size: 40px;
            }
        }

        @media (max-width: 480px) {
            .title {
                font-size: 20px;
            }

            .law-office-title {
                font-size: 28px;
            }

            .form-header {
                font-size: 22px;
            }

            .form-container input {
                font-size: 14px;
                padding: 10px 12px;
            }

            .form-container .form-btn {
                padding: 12px;
                font-size: 15px;
            }

            .login-box h1 {
                font-size: 32px;
            }

            .login-btn {
                padding: 16px 32px;
                font-size: 18px;
            }
        }
    </style>
</head>
<body>
    <?php if (isset($_SESSION['error'])): ?>
        <div class="error-popup">
            <p><?php echo $_SESSION['error']; ?></p>
            <button onclick="closePopup()">OK</button>
        </div>
        <?php unset($_SESSION['error']); ?>
    <?php endif; ?>

    <div class="left-container">
        <div class="title-container">
            <img src="images/logo.jpg" alt="Logo">
            <div class="title">LawFirm.</div>
        </div>

        <div class="header-container">
            <h1 class="law-office-title">Opiña Law<br>Office</h1>
            <img src="images/justice.png" alt="Attorney Icon">
        </div>

        <div class="form-container">
            <h2 class="form-header">Register</h2>

            <form action="" method="post">
                <label for="lastname">Name</label>
                <div style="display: flex; gap: 8px;">
                    <input type="text" name="lastname" id="lastname" required placeholder="Lastname" style="flex:1;">
                    <input type="text" name="firstname" id="firstname" required placeholder="Firstname" style="flex:1;">
                    <input type="text" name="middlename" id="middlename" placeholder="Middlename" style="flex:1;">
                </div>

                <label for="email">Email</label>
                <input type="email" name="email" id="email" required placeholder="Enter your email" pattern="^[a-zA-Z0-9._%+-]+@gmail\.com$" title="Email must be a valid @gmail.com address only">

                <label for="phone">Phone Number</label>
                <input type="text" name="phone" id="phone" required placeholder="Enter your phone number" maxlength="11" pattern="\d{11}" title="Phone number must be exactly 11 digits">

                <input type="hidden" name="user_type" value="client">

                <label for="password">Password</label>
                <div class="password-container">
                    <input type="password" name="password" id="password" required placeholder="Enter your password">
                    <i class="fas fa-eye" id="togglePassword"></i>
                </div>
                <ul style="color:#fff; font-size:12px; margin-bottom:8px; margin-top:2px; padding-left:18px;">
                    <li>Password requirements:</li>
                    <li>At least 8 characters</li>
                    <li>Must include uppercase and lowercase letters</li>
                    <li>Must include at least one number</li>
                    <li>Must include at least one special character (_ @ # * %)</li>
                </ul>

                <label for="cpassword">Confirm Password</label>
                <div class="password-container">
                    <input type="password" name="cpassword" id="cpassword" required placeholder="Confirm your password">
                    <i class="fas fa-eye" id="toggleCPassword"></i>
                </div>

                <input type="submit" name="submit" value="Register" class="form-btn">
            </form>
        </div>
    </div>

    <div class="right-container">
        <div class="login-box">
            <h1 class="mirror-shine">Already have an account?</h1>
        </div>
        <a href="login_form.php" class="login-btn">Login Now</a>
    </div>

    <script>
        document.getElementById('togglePassword').addEventListener('click', function () {
            let passwordField = document.getElementById('password');
            let icon = this;
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });

        document.getElementById('toggleCPassword').addEventListener('click', function () {
            let passwordField = document.getElementById('cpassword');
            let icon = this;
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            } else {
                passwordField.type = 'password';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            }
        });

        function closePopup() {
            document.querySelector('.error-popup').style.display = 'none';
        }

        // Password validation (client-side)
        document.querySelector('form').addEventListener('submit', function(e) {
            var pass = document.getElementById('password').value;
            var cpass = document.getElementById('cpassword').value;
            var requirements = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@#*%])[A-Za-z\d_@#*%]{8,}$/;
            if (!requirements.test(pass)) {
                alert('Password must be at least 8 characters, include uppercase and lowercase letters, at least one number, and at least one special character (_ @ # * %).');
                e.preventDefault();
                return false;
            }
            if (pass !== cpass) {
                alert('Confirm password does not match the password.');
                e.preventDefault();
                return false;
            }
        });

        // Limit phone input to 11 digits only (client-side)
        document.getElementById('phone').addEventListener('input', function(e) {
            this.value = this.value.replace(/[^\d]/g, '').slice(0, 11);
        });
    </script>

    <script src="https://kit.fontawesome.com/cc86d7b31d.js" crossorigin="anonymous"></script>

    <!-- OTP Verification Modal -->
    <?php if (isset($_SESSION['show_otp_modal']) && isset($_SESSION['pending_registration'])): ?>
    <div class="otp-modal" id="otpModal" style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(93, 14, 38, 0.8); display: flex; align-items: center; justify-content: center; z-index: 2000;">
        <div style="background: #fff; border-radius: 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3); padding: 40px 35px; max-width: 480px; width: 90%; position: relative; animation: slideIn 0.3s ease;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h2 style="color: #5D0E26; margin-bottom: 15px; font-size: 32px; font-weight: 700; font-family: 'Playfair Display', serif; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">Opiña Law Office</h2>
                <h3 style="color: #5D0E26; margin-bottom: 20px; font-size: 22px; font-weight: 600;">Verify Your Email</h3>
            </div>
            <div style="color: #666; margin-bottom: 25px; text-align: center; font-size: 15px; line-height: 1.5;">
                Enter the 6-digit OTP sent to<br><strong style="color: #5D0E26;"><?= htmlspecialchars($_SESSION['pending_registration']['email']) ?></strong>
            </div>
            
            <form method="post" style="margin-bottom: 20px;">
                <div style="margin-bottom: 25px;">
                    <input type="text" name="otp" maxlength="6" pattern="\d{6}" placeholder="Enter 6-digit OTP" required autofocus 
                           style="width: 100%; padding: 15px; font-size: 18px; border: 2px solid #e0e0e0; border-radius: 8px; outline: none; transition: all 0.3s ease; text-align: center; letter-spacing: 3px; font-weight: 600; background: #f9f9f9;"
                           onfocus="this.style.borderColor='#5D0E26'; this.style.background='#fff';"
                           onblur="this.style.borderColor='#e0e0e0'; this.style.background='#f9f9f9';">
                </div>
                <button type="submit" name="verify_otp" 
                        style="width: 100%; background: linear-gradient(135deg, #5D0E26, #8B1538); color: #fff; border: none; padding: 16px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(93, 14, 38, 0.4);"
                        onmouseover="this.style.background='linear-gradient(135deg, #8B1538, #5D0E26)'; this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 20px rgba(93, 14, 38, 0.5)';"
                        onmouseout="this.style.background='linear-gradient(135deg, #5D0E26, #8B1538)'; this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px rgba(93, 14, 38, 0.4)';">
                    Verify OTP
                </button>
            </form>
            
            <div style="text-align: center; margin-top: 20px;">
                <button onclick="closeOtpModal()" style="background: none; border: none; color: #5D0E26; text-decoration: none; font-size: 14px; font-weight: 500; cursor: pointer; padding: 5px;">
                    ← Back to Registration
                </button>
            </div>
        </div>
    </div>

    <script>
        function closeOtpModal() {
            document.getElementById('otpModal').style.display = 'none';
            // Clear the session flag via AJAX or reload the page
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'close_otp_modal=1'
            }).then(() => {
                window.location.reload();
            });
        }

        // Auto-focus on OTP input when modal appears
        document.addEventListener('DOMContentLoaded', function() {
            const otpInput = document.querySelector('input[name="otp"]');
            if (otpInput) {
                otpInput.focus();
            }
        });

        // Add animation keyframes
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: scale(0.9) translateY(-20px);
                }
                to {
                    opacity: 1;
                    transform: scale(1) translateY(0);
                }
            }
        `;
        document.head.appendChild(style);
    </script>
    <?php endif; ?>

</body>
</html>
