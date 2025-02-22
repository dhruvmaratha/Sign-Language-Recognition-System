<?php
session_start();
include("connect.php"); 

if (isset($_POST['submit'])) {
    $user_input = mysqli_real_escape_string($conn, $_POST['user_input']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);

    if (empty($user_input) || empty($password)) {
        echo '<script>alert("All fields are required!"); window.location.href = "login.php";</script>';
        exit();
    }

    if (filter_var($user_input, FILTER_VALIDATE_EMAIL)) {
        $sql = "SELECT id, name, password FROM users WHERE email = ?";
    } elseif (preg_match("/^[1-9][0-9]{9}$/", $user_input)) {
        $sql = "SELECT id, name, password FROM users WHERE phone = ?";
    } else {
        echo '<script>alert("Invalid email or phone format!"); window.location.href = "login.php";</script>';
        exit();
    }

    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $user_input);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    if ($row = mysqli_fetch_assoc($result)) {
        if (password_verify($password, $row['password'])) {
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['user_name'] = $row['name'];
            echo '<script>alert("Login successful!"); window.location.href = "dashboard.php";</script>';
        } else {
            echo '<script>alert("Incorrect password!"); window.location.href = "login.php";</script>';
        }
    } else {
        echo '<script>alert("No account found with this email or phone number!"); window.location.href = "login.php";</script>';
    }

    mysqli_stmt_close($stmt);
    mysqli_close($conn);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f4f4f4;
        }
        .login-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 400px;
        }
        .form-group {
            display: flex;
            flex-direction: column;
            margin-bottom: 15px;
        }
        label {
            margin-bottom: 5px;
            font-weight: bold;
        }
        input {
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .error {
            border-color: red;
        }
        .error-message {
            color: red;
            font-size: 12px;
            display: none;
        }
        button {
            width: 100%;
            padding: 10px;
            background: blue;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login</h2>
        <form action="login.php" method="POST">
    <div class="form-group">
        <label for="user_input">Email or Phone Number</label>
        <input type="text" name="user_input" required>
    </div>
    <div class="form-group">
        <label for="password">Password</label>
        <input type="password" name="password" required>
    </div>
    <button type="submit" name="submit">Login</button>
</form>


    <script>
        function validatePhone() {
            const phoneField = document.getElementById("phone");
            const phoneError = document.getElementById("phone-error");
            const phoneValue = phoneField.value;
            const phoneRegex = /^[1-9][0-9]{9}$/;
            if (!phoneRegex.test(phoneValue)) {
                phoneField.classList.add("error");
                phoneError.style.display = "block";
            } else {
                phoneField.classList.remove("error");
                phoneError.style.display = "none";
            }
        }

        function login() {
            let isValid = true;
            const fields = ["phone", "password"];
            fields.forEach(id => {
                const field = document.getElementById(id);
                const errorMessage = document.getElementById(id + "-error");
                if (!field.value.trim()) {
                    field.classList.add("error");
                    errorMessage.style.display = "block";
                    isValid = false;
                } else {
                    field.classList.remove("error");
                    errorMessage.style.display = "none";
                }
            });
            
            if (isValid) {
                alert("Login successful!");
            }
        }
    </script>
</body>
</html>
