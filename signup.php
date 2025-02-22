<?php
include("connect.php");

if (isset($_POST['submit'])) {
    $name = mysqli_real_escape_string($conn, $_POST['name']);
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $phone = mysqli_real_escape_string($conn, $_POST['phone']);
    $dob = mysqli_real_escape_string($conn, $_POST['dob']);
    $sex = mysqli_real_escape_string($conn, $_POST['sex']);
    $disability = mysqli_real_escape_string($conn, $_POST['disability']);
    $disabilityPercentage = isset($_POST['disabilityPercentage']) ? $_POST['disabilityPercentage'] : "";
    $disabilityType = isset($_POST['disabilityType']) ? $_POST['disabilityType'] : "";
    $address = mysqli_real_escape_string($conn, $_POST['address']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);
    $cpassword = mysqli_real_escape_string($conn, $_POST['cpassword']);

    if (empty($name) || empty($email) || empty($phone) || empty($dob) || empty($sex) || empty($address) || empty($password) || empty($cpassword)) {
        echo '<script>alert("All fields are required!"); window.location.href = "signup.php";</script>';
        exit();
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo '<script>alert("Invalid email format!"); window.location.href = "signup.php";</script>';
        exit();
    }

    if (!preg_match("/^[1-9][0-9]{9}$/", $phone)) {
        echo '<script>alert("Invalid phone number! Must be 10 digits and not start with 0."); window.location.href = "signup.php";</script>';
        exit();
    }

    if ($password !== $cpassword) {
        echo '<script>alert("Passwords do not match!"); window.location.href = "signup.php";</script>';
        exit();
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);

    $checkQuery = "SELECT id FROM users WHERE email = ? OR phone = ?";
    $stmt = mysqli_prepare($conn, $checkQuery);
    mysqli_stmt_bind_param($stmt, "ss", $email, $phone);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    if (mysqli_stmt_num_rows($stmt) > 0) {
        echo '<script>alert("Email or phone number already registered!"); window.location.href = "signup.php";</script>';
        exit();
    }
    mysqli_stmt_close($stmt);

    $sql = "INSERT INTO users (name, email, phone, dob, sex, disability, disabilityPercentage, disabilityType, address, password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "ssssssssss", $name, $email, $phone, $dob, $sex, $disability, $disabilityPercentage, $disabilityType, $address, $hash);

    if (mysqli_stmt_execute($stmt)) {
        echo '<script>alert("Registration successful!"); window.location.href = "login.php";</script>';
    } else {
        echo '<script>alert("Error: ' . mysqli_error($conn) . '"); window.location.href = "signup.php";</script>';
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
    <title>Sign Up Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f4f4f4;
        }
        .signup-container {
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
        input, select {
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
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
        button:hover {
            background: darkblue;
        }
    </style>
</head>
<body>
    <div class="signup-container">
        <h2>Sign Up</h2>
        <form action="signup.php" method="POST">
            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="phone">Phone Number</label>
                <input type="text" name="phone" required maxlength="10">
            </div>
            <div class="form-group">
                <label for="dob">Date of Birth</label>
                <input type="date" name="dob" required>
            </div>
            <div class="form-group">
                <label for="sex">Sex</label>
                <select name="sex" required>
                    <option value="">Select</option>
                    <option value="male">Male</option>
                    <option value="female">Female</option>
                    <option value="other">Other</option>
                </select>
            </div>
            <div class="form-group">
                <label for="disability">Do you have a disability?</label>
                <select name="disability" id="disability" onchange="toggleDisabilityFields()">
                    <option value="no">No</option>
                    <option value="yes">Yes</option>
                </select>
            </div>
            <div class="form-group" id="disabilityFields" style="display: none;">
                <label for="disabilityType">Type of Disability</label>
                <select name="disabilityType">
                    <option value="">Select</option>
                    <option value="visual">Visual Impairment</option>
                    <option value="hearing">Hearing Impairment</option>
                    <option value="mobility">Mobility Impairment</option>
                    <option value="cognitive">Cognitive Disability</option>
                </select>
                <br>
                <label for="disabilityPercentage">Disability Percentage</label>
                <input type="number" name="disabilityPercentage" min="0" max="100">
            </div>
            <div class="form-group">
                <label for="address">Address</label>
                <input type="text" name="address" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="cpassword">Confirm Password</label>
                <input type="password" name="cpassword" required>
            </div>
            <button type="submit" name="submit">Sign Up</button>
        </form>
    </div>
    <script>
        function toggleDisabilityFields() {
            const disability = document.getElementById("disability").value;
            document.getElementById("disabilityFields").style.display = disability === "yes" ? "block" : "none";
        }
    </script>
</body>
</html>
