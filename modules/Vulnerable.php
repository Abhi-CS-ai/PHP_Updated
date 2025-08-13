<?php

$username = $_GET['user'];  // Source
$id = $_POST['id'];        // Source

echo "<h1>Welcome " . $username . "</h1>"; // XSS Sink

$query = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $query); // SQLi Sink

?>