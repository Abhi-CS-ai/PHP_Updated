<?php
// -----------------------------------------
// 1. SQL Injection - INDIRECT (Unsafe)
$user_id = $_GET['id'];
$query = "SELECT * FROM accounts WHERE id = $user_id"; // Should be flagged
$result = mysqli_query($conn, $query);

// -----------------------------------------
// 2. SQL Injection - SAFE
$stmt = $pdo->prepare("SELECT * FROM accounts WHERE id = ?");
$stmt->execute([$user_id]); // Should NOT be flagged

// -----------------------------------------
// 3. XSS - INDIRECT (Unsafe)
function show($data) {
    echo $data; // Should be flagged if $data is from user input
}
$name = $_POST['name'];
show($name);

// -----------------------------------------
// 4. XSS - SAFE
$safe_name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');
show($safe_name); // Should NOT be flagged

// -----------------------------------------
// 5. File Inclusion - INDIRECT (Unsafe)
$page_var = $_GET['page'];
require_once($page_var); // Should be flagged

// -----------------------------------------
// 6. File Inclusion - SAFE
$whitelist = ['home.php', 'contact.php'];
if (in_array($_GET['page'], $whitelist)) {
    require_once($_GET['page']); // Should NOT be flagged
}

// -----------------------------------------
// 7. Command Injection - Wrapped in function (Unsafe)
function runCommand($cmd) {
    system($cmd); // Should be flagged if $cmd is from user input
}
$cmd = $_REQUEST['cmd'];
runCommand($cmd);

// -----------------------------------------
// 8. Insecure File Upload (Unsafe)
move_uploaded_file($_FILES['upfile']['tmp_name'], $_FILES['upfile']['name']); // Should be flagged

// -----------------------------------------
// 9. Insecure File Upload (SAFE)
$allowed = ['image/jpeg', 'image/png'];
if (in_array($_FILES['upfile']['type'], $allowed)) {
    move_uploaded_file($_FILES['upfile']['tmp_name'], basename($_FILES['upfile']['name'])); // Should NOT be flagged
}

// -----------------------------------------
// 10. Hardcoded Credentials (Unsafe)
$api_secret = "myhardcodedkey"; // Should be flagged

// -----------------------------------------
// 11. Insecure Cryptographic Storage (Unsafe)
$hash = sha1($password); // Should be flagged

// -----------------------------------------
// 12. Information Disclosure (Unsafe)
if ($_GET['debug'] === 'true') {
    phpinfo(); // Should be flagged
}

// -----------------------------------------
// 13. Compound Vulnerability (RCE Risk)
// Step 1: Upload without checks
move_uploaded_file($_FILES['payload']['tmp_name'], $_GET['upload_name']); // Upload part

// Step 2: Include the uploaded file
$file_to_include = $_GET['upload_name'];
include $file_to_include; // Inclusion part - should trigger "Remote Code Execution Risk"
?>
