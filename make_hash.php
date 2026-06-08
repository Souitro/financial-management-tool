<?php
// make_hash.php — Dev Utility Tool for Argon2id generation
header('Content-Type: text/plain');

$passwordToHash = 'Admin@Souitro1'; 
$generatedHash  = password_hash($passwordToHash, PASSWORD_ARGON2ID);

echo "Plaintext: " . $passwordToHash . "\n";
echo "Argon2id Hash: " . $generatedHash . "\n\n";
echo "Copy-paste the Hash directly into your users table query script configuration!";