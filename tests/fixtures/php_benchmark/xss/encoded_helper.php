<?php
function encode_html($value) {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
$message = $_GET['message'];
echo '<p>' . encode_html($message) . '</p>';
