<?php
$url = $_GET['url'];
if (filter_var($url, FILTER_VALIDATE_URL)) {
    $body = file_get_contents($url);
}
