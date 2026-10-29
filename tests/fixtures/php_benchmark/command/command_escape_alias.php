<?php
$raw_argument = $_GET['argument'];
$argument = $raw_argument;
$escaped = escapeshellarg($argument);
$command = 'tool ' . $escaped;
$result = shell_exec($command);
