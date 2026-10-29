<?php
$raw_path = $_GET['path'];
$path = $raw_path;
$name = basename($path);
$contents = file_get_contents($name);
