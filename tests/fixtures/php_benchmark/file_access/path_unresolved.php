<?php
$path = $_GET['path'];
$candidate = build_path($path);
$contents = file_get_contents($candidate);
