<?php
$request_id = $_GET['request_id'];
$query = "SELECT * FROM records";
mysqli_query($db, $query);
