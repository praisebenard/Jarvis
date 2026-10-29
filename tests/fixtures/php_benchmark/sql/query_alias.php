<?php
$raw_id = $_GET['record_id'];
$record_id = $raw_id;
$query = "SELECT * FROM records WHERE id=" . $record_id;
mysqli_query($db, $query);
