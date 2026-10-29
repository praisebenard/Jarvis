<?php
$record_id = $_GET['record_id'];
$query = "SELECT * FROM records WHERE id = ?";
$statement = $db->prepare($query);
$statement->bind_param("i", $record_id);
$statement->execute();
