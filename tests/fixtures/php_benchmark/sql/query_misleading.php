<?php
$user_input = 'local constant';
$query = "SELECT * FROM records WHERE id=" . $user_input;
mysqli_query($db, $query);
