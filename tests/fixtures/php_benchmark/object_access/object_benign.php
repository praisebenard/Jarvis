<?php
$search = $_GET['search'];
$query = "SELECT * FROM documents WHERE title='fixed'";
mysqli_query($db, $query);
