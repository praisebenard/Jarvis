<?php
$filter = $_GET['filter'];
$query = build_query($filter);
mysqli_query($db, $query);
