<?php
function escape_sql_value($value) {
    return mysqli_real_escape_string($db, $value);
}
$name = $_GET['name'];
$escaped_name = escape_sql_value($name);
$query = "SELECT * FROM records WHERE name='" . $escaped_name . "'";
mysqli_query($db, $query);
