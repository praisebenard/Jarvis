<?php
$document_id = $_GET['document_id'];
$query = "SELECT * FROM documents WHERE id=" . $document_id;
mysqli_query($db, $query);
