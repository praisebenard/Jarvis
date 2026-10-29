<?php
$document_id = '42';
$query = "SELECT * FROM documents WHERE id=" . $document_id;
mysqli_query($db, $query);
