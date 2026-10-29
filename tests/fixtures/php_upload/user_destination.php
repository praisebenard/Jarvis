<?php
$tmp = $_FILES['attachment']['tmp_name'];
$destination = '/srv/uploads/' . $_POST['name'];
move_uploaded_file($tmp, $destination);
