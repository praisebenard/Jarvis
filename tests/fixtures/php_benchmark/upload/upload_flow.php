<?php
$tmp = $_FILES['avatar']['tmp_name'];
move_uploaded_file($tmp, '/srv/uploads/avatar.bin');
