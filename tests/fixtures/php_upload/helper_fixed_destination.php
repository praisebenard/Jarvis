<?php
function validateUpload($file) {
    $extension = pathinfo($file, PATHINFO_EXTENSION);
    return $extension === 'png';
}
if (validateUpload($_FILES['image']['name'])) {
    move_uploaded_file($_FILES['image']['tmp_name'], '/srv/uploads/image.png');
}
