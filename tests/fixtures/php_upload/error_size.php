<?php
if ($_FILES['photo']['error'] === UPLOAD_ERR_OK && $_FILES['photo']['size'] <= 2000000) {
    move_uploaded_file($_FILES['photo']['tmp_name'], '/srv/uploads/photo.bin');
}
