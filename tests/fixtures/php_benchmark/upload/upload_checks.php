<?php
$extension = pathinfo($_FILES['document']['name'], PATHINFO_EXTENSION);
$mime = mime_content_type($_FILES['document']['tmp_name']);
if ($extension === 'pdf' && $mime === 'application/pdf') {
    if ($_FILES['document']['error'] === UPLOAD_ERR_OK && $_FILES['document']['size'] <= 2000000) {
        move_uploaded_file($_FILES['document']['tmp_name'], '/srv/uploads/document.pdf');
    }
}
