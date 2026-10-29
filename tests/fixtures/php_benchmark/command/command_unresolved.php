<?php
function build_command($value) {
    return assemble_command($value);
}
$input = $_GET['command'];
$result = shell_exec(build_command($input));
