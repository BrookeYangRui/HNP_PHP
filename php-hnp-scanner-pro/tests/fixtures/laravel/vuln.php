<?php
$host = $_SERVER['HTTP_HOST'];
$url = "https://" . $host . "/reset?token=" . $_GET['t'];
header("Location: " . $url);

