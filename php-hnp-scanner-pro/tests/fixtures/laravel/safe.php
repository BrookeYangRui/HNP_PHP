<?php
define('APP_URL', 'https://example.com');
$url = 'https://example.com/reset?token=' . $_GET['t'];
header('Location: ' . $url);

