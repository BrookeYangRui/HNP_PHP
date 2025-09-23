<?php
$h = $_SERVER['HTTP_HOST'];
$url = 'https://' . $h . '/callback';
header('Location: ' . $url);

