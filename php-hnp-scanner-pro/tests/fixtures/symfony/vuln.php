<?php
$req = new stdClass();
$req->host = $_SERVER['HTTP_HOST'];
$url = 'https://' . $req->host . '/verify?token=' . $_GET['t'];
header('Location: ' . $url);

