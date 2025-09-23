<?php
$url = 'https://example.com/verify?token=' . $_GET['t'];
header('Location: ' . $url);

