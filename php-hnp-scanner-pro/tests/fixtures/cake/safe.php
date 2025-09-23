<?php
\Cake\Routing\Router::fullBaseUrl('https://example.com');
$url = 'https://example.com/callback';
header('Location: ' . $url);

