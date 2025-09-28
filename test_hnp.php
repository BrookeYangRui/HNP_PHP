<?php
/**
 * HNP Test File - Verify final version of HNP scanner
 */

// Taint source tests
$host = $_SERVER['HTTP_HOST'];
$serverName = $_SERVER['SERVER_NAME'];
$forwardedHost = $_SERVER['HTTP_X_FORWARDED_HOST'];

// Redirect attack tests
header('Location: https://' . $host . '/redirect');
header('Location: http://' . $serverName . '/login');

// CORS misconfiguration tests
header('Access-Control-Allow-Origin: https://' . $host);

// Cookie domain pollution tests
setcookie('session', 'value', 0, '/', $host);

// Absolute URL construction tests
$absoluteUrl = 'https://' . $host . '/api/endpoint';

// Safe practices example
$allowedHosts = ['example.com', 'www.example.com'];
if (in_array($host, $allowedHosts, true)) {
    header('Location: https://' . $host . '/safe-redirect');
} else {
    header('Location: https://example.com/default');
}
