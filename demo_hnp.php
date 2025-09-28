<?php
/**
 * HNP Demo - Demonstrates true taint tracking
 */

// Taint Source: $_SERVER['HTTP_HOST'] is marked as tainted
$host = $_SERVER['HTTP_HOST'];

// Taint Propagation: $url inherits taint from $host
$url = 'https://' . $host . '/api';

// Taint Propagation: $redirectUrl inherits taint from $url
$redirectUrl = $url . '/redirect';

// Taint Sink: header() with tainted data - VULNERABILITY DETECTED!
header('Location: ' . $redirectUrl);

// Another taint source
$serverName = $_SERVER['SERVER_NAME'];

// Taint Propagation through function call
function buildUrl($host, $path) {
    return 'https://' . $host . $path; // Returns tainted data
}

$apiUrl = buildUrl($serverName, '/api'); // $apiUrl is tainted

// Taint Sink: Another vulnerability
header('Location: ' . $apiUrl);

// Sanitizer example
$allowedHosts = ['example.com', 'www.example.com'];
if (in_array($host, $allowedHosts, true)) {
    // This is safe - taint is sanitized
    header('Location: https://' . $host . '/safe');
} else {
    // This is still vulnerable
    header('Location: https://' . $host . '/unsafe');
}
