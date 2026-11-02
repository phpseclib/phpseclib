<?php

/**
 * Answers one HTTP request for X509Test's URL fetch tests
 *
 * Prints the port it listens on, then answers the way $argv[1] says:
 *
 * - "trickle" sends a status line and then a byte every 0.2 seconds for 5 seconds
 * - "large" sends a 64 KB body, so the whole response is just over 64 KB
 * - "error" sends a 404 status line and then nothing for 5 seconds
 * - "keepalive" sends a 5 byte body, and then keeps the connection open for 5 seconds
 *   unless the request asked to close it
 * - "pause" sends a 1500 byte response, then waits a second before closing the connection
 * - "late" waits a second, then sends a 5 byte body
 * - "host" sends the request's Host header as the body
 */

declare(strict_types=1);

$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if (!$server) {
    fwrite(STDERR, "$errstr\n");
    exit(1);
}
$name = stream_socket_get_name($server, false);
fwrite(STDOUT, substr($name, strrpos($name, ':') + 1) . "\n");

$conn = stream_socket_accept($server, 30);
if (!$conn) {
    exit(1);
}
$request = '';
while (($line = fgets($conn)) !== false && $line != "\r\n") {
    $request .= $line;
}

// the client may hang up part way through
switch ($argv[1]) {
    case 'trickle':
        fwrite($conn, "HTTP/1.0 200 OK\r\n");
        for ($i = 0; $i < 25; $i++) {
            usleep(200000);
            @fwrite($conn, 'a');
        }
        break;
    case 'large':
        @fwrite($conn, "HTTP/1.0 200 OK\r\nContent-Type: application/pkix-cert\r\n\r\n" . str_repeat('a', 65536));
        break;
    case 'error':
        fwrite($conn, "HTTP/1.0 404 Not Found\r\n");
        sleep(5);
        break;
    case 'keepalive':
        fwrite($conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        if (stripos($request, "\r\nConnection: close\r\n") === false) {
            sleep(5);
        }
        break;
    case 'pause':
        fwrite($conn, "HTTP/1.0 200 OK\r\n\r\n" . str_repeat('a', 1481));
        sleep(1);
        break;
    case 'late':
        sleep(1);
        fwrite($conn, "HTTP/1.0 200 OK\r\n\r\nhello");
        break;
    case 'host':
        preg_match('/^Host: ([^\r\n]*)/mi', $request, $matches);
        fwrite($conn, "HTTP/1.0 200 OK\r\n\r\n" . ($matches[1] ?? ''));
}
fclose($conn);
