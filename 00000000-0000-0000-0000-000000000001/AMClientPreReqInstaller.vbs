' Functions
function readFromRegistry (strRegistryKey, strDefault )
    Dim WSHShell, value

    On Error Resume Next
    Set WSHShell = CreateObject("WScript.Shell")
    value = WSHShell.RegRead( strRegistryKey )

    if err.number <> 0 then
        readFromRegistry= strDefault
		err.clear
    else
        readFromRegistry=value
    end if

    set WSHShell = nothing
end function
function downloadFile (strURL, strPath)
	dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP") 
	dim bStrm: Set bStrm = createobject("Adodb.Stream") 
	xHttp.Open "GET", strURL, False 
	xHttp.Send 
	with bStrm 
		.type = 1 '//binary 
		.open 
		.write xHttp.responseBody 
		.savetofile strPath, 2 '//overwrite 
	end with 
end function


If UCase(Right(Wscript.FullName, 11)) = "WSCRIPT.EXE" Then
    Wscript.Stdout.Write "This script must be run under CScript."
    Wscript.Quit
End If


Wscript.Stdout.WriteLine "#####################################"
Wscript.Stdout.WriteLine "# AM Client Prerequisites Installer #"
Wscript.Stdout.WriteLine "#####################################"
'Wscript.Stdout.Write "Initializing..."

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set wshShell = CreateObject( "WScript.Shell" )
Set objScriptFile = objFSO.GetFile(Wscript.ScriptFullName)
strScriptFolder = objFSO.GetParentFolderName(objScriptFile) 
if not objFSO.FolderExists(strScriptFolder & "\redist") Then
		objFSO.CreateFolder(strScriptFolder & "\redist")
End If

set oEnv=WshShell.Environment("Process")
oEnv("SEE_MASK_NOZONECHECKS") = 1

If objFSO.FolderExists(wshShell.ExpandEnvironmentStrings("%systemroot%\syswow64")) Then
	strArch = "x64"
Else
	strArch = "x86"
End If

Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem")
for each objItem in colItems
	strOSVersion = objItem.Version
Next


'Wscript.Stdout.WriteLine "#####################################"
Wscript.Stdout.WriteLine  "OS version: " & strOSVersion
Wscript.Stdout.WriteLine "Architecture: " & strArch
Wscript.Stdout.WriteLine "#####################################"


Set colArgs = Wscript.Arguments.Named
If colArgs.Exists("DownloadOnly") Then	
	Wscript.Stdout.WriteLine "DownloadOnly detected, downloading but not installing prereqs"
	strFileName = strScriptFolder & "\redist\Windows6.0-KB968930-x86.msu"
	Wscript.Stdout.Write "Checking if " & Replace(strFileName,strScriptFolder,"") & " exists..."
	If Not objFSO.FileExists(strFileName) Then
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write Replace(strFileName,strScriptFolder,"") & " does not exists, downloading..."
		downloadFile "http://download.microsoft.com/download/F/9/E/F9EF6ACB-2BA8-4845-9C10-85FC4A69B207/Windows6.0-KB968930-x86.msu",strFileName
		If err.number = 0 Then 
			Wscript.StdOut.WriteLine "[OK]"
		Else
			Wscript.StdOut.WriteLine "[FAILED]"
			err.clear
		End If 
	Else 
		WScript.StdOut.WriteLine "[OK]"
	End If
	strFileName = strScriptFolder & "\redist\Windows6.0-KB968930-x64.msu"
	Wscript.Stdout.Write "Checking if " & Replace(strFileName,strScriptFolder,"") & " exists..."
	If Not objFSO.FileExists(strFileName) Then
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write Replace(strFileName,strScriptFolder,"") & " does not exists, downloading..."
		downloadFile "http://download.microsoft.com/download/3/C/8/3C8CF51E-1D9D-4DAA-AAEA-5C48D1CD055C/Windows6.0-KB968930-x64.msu", strFileName
		If err.number = 0 Then 
			Wscript.StdOut.WriteLine "[OK]"
		Else
			Wscript.StdOut.WriteLine "[FAILED]"
			err.clear
		End If
	Else
		Wscript.StdOut.WriteLine "[OK]"
	End If
	strFileName = strScriptFolder & "\redist\NDP451-KB2858728-x86-x64-AllOS-ENU.exe"
	Wscript.Stdout.Write "Checking if " & Replace(strFileName,strScriptFolder,"") & " exists..."
	If Not objFSO.FileExists(strFileName) Then
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write Replace(strFileName,strScriptFolder,"") & " does not exists, downloading..."
		downloadFile "http://download.microsoft.com/download/1/6/7/167F0D79-9317-48AE-AEDB-17120579F8E2/NDP451-KB2858728-x86-x64-AllOS-ENU.exe", strFileName
		If err.number = 0 Then 
			Wscript.StdOut.WriteLine "[OK]"
		Else
			Wscript.StdOut.WriteLine "[FAILED]"
			err.clear
		End If 
	Else
		Wscript.StdOut.WriteLine "[OK]"
	End If
	strFileName = strScriptFolder & "\redist\Windows6.0-KB2506146-x64.msu"
	Wscript.Stdout.Write "Checking if " & Replace(strFileName,strScriptFolder,"") & " exists..."
	If Not objFSO.FileExists(strFileName) Then
		WScript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write Replace(strFileName,strScriptFolder,"") & " does not exists, downloading..."
		downloadFile "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.0-KB2506146-x64.msu", strFileName
		If err.number = 0 Then 
			Wscript.StdOut.WriteLine "[OK]"
		Else
			Wscript.StdOut.WriteLine "[FAILED]"
			err.clear
		End If 
	Else
		Wscript.StdOut.WriteLine "[OK]"
	End If
	strFileName = strScriptFolder & "\redist\Windows6.0-KB2506146-x64.msu"
	Wscript.Stdout.Write "Checking if " & Replace(strFileName,strScriptFolder,"") & " exists..."
	If Not objFSO.FileExists(strFileName) Then
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write Replace(strFileName,strScriptFolder,"") & " does not exists, downloading..."
		downloadFile "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.0-KB2506146-x86.msu", strFileName
		If err.number = 0 Then 
			Wscript.StdOut.WriteLine "[OK]"
		Else
			Wscript.StdOut.WriteLine "[FAILED]"
			err.clear
		End If 
	Else 
		WScript.StdOut.WriteLine "[OK]"
	End If

	strFileName = strScriptFolder & "\redist\Windows6.1-KB2506143-x64.msu"
	Wscript.Stdout.Write "Checking if " & Replace(strFileName,strScriptFolder,"") & " exists..."
	If Not objFSO.FileExists(strFileName) Then
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write Replace(strFileName,strScriptFolder,"") & " does not exists, downloading..."
		downloadFile "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-x64.msu", strFileName
		If err.number = 0 Then 
			Wscript.StdOut.WriteLine "[OK]"
		Else
			Wscript.StdOut.WriteLine "[FAILED]"
			err.clear
		End If 
	Else 
		WScript.StdOut.WriteLine "[OK]"
	End If
	strFileName = strScriptFolder & "\redist\Windows6.1-KB2506143-x86.msu"
	Wscript.Stdout.Write "Checking if " & Replace(strFileName,strScriptFolder,"") & " exists..."
	If Not objFSO.FileExists(strFileName) Then
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write Replace(strFileName,strScriptFolder,"") & " does not exists, downloading..."
		downloadFile "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-x86.msu", strFileName
		If err.number = 0 Then 
			Wscript.StdOut.WriteLine "[OK]"
		Else
			Wscript.StdOut.WriteLine "[FAILED]"
			err.clear
		End If 
	Else 
		WScript.StdOut.WriteLine "[OK]"
	End If
	Wscript.Quit(2)
End If 



' Posh2 installation on 2008/Vista
If Left(strOSVersion,3) = "6.0" Then 
	Wscript.Stdout.Write "Checking Powershell 2 installation..."
	strPosh2 = readFromRegistry("HKEY_LOCAL_MACHINE\Software\Microsoft\Powershell\1\PowershellEngine\PowerShellVersion","N/A")
	strMSUFileName = strScriptFolder & "\redist\Windows6.0-KB968930-" & strArch & ".msu"
	
	If strPosh2 = "N/A" Or strPosh2 = "1.0" Then
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.Write "Powershell 2 not found, looking for installer..."
		If Not objFSO.FileExists(strMSUFileName) Then		
			Wscript.Stdout.WriteLine "[FAILED]"
			Wscript.StdOut.Write "Could not find installer, attempting to download it from microsoft..."
			If strArch = "x86" Then
				downloadFile "http://download.microsoft.com/download/F/9/E/F9EF6ACB-2BA8-4845-9C10-85FC4A69B207/Windows6.0-KB968930-x86.msu",strMSUFileName
			Else
				downloadFile "http://download.microsoft.com/download/3/C/8/3C8CF51E-1D9D-4DAA-AAEA-5C48D1CD055C/Windows6.0-KB968930-x64.msu",strMSUFileName
			End If			
		End If		
		If err.number = 0 then
			Wscript.StdOut.WriteLine "[OK]"
			Wscript.Stdout.Write "Installing " & Chr(34) & Replace(strMSUFileName,strScriptFolder,"") & Chr(34) & "..."
			wshShell.Run "wusa.exe " & Chr(34) & strMSUFileName & Chr(34) & " /quiet /norestart",1,True
			If err.number <> 0 then
				Wscript.StdOut.WriteLine "[FAILED]"
				Wscript.Stdout.WriteLine "Installation of "& Replace(strMSUFileName,strScriptFolder,"") & " failed with exitcode:" & err.number
				err.clear
			Else
				Wscript.StdOut.WriteLine "[OK]"
				'Wscript.Stdout.Write "Installation of " & strMSUFileName & " succeeded"
				' Reboot the system and schedule this script to run during startup
				WshShell.RegWrite "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\AMClient", Chr(34) & wshShell.ExpandEnvironmentStrings("%windir%\system32\cscript.exe") & Chr(34) & " //nologo " & Chr(34) & objScriptFile & Chr(34)
				intAnswer = Msgbox("Reboot is required before continuing installation, do you wish to reboot now?", vbYesNo, "Automation Machine Client")

				If intAnswer = vbYes Then
					wshShell.Run Chr(34) & wshShell.ExpandEnvironmentStrings("%systemroot%\system32\shutdown.exe") & Chr(34) & " /r /t 0"
				Else
					WScript.Quit(1)
				End If
				'wshShell.Run Chr(34) & wshShell.ExpandEnvironmentStrings("%systemroot%\system32\schtasks.exe") & Chr(34) & " /create /f /tn AM-Initialize /sc ONSTART /tr " & Chr(34) & "%windir%\system32\cscript.exe" & Chr(34) & " //nologo " & Chr(34) & objScriptFile & Chr(34)
				
			End If
		Else 
			Wscript.StdOut.WriteLine "[FAILED]"
			Wscript.Stdout.WriteLine "Error downloading " & Replace(strMSUFileName,strScriptFolder,"") & ". Does this computer have access to the internet? Error reported:" & err.number
			err.clear
		End If
	Else
		Wscript.StdOut.Write "[OK]"
		'Wscript.Stdout.Write "Powershell 2 already installed"
	End If
End If


' .NET 4.5.1 installation
Wscript.Stdout.Write "Checking .NET 4.5.1 installation..."
dotNet451 = readFromRegistry("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SKUs\.NETFramework,Version=v4.5.1\","N/A")
If dotNet451 = "N/A" Then
	Wscript.StdOut.WriteLine "[FAILED]"
	Wscript.Stdout.Write ".NET 4.5.1 not found, looking for installer"
	strEXEFileName = strScriptFolder & "\redist\NDP451-KB2858728-x86-x64-AllOS-ENU.exe"
	If Not objFSO.FileExists(strEXEFileName) Then
			Wscript.Stdout.Write "Could not find installer, attempting to download it from microsoft..."
			downloadFile "http://download.microsoft.com/download/1/6/7/167F0D79-9317-48AE-AEDB-17120579F8E2/NDP451-KB2858728-x86-x64-AllOS-ENU.exe", strEXEFileName
	End If		
	If err.number = 0 then
		Wscript.StdOut.WriteLine "[OK]"
		Wscript.Stdout.Write "Installing " & Chr(34) & Replace(strEXEFileName,strScriptFolder,"") & Chr(34) & "..."
		wshShell.Run Chr(34) & strEXEFileName & Chr(34) & " /q /norestart",1,True
		If err.number <> 0 then
			Wscript.StdOut.WriteLine "[FAILED]"
			Wscript.Stdout.WriteLine "Installation of "& Replace(strEXEFileName,strScriptFolder,"") & " failed with exitcode:" & err.number
			err.clear
		Else
			Wscript.StdOut.WriteLine "[OK]"
			'Wscript.Stdout.Write "Installation of " & Replace(strExeFileName,strScriptFolder,"") & " succeeded"
			
			WshShell.RegWrite "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\AMClient", Chr(34) & wshShell.ExpandEnvironmentStrings("%windir%\system32\cscript.exe") & Chr(34) & " //nologo " & Chr(34) & objScriptFile & Chr(34)
			intAnswer = Msgbox("Reboot is required before continuing installation, do you wish to reboot now?", vbYesNo, "Automation Machine Client")

			If intAnswer = vbYes Then
				wshShell.Run Chr(34) & wshShell.ExpandEnvironmentStrings("%systemroot%\system32\shutdown.exe") & Chr(34) & " /r /t 0"
			Else
				WScript.Quit(1)
			End If
		End If
	Else 
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.WriteLine "Error downloading " & strEXEFileName & ". Does this computer have access to the internet? Error reported:" & err.number
		err.clear
	End If	
Else
	Wscript.StdOut.WriteLine "[OK]"
	'Wscript.Stdout.Write ".NET 4.5.1 already installed, skipping"
End If

' Posh 3 installation
Wscript.Stdout.Write "Checking Powershell 3 installation..."
strPosh3 = readFromRegistry("HKEY_LOCAL_MACHINE\Software\Microsoft\Powershell\3\PowershellEngine\PowerShellVersion","N/A")
If strPosh3 = "N/A" Then
	Wscript.StdOut.WriteLine "[FAILED]"
	Wscript.Stdout.Write "Powershell 3 not found, looking for installer..."
	If Left(strOSVersion,3) = "6.0" Then
		strMSUFileName = strScriptFolder & "\redist\Windows6.0-KB2506146-" & strArch & ".msu"
		
		If Not objFSO.FileExists(strMSUFileName) Then		
			Wscript.Stdout.Write "Could not find installer, attempting to download it from microsoft..."
			If strArch = "x64" Then
				strURL = "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.0-KB2506146-x64.msu"
			Else
				strURL = "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.0-KB2506146-x86.msu"
			End If
			downloadFile strURL,strMSUFileName
		Else
			Wscript.StdOut.WriteLine "[OK]"
		End If
	ElseIf Left(strOSVersion,3) = "6.1" Then 
		strMSUFileName = strScriptFolder & "\redist\Windows6.1-KB2506143-" & strArch & ".msu"
		If Not objFSO.FileExists(strMSUFileName) Then		
			Wscript.Stdout.Write "Could not find installer, attempting to download it from microsoft..."
			If strArch = "x64" Then
				strURL = "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-x64.msu"
			Else
				strURL = "http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-x86.msu"
			End If
			downloadFile strURL,strMSUFileName		
			WScript.StdOut.WriteLine "[OK]"
		End If
	Else 
		Wscript.StdOut.WriteLine "[FAILED]"
		Wscript.Stdout.WriteLine "This OS version is not supported by the AM Client prereq installer" 
	End If
	
	If err.number = 0 then
		WScript.StdOut.WriteLine "[OK]"
		Wscript.Stdout.Write "Installing " & Chr(34) & Replace(strMSUFileName,strScriptFolder,"") & Chr(34) & "..."
		'wshShell.Run "wusa.exe " & strMSUFileName & " /quiet /norestart",1,True
		wshShell.Run "wusa.exe " & Chr(34) & strMSUFileName & Chr(34) & " /quiet /norestart",1,True
		If err.number <> 0 then
			Wscript.StdOut.WriteLine "[FAILED]"
			Wscript.Stdout.WriteLine "Installation of "& Replace(strMSUFileName,strScriptFolder,"") & " failed with exitcode:" & err.number
			err.clear
		Else
			WScript.StdOut.WriteLine "[OK]"
			'Wscript.Stdout.Write "Installation of " & Replace(strMSUFileName,strScriptFolder,"") & " succeeded"
			' Reboot the system and schedule this script to run during startup
			WshShell.RegWrite "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\AMClient", Chr(34) & wshShell.ExpandEnvironmentStrings("%windir%\system32\cscript.exe") & Chr(34) & " //nologo " & Chr(34) & objScriptFile & Chr(34)
			intAnswer = Msgbox("Reboot is required before continuing installation, do you wish to reboot now?", vbYesNo, "Automation Machine Client")

			If intAnswer = vbYes Then
				wshShell.Run Chr(34) & wshShell.ExpandEnvironmentStrings("%systemroot%\system32\shutdown.exe") & Chr(34) & " /r /t 0"
			Else
				WScript.Quit(1)
			End If
		End If
	Else 
		Wscript.Stdout.Write "Error downloading " & Replace(strMSUFileName,strScriptFolder,"") & ". Does this computer have access to the internet? Error reported:" & err.number
		err.Clear
	End If
Else
	WScript.StdOut.WriteLine "[OK]"
	'Wscript.Stdout.Write "Powershell 3 or newer already installed"
End If


'Prepare powershell for AM
Wscript.Stdout.Write "Setting powershell execution policy to bypass..."
strExecutionPolicy = readFromRegistry("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy","N/A")
If strExecutionPolicy = "N/A" Then
	wshShell.Run "powershell.exe -command " & Chr(34) & "Set-ExecutionPolicy Bypass -Force" & Chr(34),1,True 
	If Err.number <> 0 Then
		Wscript.StdOut.WriteLine "[FAILED]"
		'Wscript.Stdout.Write "Error occured while settings powershell execution policy to bypass"
		err.clear
	Else
		Wscript.StdOut.WriteLine "[OK]"
	End If
Else
	WScript.StdOut.WriteLine "[FAILED]"
	Wscript.Stdout.WriteLine "Powershell execution policy is configured through group policy, unable to set it through script"
End If 
WScript.StdOut.Write "Enabling PS remoting..."
wshShell.Run "powershell.exe -command " & Chr(34) & "Enable-PSRemoting -Force" & Chr(34),1,True
If Err.number <> 0 Then
	Wscript.StdOut.WriteLine "[FAILED]"
	'Wscript.Stdout.Write "Error occured while enabling ps remoting"
	err.clear
Else
	WScript.StdOut.WriteLine "[OK]"
End If

WScript.StdOut.Write "Enabling Powershell CredSSP..."
wshShell.Run "powershell.exe -command " & Chr(34) & "Enable-WSManCredSSP -Role Server -Force" & Chr(34),1,True
If Err.number <> 0 Then
	WScript.StdOut.WriteLine "[FAILED]"
	'Wscript.Stdout.Write "Error occured while enabling CredSSP"
	err.clear
Else
	WScript.StdOut.WriteLine "[OK]"
End If

Wscript.StdOut.WriteLine "System is ready for AM Initialize..."

