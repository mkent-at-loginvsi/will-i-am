param
(
	$Plugins
)
## PrepSeal Event finalize on Generic Server
& "$am_env_files\config\plugins\3efa9468-86b6-46a5-88e1-9c905a1226aa\Optional\SetFirstBootFlag.ps1"  
Enable-AMMaintenance
Disable-AMSystemEventFlag
& "$am_env_files\config\plugins\3efa9468-86b6-46a5-88e1-9c905a1226aa\Optional\seal.ps1" # imaging plugin

ForEach ($Plugin in $Plugins)
{
	Invoke-AMPluginFinalization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}

#Workaround if network connection is lost during seal process
if (!(Test-Path $am_files)) {
	Write-AMWarning "Path to AM server [$am_files] is inaccessible or network connection is lost, switching to offline mode"
	$Global:am_offline = $true
}

Write-AMStatus "Finished sealing image"