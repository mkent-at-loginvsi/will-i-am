$PluginId = $AmWellKnown::Plugins.UserEnvironment.Id
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.UserEnvironment.EnableUserEnvironmentVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)
if ($pluginenabled -eq $true)
{
	# Enable login async event
	Write-AMInfo "Installing AM LogonAsync event trigger"

	#[string] $Source = "$AMCentralPath\media\cc0947ae-4087-48e9-b44c-b4af2b68ef46\1"
	[string] $Destination = Join-Path $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::Programs))) "Startup"
	#If (!(Test-Path $Destination)) {New-Item -Path $Destination -ItemType Directory | Out-Null}
	#Copy-Item "$($Source)\Invoke Automation Machine LogonAsync event.lnk" -Destination $Destination -Force
	New-AMShortcut -Name "Automation Machine LogonAsync event.lnk" -Path $Destination -Target "%windir%\system32\windowspowershell\v1.0\powershell.exe" -Arguments "-WindowStyle Hidden -command import-module amclient;invoke-amevent -name logonasync" -WorkingDirectory "%userprofile%" -WindowStyle Minimized
}