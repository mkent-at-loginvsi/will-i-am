param
(
	$Plugins
)

# FINALIZE STARTUP EVENT FOR XenApp 6.5 Session Host

# Execute optional plugin functions
& "$am_env_files\config\plugins\2933a65d-1b32-4600-b288-325fa550f2f4\Optional\WUA-AsConfigured.ps1" -CheckIsDoneAfterPackageProcessing   #Deployment plugin

ForEach ($Plugin in $Plugins) {
	Invoke-AMPluginFinalization -Plugin $Plugin
}

If (Test-Path Variable:Plugin) { . Remove-Item variable:plugin -Force }

# Disable event flag and update policies
Update-AMGroupPolicyObjects
Disable-AMSystemEventFlag



if ($global:am_rebooting -eq $false) {
	Set-Variable -Name image_enabled -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId 3efa9468-86b6-46a5-88e1-9c905a1226aa -CollectionId $am_col.Id).Value) | Expand-AMEnvironmentVariables
	Set-Variable -Name templatecomputer -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000006 -ParentId 3efa9468-86b6-46a5-88e1-9c905a1226aa -CollectionId $am_col.Id).Value) | Expand-AMEnvironmentVariables
	if (($env:COMPUTERNAME -like $templatecomputer) -and ($image_enabled -eq $true)) {
		Invoke-AMEvent -Name PrepSeal

		# remove AM from machines that are not the template machines (if configured)
		& "$am_env_files\config\plugins\3efa9468-86b6-46a5-88e1-9c905a1226aa\Optional\RemoveAM.ps1"              # Imaging plugin
		if ($lastexitcode -eq 3010) {
			exit
		}
	}
	else {
		& "$am_env_files\config\plugins\3efa9468-86b6-46a5-88e1-9c905a1226aa\Optional\ResetFirstBootFlag.ps1"    # Imaging plugin
		& "$am_env_files\config\plugins\6952e8c1-459a-4ed3-b4ec-2506575e2069\Optional\SetupAMBackgroundTask.ps1" # System configuration plugin
		& "$am_env_files\config\plugins\3572102e-07be-4112-ac2c-a214179f420c\Optional\SetupMaintSchTasks.ps1" # Maintenance plugin

		Write-AMStatus "Ready"

		# reset RebootNeeded registry value
		Remove-AMRebootNeededFlag

		# Check if maintenance is in progress, if so, we need to finish maintenance
		[boolean] $cpu_started = Test-AMMaintenanceFlag -Flag cpu_started
		If ($cpu_started -eq $true) {
			Invoke-AMEvent -Name SystemMaintenance
		}
	}
}
else {
	Write-AMinfo "System is going to reboot, not finalizing startup yet"
}