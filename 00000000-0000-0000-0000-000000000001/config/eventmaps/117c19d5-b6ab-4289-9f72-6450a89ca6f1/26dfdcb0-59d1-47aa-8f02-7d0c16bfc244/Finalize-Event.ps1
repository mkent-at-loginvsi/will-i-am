param
(
	$Plugins
)

# FINALIZE STARTUP EVENT FOR Statefull VDI

# Execute optional plugin functions
& "$am_env_files\config\plugins\2933a65d-1b32-4600-b288-325fa550f2f4\Optional\WUA-AsConfigured.ps1" -CheckIsDoneAfterPackageProcessing   #Deployment plugin


# Process all plugins for all packages that weren't processed during normal event processing e.g. installed using the App Store 
$TrackedPackages = gci "HKLM:\SOFTWARE\Automation Machine\Tracking" | % { Split-Path $_ -Leaf }
Foreach ($am_pkg_id_trk in $TrackedPackages) {
	
	If (-not ($PackagesProcessed.Contains([guid]::Parse($am_pkg_id_trk)))) {
		
		$am_pkg = Get-AMPackage -Id $am_pkg_id_trk
		
		If ($am_pkg -ne $null) {			
			$am_pkg_name = $am_pkg.name
			Write-AMInfo "Processing package: $am_pkg_name"
			if ($am_pkg.PackageCategory -is [object]) {
				$am_pkg_cat = $am_pkg.PackageCategory.Name
				[System.Environment]::SetEnvironmentVariable("am_pkg_cat", $am_pkg_cat, [System.EnvironmentVariableTarget]::Process)
			}
			[System.Environment]::SetEnvironmentVariable("am_pkg_name", $am_pkg_name, [System.EnvironmentVariableTarget]::Process)

			Set-AMEnvironmentVariables -ComponentId $am_pkg_id_trk -CollectionId $am_col.Id
									
		
			ForEach ($Plugin in $Plugins) {
				& "$am_evt_script_path\Process-Event.ps1" -Package $am_pkg -Plugin $Plugin						
			}
			If (Test-Path Variable:Plugin) { . Remove-Item variable:plugin -Force }

		}
		[void] $PackagesProcessed.Add([guid]::Parse($am_pkg_id_trk))
	}
}
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
		$amRoot = [string]::Format("HKLM:\{0}", [AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT_WITHOUT_HIVE)
		$amRootItem = Get-Item -Path $amRoot
		if ((Test-Path -Path $amRoot) -and ($amRootItem.Property.Contains($([AutomationMachine.Data.DataFilePath]::REGISTRY_VALUE_IS_REBOOT_NEEDED)))) {
			Remove-ItemProperty -Path $amRoot -Name $([AutomationMachine.Data.DataFilePath]::REGISTRY_VALUE_IS_REBOOT_NEEDED) -Force
		}

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