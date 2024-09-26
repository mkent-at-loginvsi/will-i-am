param
(
	$Plugins
)

# FINALIZE SYSTEM SCHEDULED EVENT FOR Statefull VDI


# Process all plugins for all packages that weren't processed during normal event processing e.g. installed using the App Store 
$TrackedPackages = gci "HKLM:\SOFTWARE\Automation Machine\Tracking" | % {split-path $_ -leaf}
Foreach ($am_pkg_id_trk in $TrackedPackages)
{
	
	If (-not ($PackagesProcessed.Contains([guid]::Parse($am_pkg_id_trk))))
	{
		
		$am_pkg_trk = Get-AMPackage -Id $am_pkg_id_trk
		
		If ($am_pkg_trk -ne $null)
		{			
			$am_pkg_name_trk = $am_pkg_trk.name
			Write-AMInfo "Processing package: $am_pkg_name_trk"
			if ($am_pkg_trk.PackageCategory -is [object])
			{
				$am_pkg_cat_trk = $am_pkg_trk.PackageCategory.Name
				[System.Environment]::SetEnvironmentVariable("am_pkg_cat",$am_pkg_cat_trk,[System.EnvironmentVariableTarget]::Process)
            }
			[System.Environment]::SetEnvironmentVariable("am_pkg_name",$am_pkg_name_trk,[System.EnvironmentVariableTarget]::Process)

			Set-AMEnvironmentVariables -ComponentId $am_pkg_id_trk -CollectionId $am_col.Id
									
			# Calling the process event script
			
			ForEach ($Plugin in $Plugins)
			{
			& "$am_evt_script_path\Process-Event.ps1" -Package $am_pkg_trk -Plugin $Plugin			
			#	Invoke-AMPluginExecution -Package $am_pkg_trk -Plugin $Plugin
			}
			If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}
		}
		[void] $PackagesProcessed.Add([guid]::Parse($am_pkg_id_trk))
	}
}



ForEach ($Plugin in $Plugins)
{
    Invoke-AMPluginFinalization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}
#Write-AMStatus "Ready"
Disable-AMSystemEventFlag
& "$am_env_files\config\plugins\3572102e-07be-4112-ac2c-a214179f420c\Optional\SetupMaintSchTasks.ps1" # Maintenance plugin