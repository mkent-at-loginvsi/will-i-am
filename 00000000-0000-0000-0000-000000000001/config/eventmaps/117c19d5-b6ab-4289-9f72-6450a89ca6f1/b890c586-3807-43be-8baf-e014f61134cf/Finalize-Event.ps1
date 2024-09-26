param
(
	$Plugins
)

# FINALIZE LOGON EVENT FOR Statefull VDI



# Setup Logon Async trigger

& "$am_env_files\config\plugins\f9dcdc52-4638-4939-870c-52f40e733d59\Optional\Setup-LogonAsync.ps1" # Copy startmenu shortcuts

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
									
		
			ForEach ($Plugin in $Plugins)
			{
				& "$am_evt_script_path\Process-Event.ps1" -Package $am_pkg_trk -Plugin $Plugin						
			}
			If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}

		}
		[void] $PackagesProcessed.Add([guid]::Parse($am_pkg_id_trk))
	}
}

# Invoke plugin initialization scripts
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginFinalization -Plugin $Plugin
}

