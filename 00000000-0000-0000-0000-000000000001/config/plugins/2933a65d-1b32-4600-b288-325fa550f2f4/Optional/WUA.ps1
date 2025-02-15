#region Functions
function Get-WIAStatusValue($value) {
	switch -exact ($value) {
		0 { "NotStarted" }
		1 { "InProgress" }
		2 { "Succeeded" }
		3 { "SucceededWithErrors" }
		4 { "Failed" }
		5 { "Aborted" }
	} 
}

function Get-RebootStatus {

	If (Test-Path Function:Get-AMPendingReboot) {
		$needsReboot = Get-AMPendingReboot
	}
	else {
		#fallback reboot detecion for older version of AM that don't have the Get-AMPendingReboot function
		$objSystemInfo = New-Object -ComObject "Microsoft.Update.SystemInfo"
		$needsReboot = $objSystemInfo.RebootRequired									
	}

	return $needsReboot

}

function Set-VariablesForReboot {

	$AMDataManager.RebootNeeded = $true
	$global:am_rebooting = $true
	$global:am_aborting = $true	

}

function Stop-WindowsUpdateService {
	if ($am_wua_manage_service -eq $true) {
		Write-AMInfo "Stopping Windows update service and disabling it" 
		Set-Service wuauserv -StartupType disabled
		Get-Service wuauserv | Stop-Service
	}
}

function Invoke-WUAFinalization {

	Write-AMInfo "Evaluating if system requires a reboot"			
	# re-check if reboot is required, sometimes updates don't require reboot individually, but wua still wants an update
	if ($needsReboot -eq $false) {
		$needsReboot = Get-RebootStatus
	}

	#Reboot computer if necessary 
	if ($needsReboot -eq $true) {
		Write-AMInfo "Reboot is needed"
		Set-VariablesForReboot
	}
	else {
		Write-AMInfo "Reboot is not needed"
		Stop-WindowsUpdateService
		$WAUSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
		If ($WAUSettings.ReadOnly -ne $true) {
			$WAUSettings.NotificationLevel = 1
			$WAUSettings.Save()			
		}			
	}

}

#endregion Functions

$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
$Plugin = Get-AMPlugin -Id $PluginId
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)
$ProcessUpdates = $false
$StatusPath = Join-Path $([AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT).Replace("HKEY_LOCAL_MACHINE", "HKLM:") "Status"
$MaintenanceFlag = (Get-ItemProperty -Path $StatusPath -Name "Maintenance" -ErrorAction SilentlyContinue)
Set-Variable -Name am_wua_enabled -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001D -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_wua_recommended -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001E -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_wua_other -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-00000000001F -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_wua_manage_service -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000027 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_wua_kb_exclusions -value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000064 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_wua_ms_update -value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000065 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)

If ($null -eq $MaintenanceFlag) {
	Write-AMInfo "Maintenance flag $(Join-Path $StatusPath `"Maintenance`") not set to true, not processing deployment plugin"
}
ElseIf ($MaintenanceFlag.Maintenance -ne $true) {
	Write-AMInfo "Maintenance flag $(Join-Path $StatusPath `"Maintenance`") not set to true, not processing deployment plugin"
}
ElseIf ($am_aborting -eq $true) {
	Write-AMInfo "System is going down for reboot, not installing Windows updates"
}
Elseif ($pluginenabled -eq $true) {	
	if (($am_wua_enabled -eq $true)) {	
		If (Test-Path Variable:PSSenderInfo) {
			Write-AMWarning "Automatic updates cannot be invoked via remoting sessions, please rerun startup from the scheduled task or from a local PowerShell session"
		}
		else {
			Write-AMInfo "Processing Windows updates"

			$needsReboot = Get-RebootStatus	
		
			#Reboot computer if necessary 
			if ($needsReboot -eq $true) {
				Write-AMInfo "Computer needs a reboot before new updates can be installed"
				Set-VariablesForReboot
			}
			else {
				$ProcessUpdates = $true
			}
		}
	}
	else {
		Write-AMInfo "Automatic Windows updates disabled"
		Stop-WindowsUpdateService		
	}
}

If ($ProcessUpdates -eq $true) {
	try {
		$WAUSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
		If ($WAUSettings.ReadOnly -ne $true) {
			if ("NotificationLevel" -iin $WAUSettings.PSObject.Properties.Name) {
				$WAUSettings.NotificationLevel = 1
			}
			else {
				Write-AMInfo "NotificationLevel parameter not found. Unable to disable Windows Update schedule."
			}
		}
		Set-Service wuauserv -StartupType automatic
		Get-Service wuauserv | Start-Service
		
		$ServiceManager = New-Object -com "Microsoft.Update.ServiceManager"
		if ($am_wua_ms_update -eq $true) {			
			$ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "")
		}
		else {
			If ($null -ne ($ServiceManager.Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" })) {
				$ServiceManager.SetOption("AllowWarningUI", $false)
				$ServiceManager.UnregisterServiceWithAU("7971f918-a847-4430-9279-4a52d1efe18d")
				$ServiceManager.RemoveService("7971f918-a847-4430-9279-4a52d1efe18d")
				$ServiceManager.SetOption("AllowWarningUI", $true)
			}
		}

		$SearchString = "IsAssigned=1 and IsHidden=0 and IsInstalled=0"
		if ($am_wua_recommended -eq $true) {
			If ($WAUSettings.ReadOnly -ne $true) {
				$WAUSettings.IncludeRecommendedUpdates = $true
			}
		}

		if ($am_wua_other -eq $true) {
			$SearchString = "IsInstalled=0"
			#$SearchString = "IsAssigned=1 and IsHidden=0 and IsInstalled=0 and BrowseOnly=1"
			$ServiceManager = New-Object -com Microsoft.Update.ServiceManager
			If (($ServiceManager.Services | Where-Object { $_.IsDefaultAUService -eq $true }).Name -eq "Microsoft Update") {
				If ($WAUSettings.ReadOnly -ne $true) {
					$WAUSettings.FeaturedUpdatesEnabled = $true
				}
			}
		}
		
		If ($WAUSettings.ReadOnly -ne $true) {
			$WAUSettings.Save()
		}

		$needsReboot = $false
		$UpdateSession = New-Object -ComObject Microsoft.Update.Session
		$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

		Write-AMStatus "Searching for windows updates"
		# Search for needed updates 
		try {
			$SearchResult = $UpdateSearcher.Search($SearchString)
		}
		catch {
			$ErrorMessage = $_.Exception.Message
			if ($ErrorMessage -match "0x80244010") {
				Write-AMInfo "System is going down for reboot, another Windows update cycle is needed"
				$SearchResult = $null
				$needsReboot = $true
			}
			else {
				Throw $_
			}
		}

		If ($null -ne $SearchResult -and $SearchResult.Updates.Count -gt 0) {

			# Report updates that have been found
			Write-AMInfo "Found $($SearchResult.Updates.count) updates to download and install"
			Write-AMStatus "Processing $($SearchResult.Updates.Count) Windows updates"
			$UpdatesCollection = New-Object -ComObject Microsoft.Update.UpdateColl

			foreach ($Update in $SearchResult.Updates) {
				# Add Update to Collection				
				if ( $Update.EulaAccepted -eq 0 ) { $Update.AcceptEula() }
				If ($Update.InstallationBehavior.CanRequestUserInput) {
					Write-AMWarning "Skipping update $($Update.Title) because it requires user interaction"
				}
				elseif ($Update.KBArticleIDs.Count -gt 0) {
					if ($am_wua_kb_exclusions.Replace("KB", "").Split(",") -contains $Update.KBArticleIDs[0]) {
						Write-AMWarning "Skipping update $($Update.Title) because it is marked for exclusion"
					}
					else { [void] $UpdatesCollection.Add($Update) }
				}
				else {
					[void] $UpdatesCollection.Add($Update)
				}
			}
			# Download Applicable Updates
			If ($UpdatesCollection.Count -gt 0) {
				$UpdatesDownloader = $UpdateSession.CreateUpdateDownloader()
				$UpdatesDownloader.Updates = $UpdatesCollection
				$retry = $true
				$count = 0
				$done = $false
				$maxcount = 10
				$RebootRequiredAfterUpdate = $false
				while ($retry -eq $true) {
					$count++
					try {
						Write-AMStatus "Downloading $($updatesCollection.Count) updates"
						$DownloadResult = $UpdatesDownloader.Download()				
						$Message = "Download {0}" -f (Get-WIAStatusValue $DownloadResult.ResultCode)
						Write-AMInfo $message   
						# Install Updates
						Write-AMStatus "Installing $($updatesCollection.Count) Updates"
						$Index = 1
						foreach ($updateToInstall in $UpdatesCollection) {								
							Write-AMInfo "Installing update $($Index) out of $($UpdatesCollection.Count) updates"
							Write-AMStatus "Installing update $($Index) out of $($UpdatesCollection.Count) updates"
							Write-AMInfo "Update being installed: $($updateToInstall.Title)"
							$UpdatesInstaller = $UpdateSession.CreateUpdateInstaller()
							$UpdatesInstaller.Updates = New-Object -ComObject Microsoft.Update.UpdateColl
							$UpdatesInstaller.Updates.Add($updateToInstall)
							$InstallResult = $UpdatesInstaller.Install()
							if ($installResult.rebootRequired -eq $true) {
								$RebootRequiredAfterUpdate = $true
							}
							$Index++                                
						}
						$Message = "Install {0}" -f (Get-WIAStatusValue $DownloadResult.ResultCode)
						Write-AMInfo $Message	
						$needsReboot = $RebootRequiredAfterUpdate
						$retry = $false
						$done = $true
					}
					catch {                   
						$retry = $true
						$reason = $_
					}
					if ($count -le $maxcount) {
						Start-Sleep -Seconds 30
					}
					else {
						$retry = $false
					}
				}
				if ($done -ne $true) {
					throw $reason
				}
			}
			else {
				Write-AMStatus "No updates to download and install"
			}   	
		}
		
		$WUAUCLT = "$env:SystemRoot\System32\wuauclt.exe"       
		If (Test-Path $WUAUCLT) {
			Write-AMInfo "Invoking Windows Update reporting"
			try {
				. $WUAUCLT /reportnow
				If ($LASTEXITCODE -ne 0) {
					throw "$WUAUCLT did not exit with return code 0, please run wuauclt.exe /reportnow manualy"
				}
			}
			catch {
				Write-AMWarning "WSUS reporting failed with reason: $_"
			}
		}                
		
		Invoke-WUAFinalization
	}
	catch {
		Write-AMError $_
		Write-AMWarning "An error occured while processing Windows updates, finalizing AM Windows update installation process"
		try { Invoke-WUAFinalization } catch { Write-AMError $_ }		
	}
}