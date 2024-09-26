<#
	.Synopsis
	Invokes the create shortcut action item.

	.Description
 	Invokes the specified create shortcut actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemShareFolder -ActionItem $ActionItem
#>
function Invoke-AMActionItemCreateShortcut
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[AutomationMachine.Data.ActionItem] $ActionItem
	)
	
	Write-AMInfo "Invoking $($ActionItem.Name)"
	# Resolve the variables including the filters,
	$Variables = $ActionItem.Variables
	$Variables | % {Resolve-AMVariableFilter $_}
	$Variables | % {Resolve-AMMediaPath $_}
	
	# Get the variables from the actionitem
	[String] $Name = $($Variables | ? {$_.name -eq "Name"}).Value | Expand-AMEnvironmentVariables
	[String] $Description = $($Variables | ? {$_.name -eq "Description"}).Value | Expand-AMEnvironmentVariables
	[String] $Target = $($Variables | ? {$_.name -eq "Target"}).Value.Path | Expand-AMEnvironmentVariables
	[String] $WorkDir = $($Variables | ? {$_.name -eq "Working Directory"}).Value.Path | Expand-AMEnvironmentVariables
	[String] $Arguments = $($Variables | ? {$_.name -eq "Arguments"}).Value | Expand-AMEnvironmentVariables
	[Boolean] $PublishStartMenu = $($Variables | ? {$_.name -eq "Publish in Startmenu"}).Value
	[Boolean] $PublishDesktop = $($Variables | ? {$_.name -eq "Publish on Desktop"}).Value
	[Boolean] $PublishAllUsers = $($Variables | ? {$_.name -eq "Publish for all users"}).Value
	[Boolean] $PublishRemoteApp = $($Variables | ? {$_.name -eq "Publish in RDS/XenApp/View"}).Value
	[String] $Folder = $($Variables | ? {$_.name -eq "Folder"}).Value | Expand-AMEnvironmentVariables
	[String] $GroupString = $($Variables | ? {$_.name -eq "Group"}).Value | Expand-AMEnvironmentVariables
	[Boolean] $UsePreSuffix = $($Variables | ? {$_.name -eq "AutoAdd group prefix/suffix"}).Value
	$Icon = $($Variables | ? {$_.name -eq "Icon"})
	
	if (!([string]::IsNullOrEmpty($GroupString)))
	{				
		$Groups = $GroupString.Split(';')
	}
	
	If ([string]::IsNullOrEmpty($Icon.Value.Name))
	{
		$IconPath = $Target
	}
	else
	{
		$TempPath = Get-AMImportedFilePath $Icon
		$IconName = (Get-Item $TempPath).Name
		$IconPath = Join-Path $am_workfolder $IconName
		try {
			Copy-Item $TempPath $IconPath -Force
		}
		catch {
			Write-AMWarning "Unable to copy the icon file to \"$IconPath\""
		}
	}
	
	If (!(Test-Path $Target))
	{
		throw "Target $Target does not exist, unable to create shortcut to non-existing target"
	}
	
	If ($UsePreSuffix -eq $true)
	{	
		Set-Variable -name am_col_gprefix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000014" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
		Set-Variable -Name am_col_gsuffix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000018" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
		
		for ($i = 0; $i -lt $Groups.Count; $i++)
		{
			$Groups[$i] = $am_col_gprefix + $Groups[$i] + $am_col_gsuffix
		}
	}
	
	$Target = Get-Item $Target
	
	If ($am_col_enable_startmenu_publish -eq $true)
	{
		If ($PublishStartMenu -eq $true)
		{
			If ($PublishAllUsers -ne $true)
			{
				foreach ($Group in $Groups)
				{
					If ((Get-AMLDAPPath $Group) -eq $null)
					{
						throw "Unable to find group: $group"
					}
						
					# Create new shortcut in amworkfolder
					$ShortcutFolder = Join-Path (Join-Path $am_workfolder "Shortcuts\Startmenu") $Folder
					#$ShortcutPath = Join-Path $ShortcutFolder "$Name.lnk"
					If (!(Test-Path $ShortcutFolder)) { [void] (New-Item $ShortcutFolder -Force -ItemType Directory) }
					New-AMShortcut -Path $ShortcutFolder -Name "$Name.lnk" -Target $Target -WorkingDirectory $WorkDir -Arguments $Arguments -Description $Description -IconPath $IconPath
					# Apply NTFS permissions to shortcut	
					
					Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
					
					If ($IconPath -ne $Target)
					{
						if (-Not($IconPath -Like "*.ico"))
						{
							Set-AMPermissions -Path "$IconPath" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
						}
					}
					
					# NOTE: Optional Shortcuts script ensures that shortcuts are being copied during LOGON event
				}
			}
			Else
			{
				$ShortcutFolder = Join-Path $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::CommonPrograms))) $Folder
				If (!(Test-Path $ShortcutFolder)) { [void] (New-Item $ShortcutFolder -Force -ItemType Directory) }
				New-AMShortcut -Path $ShortcutFolder -Name "$Name.lnk" -Target $Target -WorkingDirectory $WorkDir -Arguments $Arguments -Description $Description -IconPath $IconPath
				

				Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow		
				If ($IconPath -ne $Target)
				{
                    if (-Not($IconPath -Like "*.ico"))
                    {
					    Set-AMPermissions -Path "$IconPath" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow
                    }
				}
				
			}
		}
		Else
		{
			Write-AMInfo "Publishing shortcuts to start menu is disabled on the actionitem"
		}
	}
	Else
	{
		Write-AMInfo "Publishing shortcuts to start menu is disabled on the collection"
	}
	
	
	
	If ($am_col_enable_desktop_publish -eq $true)
	{
		If ($PublishDesktop -eq $true)
		{
			If ($PublishAllUsers -ne $true)
			{
				foreach ($Group in $Groups)
				{
					If ((Get-AMLDAPPath $Group) -eq $null)
					{
						throw "Unable to find group: $group"
					}
					# Create new shortcut in amworkfolder
					$ShortcutFolder = Join-Path $am_workfolder "Shortcuts\Desktop"
					#$ShortcutPath = Join-Path $ShortcutFolder "$Name.lnk"
					If (!(Test-Path $ShortcutFolder)) {[void] (New-Item $ShortcutFolder -Force -ItemType Directory) }
					New-AMShortcut -Path $ShortcutFolder -Name "$Name.lnk" -Target $Target -WorkingDirectory $WorkDir -Arguments $Arguments -Description $Description -IconPath $IconPath
					# Apply NTFS permissions to shortcut	
					

					Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
					If ($IconPath -ne $Target)
					{
						if (-Not($IconPath -Like "*.ico"))
						{
							Set-AMPermissions -Path "$IconPath" -PrincipalName $group -Permissions "ReadAndExecute" -Type Allow
						}
					}
				}
				# NOTE: Optional Shortcuts script ensures that shortcuts are being copied during LOGON event
			}
			Else
			{
				$ShortcutFolder =  $([System.Environment]::GetFolderPath($([Environment+SpecialFolder]::CommonDesktopDirectory)))			
				New-AMShortcut -Path $ShortcutFolder -Name "$Name.lnk" -Target $Target -WorkingDirectory $WorkDir -Arguments $Arguments -Description $Description -IconPath $IconPath
				
				Set-AMPermissions -Path "$ShortcutFolder\$Name.lnk" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow		
				If ($IconPath -ne $Target)
				{
                    if (-Not($IconPath -Like "*.ico"))
                    {
					    Set-AMPermissions -Path "$IconPath" -PrincipalName "Everyone" -Permissions "ReadAndExecute" -Type Allow
                    }
				}
			}
		}
		Else
		{
			Write-AMInfo "Publishing shortcuts to the desktop is disabled on the actionitem"
		}
	}
	Else
	{
		Write-AMInfo "Publishing shortcuts to the desktop is disabled on the collection"
	}
	
	If ($PublishRemoteApp -eq $true)
	{
		$EnableMaintenanceMode = $false
		$PublishMode = "Unknown"
		# Check if this server is configured for RDS or XenApp
		try
		{
			$TSservices = Get-WmiObject -class Win32_TSSessionDirectory -ns root\cimv2\terminalservices -ErrorAction SilentlyContinue -Authentication PacketPrivacy -Impersonation Impersonate
		}
		catch
		{
			$TSservices = $null
		}
		If ($TSServices -ne $null)
		{
			If ($TSServices.SessionDirectoryActive -eq 1)
			{
				$PublishMode = "RDS2012R2"
			}
			else
			{
				try
				{
					$Citrix = Get-WMIObject -class Citrix_Product -ns root\citrix -ErrorAction SilentlyContinue 
				}
				catch
				{
					$Citrix = $null
				}
				If ($Citrix -ne $null)
				{
					If ($Citrix.Version -like "*6.5*")
					{
						$PublishMode = "XA65"
					}
				}
				else
				{
					# Not RDS or XA 6.5, let's check for XA71/XA75
					If (Test-Path "HKLM:SOFTWARE\Citrix\Versions\Citrix Virtual Desktop Agent")
					{
                        $Version = (Get-ItemProperty "HKLM:SOFTWARE\Citrix\Versions\Citrix Virtual Desktop Agent")."(default)"						
						Switch -Wildcard ($Version)
						{
							"7.*" { $PublishMode = "XA7" }

                            default { $PublishMode = "Unknown" }
						}
						
					}
                    elseif (Test-Path "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\Agent")
                    {
                        $Version = (Get-ItemProperty "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM").ProductVersion
                        Switch -Wildcard ($Version)
                        {
                            "7.*" { $PublishMode = "View6"}

                            default { $PublishMode = "Unknown"}
                        }
                        
                    }
					else
					{
						$PublishMode = "Unknown"						
					}
				}
			}
		}
		else
		{
			# Not a Terminal Server, probably a workstation
			If (Test-Path "HKLM:SOFTWARE\Citrix\Versions\Citrix Virtual Desktop Agent")
			{
				$Version = (Get-ItemProperty "HKLM:SOFTWARE\Citrix\Versions\Citrix Virtual Desktop Agent")."(default)"
				
				Switch -Wildcard ($Version)
				{
					"7.*" { $PublishMode = "XA7"; $EnableMaintenanceMode = $true }
					default { $PublishMode = "Unknown" }
				}
				
			}
			elseif (Test-Path "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\Agent")
			{
				$Version = (Get-ItemProperty "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM").ProductVersion
				Switch -Wildcard ($Version)
				{
					"6.*" { Write-AMWarning "Application publishing for VMware Horizon View 6 is only supported for RDS servers" }
					default { $PublishMode = "Unknown"}
				}
				
			}
			else
			{
				$PublishMode = "Unknown"						
			}
		}
		
		# Create/process remoteapp for the different modes
		Switch ($PublishMode)
		{
			"Unknown" { Write-AMWarning "No supported application publication method found, unable to create published application"}
			"RDS2012R2"
			{
				If ($am_rds_publish -eq $true)
				{
					If (Get-Module -ListAvailable -Name RemoteDesktop)
					{
						
						If ($PublishAllUsers -ne $true)
						{
							foreach ($Group in $Groups)
							{
								If ((Get-AMLDAPPath $Group) -eq $null)
								{
									throw "Unable to find group: $group"
								}
							}
						}
						else
						{
							$Groups[0] = "Domain Users"
						}
						
						If (!(Get-Module -Name RemoteDesktop)) {Import-Module RemoteDesktop}
						$RDCB = (Get-WMIObject -Namespace root\cimv2\terminalservices -Class Win32_TSSessionDirectory -Authentication PacketPrivacy -Impersonation Impersonate).SessionDirectoryLocation
						$CollectionAlias = (Get-WMIObject -Namespace root\cimv2\terminalservices -Class Win32_TSSessionDirectory -Authentication PacketPrivacy -Impersonation Impersonate).SessionDirectoryClusterName
						

						# Try to use AM collection if RDS collection is still "AM Maintenance"
						$AMMaintenanceCollection = "AM Maintenance"
						$am_pkg_rds_collection = (Get-WMIObject -Namespace root\cimv2\rdms -class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate | Where-Object {$_.Alias -eq $CollectionAlias}).Name
						if ($am_pkg_rds_collection -eq $AMMaintenanceCollection)
						{
							$AMCollectionName = (Get-AMCollection -Current).Name
							$RDSHCollection = (Get-WMIObject -Namespace root\cimv2\rdms -class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate) | Where-Object {$_.Name -eq $AMCollectionName}
							if ($RDSHCollection -ne $null -and ![string]::IsNullOrEmpty($RDSHCollection.Alias))
							{
								$CollectionAlias = $RDSHCollection.Alias
								$am_pkg_rds_collection = (Get-WMIObject -Namespace root\cimv2\rdms -class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate | ? {$_.Alias -eq $CollectionAlias}).Name
								Write-AMWarning "Server was still in maintenance collection, using `"$CollectionAlias`" as a collection"
							}
							else {
								Write-AMError "Server was still in maintenance collection, and no RDS collection corresponds to the AM Collection. Please move back server to correct RDS collection manually"
							}
						}
						
                        $StringBuilder = New-Object System.Text.StringBuilder 
                        $Package = Get-AMPackage -Name $env:am_pkg_name | Select -First 1
                        $String = $Package.Id.ToString() + $ActionItem.Id.ToString()
                        [System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{[Void]$StringBuilder.Append($_.ToString("x2"))}
                        $AliasEnding = $StringBuilder.ToString()
						$Alias = (Get-Item $Target).BaseName.Replace("+", "") + "_" + $AliasEnding
						$Result = Get-AMRDRemoteApp -Alias $Alias -ConnectionBroker $RDCB -CollectionName $am_pkg_rds_collection

						$ShortcutsPluginId = [AM.Data.WellKnown.WellKnown]::Plugins.Shortcuts.Id
						$CommandLineArgumentsVariableId = [AM.Data.WellKnown.WellKnown]::Plugins.Shortcuts.CommandLineArgumentsVariable.Id
						$CommandLineArgumentsVariable = Get-AMVariable -ComponentId $ShortcutsPluginId | ? { $_.Id -eq $CommandLineArgumentsVariableId}
						$ArgumentPermissions = $CommandLineArgumentsVariable.Value.Value
						If ($Result -isnot [Object])
						{
							New-AMRemoteApp -DisplayName $Name -FilePath $Target -Alias $Alias -Arguments $Arguments -Folder $Folder -UserGroups @($Groups) -Collection $am_pkg_rds_collection -PublishFileTypes $am_rds_publishFTE -ShowInWebAccess $am_rds_showWA -IconPath $IconPath -ArgumentPermissions $ArgumentPermissions
						}
						Else
						{
							If ($am_rds_autofix -eq $true)
							{
								Set-AMRemoteApp -DisplayName $Name -FilePath $Target -Alias $Alias -Arguments $Arguments -Folder $Folder -UserGroups @($Groups) -Collection $am_pkg_rds_collection -PublishFileTypes $am_rds_publishFTE -ShowInWebAccess $am_rds_showWA	-IconPath $IconPath -ArgumentPermissions $ArgumentPermissions
							}
							Else
							{
								Write-Verbose "Not updating RemoteApp $Name"
							}
						}	
					}
					Else
					{
						Write-AMWarning "Cannot find RemoteDesktop module on this machine, unable to create RemoteApp"
					}
				}
				Else
				{
					Write-AMInfo "RDS RemoteApp publishing is disabled"
				}
			}
			"XA65"
			{
				If ($am_xa_publish -eq $true)
				{
					If (Get-PSSnapin -Registered -Name Citrix.XenApp.Commands)
					{	

						#region translations
						if (-not ([string]::IsNullOrEmpty($Arguments)))
						{
							$CmdLine = "$Target $Arguments"
						}
						else
						{
							$CmdLine = $Target
						}
						
						if (!([string]::IsNullOrEmpty($Description)) -and $Description.Length -gt 255)
						{
							$Description = $Description.Substring(0,255)
						}
						$CollectionString = ""
						$am_col.Id.ToString().Split("-") | % {$CollectionString += $_[0]} 
						$BrowserName = $AMEnvironment.Prefix + $Name + "_" + $CollectionString
						$BrowserName = $BrowserName -replace "\\|\/|;|:|#|\.|\*|\?|=|<|>|\||\[|\]|`'|`"|\(|\)","_"
						If ($BrowserName.Length -gt 38) {$BrowserName = $BrowserName.Substring(0,38) }
						
						$Name = $Name -replace "\\|\/|;|:|#|\.|\*|\?|=|<|>|\||\[|\]|`'|`"|\(|\)","_"
						If ($Name.Length -gt 38) {$Name = $Name.Substring(0,38) }
						$am_xa_folderpath = $am_xa_folderpath -replace ";|:|#|\.|\*|\?|=|<|>|\||\[|\]|`'|`"|\(|\)","_"		
						
						
						#endregion 
						
						
					
					
						# Load the XA snapin
						If (!(Get-PSSnapin -Name Citrix.XenApp.Commands -ErrorAction SilentlyContinue))
						{
							Add-PSSnapin -Name Citrix.XenApp.Commands
						}
						If (!(Get-PSSnapin -Name Citrix.Common.Commands -ErrorAction SilentlyContinue))
						{
							Add-PSSnapin -Name Citrix.Common.Commands
						}
						
						If ($PublishAllUsers -ne $true)
						{
							foreach ($Group in $Groups)
							{
								If ((Get-AMLDAPPath $Group) -eq $null)
								{
									throw "Unable to find group: $group"
								}
							}
						}
						else
						{
							$Groups[0] = "Domain Users"
						}
						$AppCreated = $false
						$CreateApp = $false
						
						$PATrackingFolder = "$($AMCentralPath)\$($AMEnvironment.Id)\monitoring\XenApp\$($am_col_path)"
						
						
						#create parent folders if necessary
						$am_xa_folderpath = "Applications/$($am_xa_folderpath.Replace("\","/"))"
						
						$CreateFolder = $false
						try
						{
							Get-XAFolder $am_xa_folderpath
						}
						catch 
						{
							$CreateFolder = $true	
						}
						
						If ($CreateFolder -eq $true)
						{
							[void] (New-XAFolder $am_xa_folderpath -Force)
						}
						
						If (-not(Test-Path $PATrackingFolder))
						{
							[void] (New-Item -ItemType Directory -Path $PATrackingFolder -Force)
						}
						
						# Check if the application was already created
						$Package = Get-AMPackage -Name $env:am_pkg_name | Select -First 1
						$PKGTrackingPath = Join-Path $PATrackingFolder $Package.Name
						If (-not(Test-Path $PKGTrackingPath)) { [void] (New-Item -Type Directory -Path $PKGTrackingPath) }
						$AITrackingPath = Join-Path $PKGTrackingPath "$($ActionItem.Name)_$($ActionItem.Id).txt"
						$AppCreated = Test-Path $AITrackingPath
						
						
						# Add myself to server list of application
						If ($AppCreated -eq $true)
						{
								# Check if pkg revision was changed compared to last update of app
								$LastUpdateRevision = (Get-Content $AITrackingPath)
								If ($Package.Version.VersionNumber -gt $LastUpdateRevision.Split(".")[0])
								{
									Write-Verbose "Published app $($BrowserName) was already created, but modifications were detected, updating app"
									# Check if app already exists in XA
									$AppExist = (Get-XAApplication -BrowserName $BrowserName -ea silent)
									If ($AppExist -ne $null)
									{
										# Check if folder path was changed, if it was, remove the app and recreate it
										If ($AppExist.FolderPath -ne $am_xa_folderpath)
										{
											Write-Verbose "Folderpath changed for published app $($BrowserName), removing app and recreating"
											[void] (Remove-XAApplication -BrowserName $BrowserName)
											$CreateApp = $true
										}
										else
										{
											$Icon = Get-CtxIcon $IconPath
											#update the app 
											[void] (Set-XAApplication -BrowserName $BrowserName `
												-Description $Description `
												-CommandLineExecutable $CmdLine `
												-WorkingDirectory $WorkDir `
												-Accounts $Groups `
												-ClientFolder $am_xa_clientfolder `
												-AddToClientStartmenu $am_xa_addtostartmenu `
												-StartMenuFolder $Folder `
												-AddToClientDesktop $am_xa_addtodesktop `
												-CpuPriorityLevel $am_xa_cpu_prio `
												-WaitOnPrinterCreation $am_xa_waitforprinter `
												-EncodedIconData $Icon[0].EncodedIconData)
										
											If ($am_xa_publishFTE -eq $true)
											{
												try
												{
													$FileTypes = Get-XAFileType -ProgramLocation "$($Target | Expand-AMEnvironmentVariables)"
													Set-XAApplication -BrowserName $BrowserName -FileTypeNames $FileTypes
												}
												catch
												{
													Write-AMWarning "Error occurred while trying to set filetypes for application $($BrowserName)"
												}
											}
											else
											{
												try 
												{
														get-xafiletype -ProgramLocation "$($Target | Expand-AMEnvironmentVariables)" | Remove-XAApplicationFileType -BrowserName $BrowserName
												}
												catch
												{
													Write-AMWarning "Error occurred while trying to remove filetypes for application $($BrowserName)"
												}
												
											}
											
											# Set pkg revision number in central cache, so we can detect pkg updates
											Set-Content -Path $AITrackingPath -Value $Package.Version -Force	
										
										}
									
									}
									Else {
										$CreateApp = $true
									}
									

								}
								else
								{
									Write-Verbose "Published app $($BrowserName) was already created and no modifications were detected"
								}
						}
						else
						{
							Write-Verbose "Published app $($BrowserName) not yet created, creating published app"
							$CreateApp = $true
						}
						If ($CreateApp -eq $true)
						{
						
							# If an app already exists with same browsername, log a warning
							$AppExist = (Get-XAApplication -BrowserName $BrowserName -ea silent)
							If ($AppExist -ne $null)
							{
								Write-AMWarning "An application with browsername $($BrowserName) already exists, cannot create published app"
							}
							else
							{
								# Create the app
								$Icon = Get-CtxIcon $IconPath
								
								[void] (New-XAApplication -ApplicationType ServerInstalled `
								-DisplayName $Name `
								-BrowserName $BrowserName `
								-Description $Description `
								-CommandLineExecutable $CmdLine `
								-WorkingDirectory $WorkDir `
								-FolderPath $am_xa_folderpath `
								-Accounts $Groups `
								-ClientFolder $am_xa_clientfolder `
								-AddToClientStartmenu $am_xa_addtostartmenu `
								-StartMenuFolder $Folder `
								-AddToClientDesktop $am_xa_addtodesktop `
								-CpuPriorityLevel $am_xa_cpu_prio `
								-WaitOnPrinterCreation $am_xa_waitforprinter `
								-EncodedIconData $Icon[0].EncodedIconData)
								
								# Set FTA
								If ($am_xa_publishFTE -eq $true)
								{
									try
									{
										$FileTypes = Get-XAFileType -ProgramLocation "$($Target | Expand-AMEnvironmentVariables)"
										Set-XAApplication -BrowserName $BrowserName -FileTypeNames $FileTypes
									}
									catch
									{
										Write-AMWarning "Error occurred while trying to set filetypes for application $($BrowserName)"
									}
								}
								else
								{
									try 
									{
											get-xafiletype -ProgramLocation "$($Target | Expand-AMEnvironmentVariables)" | Remove-XAApplicationFileType -BrowserName $BrowserName
									}
									catch
									{
										Write-AMWarning "Error occurred while trying to remove filetypes for application $($BrowserName)"
									}
									
								}							
								# Set pkg revision number in central cache, so we can detect pkg updates
								Set-Content -Path $AITrackingPath -Value $Package.Version -Force
							}
						}													
						# Add myself as server to the app
						[void] (Add-XAApplicationServer -BrowserName $BrowserName -ServerNames $env:computername)
						
						
					}
					else
					{
						throw "Unable to locate XenApp 6.5 SDK, unable to create published application"
					}
				}
				else
				{
					Write-AMInfo "XenApp/XenDesktop publishing is disabled"
				}
			}
			"XA7"
			{			
				If ($am_xa_publish -eq $true)
				{
					If ($PublishAllUsers -ne $true)
					{
						foreach ($Group in $Groups)
						{
							If ($Group -eq $null)
							{
								throw "Shortcut is not published to all users and no group was selected, please specify a group or publish to all users"
								
								If ((Get-AMLDAPPath $Group) -eq $null)
								{
									throw "Unable to find group: $group"
								}
							}
						}
					}
					else
					{
						$Groups[0] = "Domain Users"
					}
					$AppCreated = $false
					$CreateApp = $true
						
					$PATrackingFolder = "$($AMCentralPath)\$($AMEnvironment.Id)\monitoring\XenApp7\$($am_col_path)"
					
					# region translations
					if (!([string]::IsNullOrEmpty($Description)) -and $Description.Length -gt 255)
					{
						$Description = $Description.Substring(0,255)
					}
					$CollectionString = ""
					$am_col.Id.ToString().Split("-") | % {$CollectionString += $_[0]} 
						
					$BrowserName = ($AMEnvironment.Prefix + $Name + "_" + $CollectionString) -replace "-| |\\|\/|;|:|#|\.|\*|\?|=|<|>|\||\[|\]|`'|`"|\(|\)","_"
					$BrowserName = $BrowserName -replace "\\|\/|;|:|#|\.|\*|\?|=|<|>|\||\[|\]|`'|`"|\(|\)","_"
					If ($BrowserName.Length -gt 38) {$BrowserName = $BrowserName.Substring(0,38) }						
					
					$Name = $Name -replace "\\|\/|;|:|#|\.|\*|\?|=|<|>|\||\[|\]|`'|`"|\(|\)","_"
					If ($Name.Length -gt 38) {$Name = $Name.Substring(0,38) }
					$am_xa_folderpath = $am_xa_folderpath -replace ";|:|#|\.|\*|\?|=|<|>|\||\[|\]|`'|`"|\(|\)","_"						
					
						
					#endregion
					
					If (-not(Test-Path $PATrackingFolder))
					{
						[void] (New-Item -ItemType Directory -Path $PATrackingFolder -Force)
					}
					
					Write-Verbose "Check if the application was already created"
					$Package = Get-AMPackage -Name $env:am_pkg_name | Select -First 1
					$PKGTrackingPath = Join-Path $PATrackingFolder $Package.Name
					If (-not(Test-Path $PKGTrackingPath)) { [void] (New-Item -Type Directory -Path $PKGTrackingPath) }
					$AITrackingPath = Join-Path $PKGTrackingPath "$($ActionItem.Name)_$($ActionItem.Id).txt"
					$AppCreated = Test-Path $AITrackingPath
					
					
					# Add myself to server list of application
					If ($AppCreated -eq $true)
					{
						
							# Check if pkg revision was changed compared to last update of app
							$LastUpdateRevision = (Get-Content $AITrackingPath)
							If ($Package.Version.VersionNumber -le $LastUpdateRevision.Split(".")[0])
							{
								Write-Verbose "Published app $($BrowserName) was already created, and no modifications were detected, not updating app"
								$CreateApp = $false
							}
							else
							{
								Write-Verbose "Published app $($BrowserName) was already created, but modifications were detected, updating app"
							}
					}

					If ($CreateApp -eq $true)
					{
						Write-Verbose "Getting the desktop group UUID from registry"
						If (Test-Path "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent\State")
						{
							$DesktopGroupUUID = (gp "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent\State") | Select-Object -ExpandProperty DesktopGroupId -ea Silent
							If ($DesktopGroupUUID -ne $null)
							{
								Write-Verbose "Getting DDCs from registry"
								# Determine activebroker
								$ListOfDDCs = (gp "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent") | Select-Object -ExpandProperty ListOfDDcs -ea Silent
								If ($ListOfDDCs -ne $null)
								{
									foreach ($DDC in $ListOfDDcs.Split() | ? {-not ([string]::IsNullOrEmpty($_))})
									{
										Write-Verbose "Querying DDC: $($DDC)"
										try 
										{
											$BrokerService = Get-Service -Computername $DDC -Name CitrixBrokerService -ea silent
											If ($BrokerService -eq $null)
											{
												Write-Verbose "Unable to find CitrixBrokerService on $($DDC)"
												continue
											}
											else
											{
												Write-Verbose "CitrixBrokerService status: $($BrokerService.Status)"
											}
											
											$ConfigService = Get-Service -Computername $DDC -Name CitrixConfigurationService -ea silent
											If ($ConfigService -eq $null)
											{
												Write-Verbose "Unable to find CitrixConfigurationService on $($DDC)"
												continue
											}
											else
											{
												Write-Verbose "CitrixConfigurationService status: $($ConfigService.Status)"
											}
											If (($ConfigService.Status -eq "Running") -and ($BrokerService.Status -eq "Running"))
											{
												Write-Verbose "Setting activebroker variable to $($DDC)"
												$ActiveBroker = $DDC
												continue
											}
										}
										catch
										{									
											continue
										}								
									}
									If (Test-Path Variable:ActiveBroker)
									{
										Write-Verbose "Publishing application using broker: $($ActiveBroker)"
										try
										{
											foreach ($Group in $Groups)
											{
												$GroupSID = (Get-AMSID -Name $Group).Value
												$ComputerSID = (Get-AMSID -Name $env:Computername).Value
												Write-Verbose "Getting VDA installdir and loading icon converter"
												$AgentInstallDir = (gp "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent\InstallData").Location
												[void] ([Reflection.Assembly]::LoadFile($($AgentInstallDir + "\Citrix.IconConverter.dll")))
												Write-Verbose "Converting icon to base64 encoded string"
												$bytes = [Citrix.IconConverter.ExtractIcon]::FromFile($IconPath)
												$icon = [System.Convert]::ToBase64String($bytes[0])

												Invoke-Command -Verbose:$true -Computername $ActiveBroker -ArgumentList @($BrowserName,$Name,$am_xa_clientfolder,$am_xa_addtodesktop,$am_xa_addtostartmenu,$am_xa_cpu_prio,$am_xa_folderpath,$am_xa_publishFTE,$am_xa_waitforprinter,$WorkDir,$GroupSID,$Folder,$Description,$Arguments,$Target,$DesktopGroupUUID,$ComputerSID,$Icon,$EnableMaintenanceMode) -ScriptBlock {
													[CmdletBinding()]
													Param
													(
														$BrowserName,
														$Name,
														$am_xa_clientfolder,
														$am_xa_addtodesktop,
														$am_xa_addtostartmenu,
														$am_xa_cpu_prio,
														$am_xa_folderpath,
														$am_xa_publishFTE,
														[boolean]$am_xa_waitforprinter,
														$WorkDir,
														$GroupSID,
														$Folder,
														$Description,
														$Arguments,
														$Target,
														$DesktopGroupUUID,
														$ComputerSID,
														$Icon,
														$EnableMaintenanceMode
														
													)
													$VerbosePreference=$Using:VerbosePreference
													Add-PSSnapin Citrix*
													$DesktopGroup = Get-BrokerDesktopGroup -UUID $DesktopGroupUUID
													If ($EnableMaintenanceMode -eq $true)
													{
														$BrokerDesktop = Get-BrokerMachine -Sid $ComputerSID -ea silent
														If ($BrokerDesktop -ne $null)
														{
															Set-BrokerMachineMaintenanceMode -InputObject $BrokerDesktop -MaintenanceMode $true
														}
													}
													Write-Verbose "Test if application $($BrowserName) exists"
													$AppExist = Get-BrokerApplication -BrowserName $BrowserName -ea Silent
													Write-Verbose "Testing if folder $($am_xa_folderpath) exists"
													$Parent = $null																						
													ForEach ($folder in $am_xa_folderpath.Split("\/"))
													{
														If ($Parent -ne $null)
														{														
															$xa_folder = Get-BrokerAdminFolder -Name "$($Parent)$($folder)\" -ea Silent
														}
														else
														{
															$xa_folder = Get-BrokerAdminFolder -FolderName "$folder" -ea Silent
														}
														
														If ($xa_folder -eq $null)
														{
															if ($Parent -ne $null)
															{
																New-BrokerAdminFolder -FolderName $folder -Parent $Parent
															}
															else
															{
																New-BrokerAdminFolder -FolderName $folder
															}
														}
													   
														$Parent += $folder + "\"                                                   
													}
													
													$BrokerIcon = New-BrokerIcon -EncodedIconData $Icon
													If ($AppExist -ne $null)
													{
														Write-Verbose "Application $($BrowserName) already exists, updating application"
														[void] (Set-BrokerApplication -InputObject $AppExist `
																				-ClientFolder $am_xa_clientfolder `
																				-CommandLineArguments $Arguments `
																				-CommandLineExecutable $Target `
																				-CpuPriorityLevel $am_xa_cpu_prio `
																				-Description $Description `
																				-Enabled $True `
																				-IconUid $BrokerIcon.Uid `
																				-PublishedName $Name `
																				-StartMenuFolder $Folder `
																				-SecureCmdLineArgumentsEnabled $True `
																				-ShortcutAddedToDesktop $am_xa_addtodesktop `
																				-ShortcutAddedToStartMenu $am_xa_addtostartmenu `
																				-UserFilterEnabled $True `
																				-Visible $True `
																				-WorkingDirectory $WorkDir `
																				-WaitForPrinterCreation $am_xa_waitforprinter)
																				
													}
													else
													{
														
														
														Write-Verbose "Creating published app $($BrowserName)"
														[void] (New-BrokerApplication -ClientFolder $am_xa_clientfolder `
																				-BrowserName $BrowserName `
																				-AdminFolder $am_xa_folderpath `
																				-ApplicationType 'HostedOnDesktop' `
																				-CommandLineArguments $Arguments `
																				-CommandLineExecutable $Target `
																				-CpuPriorityLevel $am_xa_cpu_prio `
																				-DesktopGroup $DesktopGroup.Uid `
																				-Description $Description `
																				-Enabled $True `
																				-Name $Name `
																				-Priority 0 `
																				-IconUid $BrokerIcon.Uid `
																				-PublishedName $Name `
																				-StartMenuFolder $Folder `
																				-SecureCmdLineArgumentsEnabled $True `
																				-ShortcutAddedToDesktop $am_xa_addtodesktop `
																				-ShortcutAddedToStartMenu $am_xa_addtostartmenu `
																				-UserFilterEnabled $True `
																				-Visible $True `
																				-WorkingDirectory $WorkDir `
																				-WaitForPrinterCreation $am_xa_waitforprinter)
																				
														
													}
													
													
													Write-Verbose "Checking if user is already a broker user"
													
													$BrokerUser = Get-BrokerUser -SID $GroupSID -ea silent
													If ($BrokerUser -eq $null)
													{
														Write-Verbose "Creating brokeruser for SID $($GroupSID)"
														$BrokerUser = New-BrokerUser -SID $GroupSID																	
													}
													#$BrokerUser = Get-BrokerUser -SID $GroupSID								
													$BrokerApp = Get-BrokerApplication -BrowserName $($BrowserName) 
													Write-Verbose "Checking security group for published app $($BrowserName)"
													If ($BrokerApp.AssociatedUserNames -notcontains $BrokerUser.Name)
													{
														Write-Verbose "Adding $($BrokerUser.Name) to $($BrowserName)"
														Add-BrokerUser  -Application $BrokerApp.Uid -Name $BrokerUser.Name
													}
													
																
													Write-Verbose "Setting FTA for published app $($BrowserName)"
													If ($am_xa_publishFTE -eq $true)
													{
														Write-Verbose "Getting desktopUid for $ComputerSID"
														$BrokerMachine = Get-BrokerMachine -SID $ComputerSID
														Write-Verbose "Updating broker imported FTAs from $($BrokerMachine.Name)"
														Update-BrokerImportedFTA -DesktopUids $BrokerMachine.DesktopUid
														$FTAs = Get-BrokerImportedFTA -OpenExecutableName (Split-Path $Target -Leaf)
														Write-Verbose "Adding FTAs for $($BrowserName)"
														ForEach ($FTA in $FTAs)
														{
															[void] (New-BrokerConfiguredFTA -ApplicationUid $BrokerApp.Uid -ImportedFTA $FTA)
														}
													}
													else
													{
														Get-BrokerConfiguredFTA -ApplicationUid $BrokerApp.Uid | Remove-BrokerConfiguredFTA
													}
													Write-Verbose "Adding application to desktop group"
													$App = Get-BrokerApplication -BrowserName $BrowserName
													Add-BrokerApplication -DesktopGroup $DesktopGroup.Uid -InputObject $App

													If ($EnableMaintenanceMode -eq $true)
													{
														$BrokerDesktop = Get-BrokerMachine -Sid $ComputerSID -ea silent
														If ($BrokerDesktop -ne $null)
														{
															Set-BrokerMachineMaintenanceMode -InputObject $BrokerDesktop -MaintenanceMode $false
														}
													}
												
												}
												Write-Verbose "Setting  pkg revision number in $($AITrackingPath)"
												Set-Content -Path $AITrackingPath -Value $Package.Version -Force
											}
										}
										catch
										{
											Write-AMWarning $_
										}
										
									}
									else
									{
										Write-AMWarning "Unable to detect active controller for this machine, unable to publish application"
									}
									
								}
								else
								{
									Write-AMWarning "Unable to detect list of controllers for this machine, unable to publish application"
								}
							}
							else
							{
								Write-AMWarning "Unable to detect desktop group for this machine, unable to publish application"
							}
						}
						else
						{
							Write-AMWarning "Unable to detect virtual desktop agent state information, unable to publish application"
						}


					}
					
				}
				else
				{
					Write-AMInfo "XenApp/XenApp/XenDesktop publishing is disabled"
				}
			}
			"View6"
            {
                If ($am_view_publish -eq $true)
				{
					If ($PublishAllUsers -ne $true)
					{
						foreach ($Group in $Groups)
						{
							If ((Get-AMLDAPPath $Group) -eq $null)
							{
								throw "Unable to find group: $group"
							}
						}
					}
					else
					{
						$Group[0] = "Domain Users"
					}
					$AppCreated = $false
					$CreateApp = $true
						
					$PATrackingFolder = "$($AMCentralPath)\$($AMEnvironment.Id)\monitoring\View6\$($am_col_path)"
                    
                    If (-not(Test-Path $PATrackingFolder))
					{
						[void] (New-Item -ItemType Directory -Path $PATrackingFolder -Force)
					}
					
					Write-Verbose "Check if the application was already created"
					$Package = Get-AMPackage -Name $env:am_pkg_name | Select -First 1
					$PKGTrackingPath = Join-Path $PATrackingFolder $Package.Name
					If (-not(Test-Path $PKGTrackingPath)) { [void] (New-Item -Type Directory -Path $PKGTrackingPath)}
					$AITrackingPath = Join-Path $PKGTrackingPath "$($ActionItem.Name)_$($ActionItem.Id).txt"
					$AppCreated = Test-Path $AITrackingPath
					
					
					# Add myself to server list of application
					If ($AppCreated -eq $true)
					{
						
							# Check if pkg revision was changed compared to last update of app
							$LastUpdateRevision = (Get-Content $AITrackingPath)
							If ($Package.Version.VersionNumber -le $LastUpdateRevision.Split(".")[0])
							{
								Write-Verbose "Published app $($Name) was already created, and no modifications were detected, not updating app"
								$CreateApp = $false
							}
							else
							{
								Write-Verbose "Published app $($Name) was already created, but modifications were detected, updating app"
							}
					}

					If ($CreateApp -eq $true)
					{
                        If (Test-Path "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\Node Manager")
                        {
                            
                            $RegKey = (Get-Item "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\Agent\Configuration" -ea SilentlyContinue)
                            If ($RegKey -ne $null)
                            {
                                $Broker =  $RegKey.GetValue("Broker").ToString().Trim()
                                Write-Verbose "Using $Broker as broker to connect to"
                                $Node = (Get-Item "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\Node Manager" -ea SilentlyContinue)
                                If ($Node -ne $null)
                                {                                    
                                    #Publish/update the application
                                    Set-AMViewApplication -DisplayName $Name -Name ($AMEnvironment.Prefix + $Name) -Path $Target -IconPath $IconPath -Principal $Groups[0] -ConnectionServer $Broker

                                    #Update published application cache
                                    Write-Verbose "Setting  pkg revision number in $($AITrackingPath)"
								    Set-Content -Path $AITrackingPath -Value $Package.Version -Force
                                }
                                
                                                                 
                            }
							else
							{
								Write-AMWarning "Unable to detect broker for this machine, unable to publish application"
							}
                        }
                        else
                        {
                            Write-AMWarning "Unable to find Agent Node information on this machine, unable to publish application"
                        }
                    }


                }
				else
				{
					Write-AMInfo "VMware view publishing is disabled"
				}
                
            }
            default {Write-AMWarning "Unable to detect application publishing method. Is this server a XenApp or RDS server?"}
		}
	}	
}