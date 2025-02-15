$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
$Plugin = Get-AMPlugin -Id $PluginId
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)

If ($am_aborting -eq $true)
{
	Write-AMInfo "System is going down for reboot, not disabling RDS maintenance mode"
}
elseif (($pluginenabled -eq $true) -and ((get-module -ListAvailable | ? {$_.name -eq "RemoteDesktop"} | measure).count -ge 1))
{
    # Get current logon mode for server
    $LogonMode = Get-AMLogonMode

	If ((Get-WindowsFeature -Name RDS-RD-Server).InstallState -eq "Installed")
	{
		Import-Module RemoteDesktop
		
		[string] $AMMaintenanceCollection = "AM Maintenance"	
		[string] $AMCollectionDescription = "Collection that is used for maintenance purposes"
		
		
		
		
		# Get the current collection alias of this server and store it in registry for safekeeping
		[string] $Alias = (Get-WmiObject -Namespace Root\Cimv2\TerminalServices -Class Win32_TSSessionDirectory -Authentication PacketPrivacy -Impersonation Impersonate).SessionDirectoryClusterName 
		[string] $RDCB = (Get-WmiObject -Namespace Root\Cimv2\TerminalServices -Class Win32_TSSessionDirectory -Authentication PacketPrivacy -Impersonation Impersonate).SessionDirectoryLocation.Split(";")[0]
		[string] $h = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).HostName
		[string] $d = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).DomainName
		[string] $RDSH = "$h.$d"
		
		If (-not [string]::IsNullOrEmpty($RDCB))
		{
			$HA = Get-AMRDConnectionBrokerHighAvailability -ConnectionBroker $RDCB -Retry 3 -RetryIntervalSeconds 60
			If ($HA -ne $null)
			{
				$RDCB = $HA.ActiveManagementServer
			}
			
			# Process first boot configuration
			$Reg = (Get-Item -Path "HKLM:\Software\Automation Machine")
			$AliasReg = $Reg.GetValue("RDSCollectionAlias")
			If ($AliasReg -ne $null)
			{
			
				$FirstBoot = $False
				try
				{
					$FirstBoot = [boolean] (Get-ItemProperty -Path "HKLM:\SOFTWARE\Automation Machine\Status" -Name FirstBootAfterSeal -ErrorAction SilentlyContinue).FirstBootAfterSeal
					
				} catch {}

				If ($FirstBoot -eq $true)
				{
					Write-AMInfo "Processing first boot sequence for $rdsh"
					if ((Get-RDServer -ConnectionBroker $RDCB -Role RDS-RD-SERVER).Server -notcontains $rdsh)
					{
						Write-host "Adding $rdsh to to deployment on $rdcb"
						Add-RDServer -Server $rdsh -ConnectionBroker $rdcb -ErrorAction stop -Role RDS-RD-SERVER
					}
					$Result = Get-WMIObject -Namespace Root\Cimv2\RDMS -Class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate | ? {$_.Alias -eq $AliasReg}
					If ((Get-RDSessionHost -ConnectionBroker $rdcb -CollectionName $Result.Name).SessionHost -notcontains $rdsh)
					{
						Write-AMInfo "Adding $RDSH to $AliasReg collection"
						Add-RDSessionHost -CollectionName $Result.Name -ConnectionBroker $RDCB -SessionHost $RDSH
					}
					
				}
		
				If ($Alias -ne $AliasReg)
				{
					
				
					# Remove server from current collection
					Remove-RDSessionHost -SessionHost $RDSH -ConnectionBroker $RDCB -Force
				
					# See if the collection exists
					$Result = Get-WMIObject -Namespace Root\Cimv2\RDMS -Class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate | ? {$_.Alias -eq $AliasReg}
					If ($Result -isnot [Object])
					{
						#Create the maintenance collection
						Throw "Unable to move computer back to collection $AliasReg, it does not exist"
					}	
					Else
					{
						Write-AMInfo "Moving $RDSH to $AliasReg collection"
						# Get the maintenance collection, just to make sure it exists and is accessible
						$Check = Get-RDSessionCollection -CollectionName $Result.Name -ConnectionBroker $RDCB
						try
                        {
                            Add-RDSessionHost -CollectionName $Result.Name -ConnectionBroker $RDCB -SessionHost $RDSH -ErrorAction Stop
                        }
                        catch [Exception]
                        {
                            if ($($_.FullyQualifiedErrorId) -eq "GPSettingfailed,Microsoft.RemoteDesktopServices.Management.Cmdlets.AddRDSessionHostServerCommand") 
	                        {
	                            # This is an error thrown by the MS remotedesktop module that should actually be a warning due to a setting in a gpo
                                Write-Host "WARNING: $_" -ForegroundColor Yellow
	                        }
                            else
                            {
                                Throw $_
                            }
                        }
					}
				}
				Else
				{
					Write-AMInfo "$RDSH is already member of $Alias"
				}
			}
		}
		Else
		{
			Write-AMInfo "Could not detect connection broker, unable to disable maintenance mode" 
		}
	}
    # Set original logonmode for server
    Set-AMLogonMode -Mode $LogonMode
	
}	