$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
$Plugin = Get-AMPlugin -Id $PluginId
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)

$FirstBoot = $False
try
{
    $FirstBoot = [boolean] (Get-ItemProperty -Path "HKLM:\SOFTWARE\Automation Machine\Status" -Name FirstBootAfterSeal -ErrorAction SilentlyContinue).FirstBootAfterSeal
    
} catch {}

If ($FirstBoot -eq $true)
{
	Write-AMInfo "System is still processing it's first boot sequence, not enabling RDS maintenance mode"
}
elseif (($pluginenabled -eq $true) -and ((get-module -ListAvailable | ? {$_.name -eq "RemoteDesktop"} | measure).count -ge 1))
{
    # Get current logon mode for server
    $LogonMode = Get-AMLogonMode

	If ((Get-WindowsFeature -Name RDS-RD-Server).InstallState -eq "Installed")
	{
		Write-AMInfo "Enabling RDS maintenance mode"
		Import-Module RemoteDesktop
		
		[string] $AMMaintenanceCollection = "AM Maintenance"	
		[string] $AMCollectionDescription = "Collection that is used for maintenance purposes"
		
		# Get the current collection alias of this server and store it in registry for safekeeping
		[string] $Alias = (Get-WmiObject -Namespace Root\Cimv2\TerminalServices -Class Win32_TSSessionDirectory -Authentication PacketPrivacy -Impersonation Impersonate).SessionDirectoryClusterName
		[string] $RDCB = (Get-WmiObject -Namespace Root\Cimv2\TerminalServices -Class Win32_TSSessionDirectory -Authentication PacketPrivacy -Impersonation Impersonate).SessionDirectoryLocation.Split(";")[0]

		If (-not [string]::IsNullOrEmpty($RDCB))
		{
			# Try to use AM collection if RDS collection is still "AM Maintenance"
			$CurrentCollectionName = (Get-WMIObject -Namespace root\cimv2\rdms -class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate | Where-Object {$_.Alias -eq $Alias}).Name
			if ($CurrentCollectionName -eq $AMMaintenanceCollection)
			{
				$AMCollectionName = (Get-AMCollection -Current).Name
				$RDSHCollection = (Get-WMIObject -Namespace root\cimv2\rdms -class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate) | Where-Object {$_.Name -eq $AMCollectionName}
				if ($RDSHCollection -ne $null -and ![string]::IsNullOrEmpty($RDSHCollection.Alias))
				{
					$Alias = $RDSHCollection.Alias
					Write-AMWarning "Server was still in maintenance collection, using `"$Alias`" as a collection"
				}
				else {
					Write-AMError "Server was still in maintenance collection, and no RDS collection corresponds to the AM Collection. Please move back server to correct RDS collection manually"
				}
			}
			
			[string] $h = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).HostName
			[string] $d = ([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()).DomainName
			[string] $RDSH = "$h.$d"
			
			$HA = Get-AMRDConnectionBrokerHighAvailability -ConnectionBroker $RDCB -Retry 3 -RetryIntervalSeconds 60
			If ($HA -ne $null)
			{
				$RDCB = $HA.ActiveManagementServer
			}
		
			# Add computer to deployment if not already added
			if ((Get-RDServer -ConnectionBroker $RDCB -Role RDS-RD-SERVER).Server -notcontains $rdsh)
			{
				Write-host "Adding $rdsh to to deployment on $rdcb"
				Add-RDServer -Server $rdsh -ConnectionBroker $rdcb -ErrorAction stop -Role RDS-RD-SERVER
			}
			Write-AMInfo "Moving $RDSH to $AMMaintenanceCollection collection on $RDCB"
			
			Set-ItemProperty -Path "HKLM:\Software\Automation Machine" -Name "RDSCollectionAlias" -Value $Alias -Type String -Force
			
			# Remove server from current collection
			Remove-RDSessionHost -SessionHost $RDSH -ConnectionBroker $RDCB -Force
			
			# See if there's a maintenance collection
			$Result = Get-WMIObject -Namespace Root\Cimv2\RDMS -Class Win32_RDSHCollection -Computername $RDCB -Authentication PacketPrivacy -Impersonation Impersonate | ? {$_.Name -eq $AMMaintenanceCollection}
			If ($Result -isnot [Object])
			{
				#Create the maintenance collection
			    try
                {	
                    New-RDSessionCollection -CollectionName $AMMaintenanceCollection -CollectionDescription $AMCollectionDescription -SessionHost $RDSH -ConnectionBroker $RDCB -ErrorAction Stop
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
				Set-RDRemoteDesktop -CollectionName $AMMaintenanceCollection -ConnectionBroker $RDCB -ShowInWebAccess $False -Force
				Set-RDSessionCollectionConfiguration -CollectionName $AMMaintenanceCollection -ConnectionBroker $RDCB -UserGroup "Domain Admins"
			}
			Else
			{
				# Get the maintenance collection, just to make sure it exists and is accessible
				$Result = Get-RDSessionCollection -CollectionName $AMMaintenanceCollection -ConnectionBroker $RDCB
    	        try
                {
                    Add-RDSessionHost -CollectionName $AMMaintenanceCollection -ConnectionBroker $RDCB -SessionHost $RDSH -ErrorAction Stop
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
			Write-AMInfo "Could not detect connection broker, unable to enable maintenance mode" 
		}
	}
    
    # Set original logonmode for server
    Set-AMLogonMode -Mode $LogonMode	
	
}	