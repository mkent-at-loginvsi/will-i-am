$PluginId = $AmWellKnown::Plugins.SystemConfiguration.Id
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.EnableSystemConfigurationVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_ou -Value ([string]  (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.CollectionOuPathVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_col_movecomputers -Value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.AutoMoveComputersToOuVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)
Set-Variable -name am_col_createou -Value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.AutoCreateCollectionOuVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)
[string]  $tmp_am_col_ou_dn = ""
$am_col_ou.Split("\") | %{$tmp_am_col_ou_dn = ",ou=$($_)" + $tmp_am_col_ou_dn};
$tmp_am_col_ou_dn = $tmp_am_col_ou_dn.TrimStart(",");
Set-Variable -Name am_col_ou_dn -Value $tmp_am_col_ou_dn

if (($pluginenabled -eq $true) -and ($global:am_aborting -ne $true) -and ($am_col_movecomputers -eq $true))
{
	if ($am_offline -eq $false)
	{
		If ($null -eq (Get-AMComputerDomain))
		{
			Write-AMInfo "Computer not a member of a domain, skipping OU move"
		}
		else
		{

			# Check if the target OU exists and create it if needed
			if ($am_col_createou -eq $true)
			{
				Write-AMInfo "Checking collection OU in Active Directory"
				[string]  $CollectionLDAP = "LDAP://$am_col_ou_dn,$(Get-AMDomainDN)"
				[boolean] $TargetOUExists = [System.DirectoryServices.DirectoryEntry]::Exists($CollectionLDAP)

				if ($TargetOUExists -eq $false)
				{
					Write-AMInfo "Creating collection OU: $am_col_ou"
					[void] (New-AMOU -LDAPPath $CollectionLDAP)
				}        
			}

			# Check if the computer is in the correct OU. Move it if it if not
			if ($am_col_movecomputers -eq $true)
			{
				Write-AMInfo "Checking computer location in Active Directory"
				[string]  $CollectionLDAP = "LDAP://$am_col_ou_dn,$(Get-AMDomainDN)"
				[boolean] $TargetOUExists = [System.DirectoryServices.DirectoryEntry]::Exists($CollectionLDAP)

				if ($TargetOUExists -eq $true)
				{
					[string] $ComputerLDAP = Get-AMLDAPPath -Name $Env:COMPUTERNAME
			
					if ([string]::IsNullOrEmpty($ComputerLDAP) -eq $false)
					{
						[System.DirectoryServices.DirectoryEntry] $ComputerDE = Get-AMDirectoryEntry -LDAPPath $ComputerLDAP
						[System.DirectoryServices.DirectoryEntry] $ComputerParentDE = Get-AMDirectoryEntry -LDAPPath $ComputerDE.Parent
						[System.DirectoryServices.DirectoryEntry] $TargetDE = Get-AMDirectoryEntry -LDAPPath $CollectionLDAP

						if ($ComputerParentDE.Path -ne $CollectionLDAP)
						{

							#Write-AMInfo "Moving $($Env:COMPUTERNAME) to $am_col_ou"

							$DirectoryMoveResult = Move-AMDirectoryEntry -DirectoryEntry $ComputerDE -Destination $TargetDE.Path #$ComputerDE.psbase.moveto($TargetDE)
							If ($DirectoryMoveResult -eq $True) # computer object was moved, we need to reboot
							{
								$AMDataManager.RebootNeeded = $true
							}

						}
					}
					else
					{
						throw "Could not find computer object in Active Directory"
					}
				}
				else
				{
					throw "Collection OU `"$($CollectionLDAP)`" does not exist"
				}
			}
		}
	}
	else
	{
		Write-AMInfo "Computer is offline, skipping OU move"
	}
}	