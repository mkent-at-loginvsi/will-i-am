param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package,
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

Write-Verbose "Starting security plugin for package"

if (($(Get-AMEventMap -Current).ErrorActionPreference -eq "Continue") -or ((Test-AMDeploymentCompletion -Package $Package) -eq $true)) {
	#If (!(Test-AMElevation)) {throw "Process is not running elevated, unable to process deployment plugin"}

	[Boolean] $am_pkg_createpgroup = (Get-AMVariable -Id "00000000-0000-0000-0000-00000000001B" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value
	[Boolean] $am_pkg_autosecure = (Get-AMVariable -Id "00000000-0000-0000-0000-000000000011" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value
	[String] $am_pkg_installdir = (Get-AMVariable -Id "00000000-0000-0000-0000-000000000004" -ParentId "0008cfe0-532e-462f-99ba-4b5b16cf1754" -CollectionId $am_col.Id -ComponentId $Package.Id).Value.Path | Expand-AMEnvironmentVariables
	
	[string]$am_pkg_pgroup  = (Get-AMVariable -Id "00000000-0000-0000-0000-000000000017" -ParentId "0008cfe0-532e-462f-99ba-4b5b16cf1754" -CollectionId $am_col.Id -ComponentId $Package.Id).Value | Expand-AMEnvironmentVariables
	[string]$am_pkg_pgroupfull = ($am_col_gprefix + $am_pkg_pgroup + $am_col_gsuffix | Expand-AMEnvironmentVariables)

	
	
	Write-AMInfo "Creating primary group for $($Package.Name)"
	#region Create security groups
	If ($am_col_createpgroups -eq $true)
	{
		If ($am_pkg_createpgroup -eq $true)
		{
			If ((Get-AMComputerDomain) -eq $null)
			{
				If ($am_col_gscope -ne [AutomationMachine.Plugins.ActiveDirectory.GroupScope]::Local) 
				{
					Write-AMWarning "The groupscope was set to: $am_col_gscope, but this computer is not a member of a domain, reverting to local groups"					
				}
				$GScope = [AutomationMachine.Plugins.ActiveDirectory.GroupScope]::Local
				[string] $OULDAP = "WinNT://$env:computername"
			}
			else
			{
				$GScope = $am_col_gscope
				[string] $OULDAP = "LDAP://$am_col_gou_dn,$(Get-AMDomainDN)"			
			}
			
			$PrimaryGroup = Get-AMLDAPPath -Name $am_pkg_pgroupfull
			If ($PrimaryGroup -is [Object])
			{
				Write-AMInfo "Security group $am_pkg_pgroupfull already exists"
			}
			Else
			{
				[void] (New-AMGroup -Name $am_pkg_pgroupfull -LDAPPath $OULDAP -Scope $GScope -Description ($am_col_gdescription | Expand-AMEnvironmentVariables))
			}			
		}
		Else
		{
			Write-AMInfo "Creation of primary groups disabled on $am_pkg_name"	
		}
	}
	Else
	{
		Write-AMInfo "Creation of primary groups disabled on collection $($am_col.Name)"
	}	
	#endregion
	
	#region Auto-Secure install folder
	Write-AMInfo "Securing install folder for $($Package.Name)"
	If ($am_pkg_autosecure -eq $true)
	{
		If (Test-Path $am_pkg_installdir)
		{
			$PrimaryGroup = Get-AMLDAPPath -Name $am_pkg_pgroupfull
			If ($PrimaryGroup -is [Object])
			{
				Set-AMPermissions -Path $am_pkg_installdir -Permissions "ReadAndExecute" -Type Allow -Recurse -PrincipalName $am_pkg_pgroupfull -Append
			}
			Else
			{
				Write-AMWarning "Primary group $am_pkg_pgroupfull does not exist, unable to secure install folder"
			}
			
		}
		Else
		{
			Write-AMWarning "Install folder $am_pkg_installdir could not be found, unable to secure install folder"
		}
	}
	Else
	{
		Write-AMInfo "Autosecure install folder disabled on $am_pkg_name"	
	}
	#endregion
	
	#region actionset processing
	Read-AMActionItems $Package
	$Package = Get-AMPackage -Id $Package.Id		
	    
    Invoke-AMActionSet -Package $Package -Plugin $Plugin
	return $true
}
else {
	Write-AMWarning "Deployment has not yet run for this package, unable to process actionsets for plugin $($Plugin.name)"
	return $false
}

Write-Verbose "Finished security plugin for package"
