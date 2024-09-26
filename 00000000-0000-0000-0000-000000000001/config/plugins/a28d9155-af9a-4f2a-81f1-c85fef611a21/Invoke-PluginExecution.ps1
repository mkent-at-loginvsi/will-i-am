param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package,
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

try
{
	if (($(Get-AMEventMap -Current).ErrorActionPreference -eq "Continue") -or ((Test-AMDeploymentCompletion -Package $Package) -eq $true)) {
		Set-Variable -Name am_pkg_pgroup -Scope 3 -Value([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000017" -ParentId "0008cfe0-532e-462f-99ba-4b5b16cf1754" -CollectionId $am_col.Id -ComponentId $Package.Id).Value | Expand-AMEnvironmentVariables)
		Set-Variable -Name am_pkg_pgroupfull -Scope 3 -Value ($am_col_gprefix + $am_pkg_pgroup + $am_col_gsuffix | Expand-AMEnvironmentVariables)
		Set-Variable -Name am_rds_publishFTE -Scope 3 -Value ([Boolean] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000025" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_rds_showWA -Scope 3 -Value ([Boolean] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000026" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_rds_autofix -Scope 3 -Value ([Boolean] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000023" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_rds_publish -Scope 3 -Value ([Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000060 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		
		Set-Variable -Name am_xa_waitforprinter -Scope 3 -Value ([Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000051 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_xa_clientfolder -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000052 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value | Expand-AMEnvironmentVariables)
		Set-Variable -Name am_xa_folderpath -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000053 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value | Expand-AMEnvironmentVariables)
		Set-Variable -Name am_xa_cpu_prio -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000054 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		
		Set-Variable -Name am_xa_addtostartmenu -Scope 3 -Value ([Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000056 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_xa_addtodesktop -Scope 3 -Value ([Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000057 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_xa_publishFTE -Scope 3 -Value ([Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000058 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_xa_publish -Scope 3 -Value ([Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000061 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		
		Set-Variable -Name am_view_publish -Scope 3 -Value ([Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000067 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		
		Set-Variable -Name am_col_enable_startmenu_publish -Scope 3 -Value ([Boolean] (Get-AMVariable -Id "00000000-0000-0000-0000-00000000002b" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		Set-Variable -Name am_col_enable_desktop_publish -Scope 3 -Value ([Boolean] (Get-AMVariable -Id "00000000-0000-0000-0000-00000000002a" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value)
		
		
		
	    Read-AMActionItems $Package
		$Package = Get-AMPackage -Id $Package.Id		
	    
		Invoke-AMActionSet -Package $Package -Plugin $Plugin
		return $true
	}
	else {
		Write-AMWarning "Deployment has not yet run for this package, unable to process actionsets for plugin $($Plugin.name)"
		return $false
	}
}
catch [Exception]
{
    throw $_
}