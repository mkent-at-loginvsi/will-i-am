[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# PROCESS LOGONASYNC EVENT FOR RDS 2012R2 Session Hosts

$ShouldBeProcessedAfterExplorer = [Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000016 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value
$am_col_gprefix = [string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000014" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables
$am_col_gsuffix = [string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000018" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables
$Everyone = [Boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000066 -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value

$am_pkg_pgroup  = [string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000017" -ParentId "0008cfe0-532e-462f-99ba-4b5b16cf1754" -CollectionId $am_col.Id -ComponentId $Package.Id).Value | Expand-AMEnvironmentVariables
$am_pkg_pgroupfull = $am_col_gprefix + $am_pkg_pgroup + $am_col_gsuffix #| Expand-AMEnvironmentVariables

if ($ShouldBeProcessedAfterExplorer -eq $true)
{
	If ((Test-AMMemberOf($am_pkg_pgroupfull)) -or $Everyone)
	{
		Invoke-AMPluginExecution -Package $Package -Plugin $Plugin
	}
	else
	{
		Write-AMInfo "User not member of $am_pkg_pgroupfull and Everyone option not set, not executing $($Plugin.Name) for $($Package.Name)"
	}
}