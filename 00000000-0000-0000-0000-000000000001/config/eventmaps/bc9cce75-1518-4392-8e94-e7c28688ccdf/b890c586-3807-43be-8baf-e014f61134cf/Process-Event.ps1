[CmdletBinding()]
param (
	
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin,
		
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package

)

# PROCESS LOGON EVENT FOR RDS 2012R2 Session Host

$ShouldBeProcessedAfterExplorer = [Boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.UserEnvironment.ExecuteUemActionsAfterExplorerStartedVariable.Id -ParentId $AmWellKnown::Plugins.UserEnvironment.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value
$Everyone = [Boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.UserEnvironment.ExecuteUemActionsForEveryoneVariable.Id -ParentId $AmWellKnown::Plugins.UserEnvironment.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value

$am_col_gprefix = [string] (Get-AMVariable -Id $AmWellKnown::Plugins.Security.GroupsPrefixVariable.Id -ParentId $AmWellKnown::Plugins.Security.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables
$am_col_gsuffix = [string] (Get-AMVariable -Id $AmWellKnown::Plugins.Security.GroupsSuffixVariable.Id -ParentId $AmWellKnown::Plugins.Security.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables

$am_pkg_pgroup  = [string] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.PrimaryGroupVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value | Expand-AMEnvironmentVariables
$am_pkg_pgroupfull = $am_col_gprefix + $am_pkg_pgroup + $am_col_gsuffix #| Expand-AMEnvironmentVariables

if ($ShouldBeProcessedAfterExplorer -eq $false)
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
