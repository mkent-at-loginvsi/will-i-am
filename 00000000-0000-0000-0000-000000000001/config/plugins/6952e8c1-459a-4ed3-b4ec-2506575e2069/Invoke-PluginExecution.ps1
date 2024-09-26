param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Package] $Package,
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

try
{
	if (($(Get-AMEventMap -Current).ErrorActionPreference -eq "Continue") -or ((Test-AMDeploymentCompletion -Package $Package) -eq $true)) {
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