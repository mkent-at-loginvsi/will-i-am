<#
	.Synopsis
	Invokes the set environment variable action item.

	.Description
 	Invokes the specified set environment variable actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemEnvVar -ActionItem $ActionItem
#>
function Invoke-AMActionItemEnvVar
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
	$Name = $($Variables | ? {$_.name -eq "Name"}).Value | Expand-AMEnvironmentVariables
	$Value = $($Variables | ? {$_.name -eq "Value"}).Value | Expand-AMEnvironmentVariables
	$Scope = $($Variables | ? {$_.name -eq "Scope"}).Value | Expand-AMEnvironmentVariables
	
	$Scope = [System.EnvironmentVariableTarget]::("$($Scope)")
	
	# Test if we can set machine variables.
	If ($Scope -eq [System.EnvironmentVariableTarget]::Machine)
	{
		If (!(Test-AMElevation)) {throw "Process is not running elevated, cannot set machine environment variable"}
	}

	# If envvar target is not process, we need to set the env var for both process and the other scope, otherwise it is not available to other actionitems that are running in this process.
	If ($Scope -ne [System.EnvironmentVariableTarget]::Process)
	{
		[System.Environment]::SetEnvironmentVariable($Name,$Value,[System.EnvironmentVariableTarget]::Process)
	}
	
	[System.Environment]::SetEnvironmentVariable($Name,$Value,$Scope)
		
	
}