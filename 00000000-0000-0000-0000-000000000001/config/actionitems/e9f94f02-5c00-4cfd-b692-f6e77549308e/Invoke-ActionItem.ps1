<#
	.Synopsis
	Invokes the apply file permissions action item.

	.Description
 	Invokes the specified apply file permissions actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemApplyFilePermissions -ActionItem $ActionItem
#>
function Invoke-AMActionItemConfigureService
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
	
	$ServiceName = $($Variables | ? {$_.name -eq "Service Name"}).Value | Expand-AMEnvironmentVariables
	$StartupType = $($Variables | ? {$_.name -eq "Startup type"}).Value | Expand-AMEnvironmentVariables
	
	Set-Service $ServiceName -StartupType $StartupType
	
}