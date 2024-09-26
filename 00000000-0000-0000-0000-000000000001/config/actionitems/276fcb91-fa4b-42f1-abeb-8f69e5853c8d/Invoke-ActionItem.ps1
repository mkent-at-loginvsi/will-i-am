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
function Invoke-AMActionItemStartService
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
	$Wait = $($Variables | ? {$_.name -eq "Wait for service to start"}).Value | Expand-AMEnvironmentVariables
	$Seconds = $($Variables | ? {$_.name -eq "Amount of seconds to wait"}).Value | Expand-AMEnvironmentVariables

	If ($Wait)
	{
		Start-AMService -Name $ServiceName -Wait -Seconds $Seconds
	}
	else
	{
		Start-AMService -Name $ServiceName
	}
	
}