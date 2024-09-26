<#
	.Synopsis
	Invokes the map network printer action item.

	.Description
 	Invokes the specified map network printer actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemMapDrive -ActionItem $ActionItem
#>
function Invoke-AMActionItemMapPrinter
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
	$UNCPath = $($Variables | ? {$_.name -eq "UNC Path"}).Value | Expand-AMEnvironmentVariables


	Write-Verbose "Mapping network printer $UNCPath with currently logged on user context"
	Connect-AMPrinter -UNCPath $UNCPath


		
	

	
}