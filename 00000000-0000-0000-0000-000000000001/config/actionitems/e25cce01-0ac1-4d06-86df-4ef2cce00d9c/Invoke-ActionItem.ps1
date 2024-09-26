<#
	.Synopsis
	Invokes the create folder action item.

	.Description
 	Invokes the specified create folder actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCreateFolder -ActionItem $ActionItem
#>
function Invoke-AMActionItemCreateFolder
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
	$Path = $($Variables | ? {$_.name -eq "Path"}).Value.Path | Expand-AMEnvironmentVariables
	If (!(Test-Path $Path))
	{
		Write-AMInfo "Creating folder $Path"
		[void] (New-Item -Path $Path -ItemType Directory -ErrorAction Stop)
	}
	Else
	{
		Write-AMInfo "The path $Path already exists"
	}
	
}