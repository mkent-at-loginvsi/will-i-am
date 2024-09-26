<#
	.Synopsis
	Invokes the rename file action item.

	.Description
 	Invokes the specified rename file actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItem -ActionItem $ActionItem
#>
function Invoke-AMActionItemRenameFile
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
	$Original = $($Variables | ? {$_.name -eq "Original"}).Value.Path | Expand-AMEnvironmentVariables
	$Desired = $($Variables | ? {$_.name -eq "Desired"}).Value.Path | Expand-AMEnvironmentVariables
	try
	{
		if (!(Test-Path -Path $Original))
		{
			Throw "The original file doesn't exist"
		}

		if (Test-Path -Path $Desired)
		{
			Throw "The desired file already exists"
		}

		Rename-Item $original $desired

	}
	catch
	{
		Throw $_
	}
}