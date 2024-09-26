<#
	.Synopsis
	Invokes the copy folder action item.

	.Description
 	Invokes the specified copy folder actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCopyFolder -ActionItem $ActionItem
#>
function Invoke-AMActionItemCopyFolder
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
	$Folder = $($Variables | ? {$_.name -eq "Folder"})
	$Destination = $($Variables | ? {$_.name -eq "Destination"}).Value.Path | Expand-AMEnvironmentVariables
	$Overwrite = $($Variables | ? {$_.name -eq "Overwrite existing files"}).Value
		
	# Get zipfile location from datamanager
	$ZipFile = Get-AMImportedFilePath $Folder
		
	if ($Overwrite)
	{
		Expand-AMZipFile -Path $ZipFile -Destination $Destination -Overwrite
	}
	else
	{
		Expand-AMZipFile -Path $ZipFile -Destination $Destination
	}
}