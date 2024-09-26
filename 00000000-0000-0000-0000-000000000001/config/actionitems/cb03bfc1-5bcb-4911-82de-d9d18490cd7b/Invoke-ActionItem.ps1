<#
	.Synopsis
	Invokes the remove file/folder action item.

	.Description
 	Invokes the specified remove file/folder actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemRemoveFileFolder -ActionItem $ActionItem
#>
function Invoke-AMActionItemRemoveFileFolder
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
	If (Test-Path $Path)
	{
        if ((Get-Item -Path $Path).PSIsContainer -eq $true)
        {
	        [System.IO.Directory]::Delete($Path, $true)
		    #Remove-Item -Path $Path -Force -ErrorAction Stop
        }
        else
        {
            Remove-Item -Path $Path -Force -ErrorAction Stop
        }
	}
	else
	{
		Write-AMInfo "Could not find $($Path), unable to remove"
	}
	
	
}