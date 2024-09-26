<#
	.Synopsis
	Invokes the copy folder2 action item.

	.Description
 	Invokes the specified copy folder2 actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCopyFolder2 -ActionItem $ActionItem
#>
function Invoke-AMActionItemCopyFolder2 {
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AutomationMachine.Data.ActionItem] $ActionItem
    )
	
    Write-AMInfo "Invoking $($ActionItem.Name)"
    # Resolve the variables including the filters,
    $Variables = $ActionItem.Variables
    $Variables | % {Resolve-AMVariableFilter $_}
    $Variables | % {Resolve-AMMediaPath $_}
	
    # Get the variables from the actionitem
    $Folder = $($Variables | ? {$_.name -eq "Folder"}).Value.Path | Expand-AMEnvironmentVariables
    $Destination = $($Variables | ? {$_.name -eq "Destination"}).Value.Path | Expand-AMEnvironmentVariables
    $Overwrite = $($Variables | ? {$_.name -eq "Overwrite existing files"}).Value
	
	
    if ($Overwrite -eq $False) {
        Get-ChildItem $Folder -Recurse | ForEach-Object {            
            $FinalDestination = $($_.FullName).Replace("$Folder", "$Destination")
            If ((Test-Path $FinalDestination) -eq $False) {
                Copy-Item -Path $_.FullName -Destination $FinalDestination -ErrorAction SilentlyContinue -Force -Container
            }
        }       
    }
    elseif (Test-Path $Destination) {
        Copy-Item -Recurse -Path $("$Folder\*") -Destination $Destination -ErrorAction SilentlyContinue -Force -Container
    }
    else {
        Copy-Item -Recurse -Path $Folder -Destination $Destination -ErrorAction Stop -Force -Container
    }	
		
}