<#
	.Synopsis
	Invokes the custom script 2 action item.

	.Description
 	Invokes the specified custom script 2 actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCustomScript2 -ActionItem $ActionItem
#>
function Invoke-AMActionItemCustomScript2 
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
	$Script = $($Variables | ? {$_.name -eq "Script"}).Value.Path | Expand-AMEnvironmentVariables
	$Arguments = $($Variables | ? {$_.name -eq "Arguments"}).Value | Expand-AMEnvironmentVariables
	$SuccessCodes = $($Variables | ? {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables
	
	# Invoke the script
	try
	{
		$TranscriptFile = $("$env:TEMP\$(Get-Date -f yyyyMMddHHmmss)-$(Get-Random).log")
		[void] (Start-Transcript -Path $TranscriptFile)
	}
	catch
	{
		Write-AMWarning "Could not start transcript for custom script, no output will be recorded in log"
	}
	Invoke-AMCustomScript -Path $Script -Arguments $Arguments -ExpectedReturncodes $SuccessCodes 
	try
	{
		[void] (Stop-Transcript)
	}
	catch
	{
	}
	If (Test-Path $TranscriptFile)
	{
		If (-not ([string]::IsNullOrEmpty($global:am_logfile)))		
		{
			Add-Content -Value (Get-Content $TranscriptFile) -Path $global:am_logfile
		}
	}
	
	
	
}