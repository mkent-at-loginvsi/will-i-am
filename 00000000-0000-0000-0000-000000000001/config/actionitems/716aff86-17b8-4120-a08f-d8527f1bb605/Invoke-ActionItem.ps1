<#
	.Synopsis
	Invokes the custom script action item.

	.Description
 	Invokes the specified custom script actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCustomScript -ActionItem $ActionItem
#>
function Invoke-AMActionItemExternalProcess 
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
	$Variables | ForEach-Object {Resolve-AMVariableFilter $_}
	$Variables | ForEach-Object {Resolve-AMMediaPath $_}
	
	$Executable = $($Variables | Where-Object {$_.name -eq "Executable"}).Value.Path | Expand-AMEnvironmentVariables
	$Arguments = $($Variables | Where-Object {$_.name -eq "Arguments"}).Value | Expand-AMEnvironmentVariables
	$Wait = $($Variables | Where-Object {$_.name -eq "Wait for process to finish"}).Value
	$ExitCode = $($Variables | Where-Object {$_.name -eq "Success return codes"}).Value | Expand-AMEnvironmentVariables
	$WaitForChildProcesses = $($Variables | Where-Object {$_.name -eq "Wait for child processes"}).Value
	$ChildProcessesTimeout = $($Variables | Where-Object {$_.name -eq "Child processes timeout in seconds"}).Value | Expand-AMEnvironmentVariables
	
	if ($Wait)
	{
		Start-AMProcess -Path $Executable -Arguments $Arguments -ExpectedReturncode $ExitCode -WaitForChildProcesses $WaitForChildProcesses -ChildProcessesTimeout $ChildProcessesTimeout
	}
	else
	{
		Start-AMProcess -Path $Executable -Arguments $Arguments -NoWait
	}
}