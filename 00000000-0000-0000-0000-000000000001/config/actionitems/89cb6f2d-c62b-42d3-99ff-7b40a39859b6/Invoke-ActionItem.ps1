<#
	.Synopsis
	Invokes the create scheduled task action item.

	.Description
 	Invokes the specified create scheduled task actionitem.

	.Parameter Actionitem
	Specifies the actionitem which to invoke.

 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemRegisterSchTask -ActionItem $ActionItem
#>
function Invoke-AMActionItemRegisterSchTask
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
	$Taskname = $($Variables | ? {$_.name -eq "Task name"}).Value | Expand-AMEnvironmentVariables
	$Command = $($Variables | ? {$_.name -eq "Command"}).Value | Expand-AMEnvironmentVariables
	$Arguments = $($Variables | ? {$_.name -eq "Arguments"}).Value | Expand-AMEnvironmentVariables
	$WorkingDir = $($Variables | ? {$_.name -eq "Working directory"}).Value | Expand-AMEnvironmentVariables
	$Credentials = $($Variables | ? {$_.name -eq "Credentials"}).Value #| Expand-AMEnvironmentVariables
	$HighestPrivileges = $($Variables | ? {$_.name -eq "Run with highest privileges"}).Value #| Expand-AMEnvironmentVariables
	$LogonType = $($Variables | ? {$_.name -eq "LogonType"}).Value | Expand-AMEnvironmentVariables
	$Trigger = $($Variables | ? {$_.name -eq "Trigger"}).Value | Expand-AMEnvironmentVariables
	$At = $($Variables | ? {$_.name -eq "At"}).Value | Expand-AMEnvironmentVariables
	$DaysInterval = $($Variables | ? {$_.name -eq "DaysInterval"}).Value | Expand-AMEnvironmentVariables
	$DaysOfWeek = $($Variables | ? {$_.name -eq "DaysOfWeek"}).Value | Expand-AMEnvironmentVariables
	$WeeksInterval = $($Variables | ? {$_.name -eq "WeeksInterval"}).Value | Expand-AMEnvironmentVariables
	$RepetitionInterval = $($Variables | ? {$_.Id -eq "f2e1df5d-d924-4540-bfff-63fd0f1a90cc"}).Value | Expand-AMEnvironmentVariables
	$RepetitionDuration = $($Variables | ? {$_.Id -eq "778690b2-6b2a-436c-9799-8b398994cd08"}).Value | Expand-AMEnvironmentVariables
	$EventLog = $($Variables | ? {$_.name -eq "EventLog"}).Value | Expand-AMEnvironmentVariables
	$EventID = $($Variables | ? {$_.name -eq "EventID"}).Value | Expand-AMEnvironmentVariables

	# Translate trigger
	If ($Trigger -eq "At startup") {$Trigger = "Startup"}
	If ($Trigger -eq "At logon") {$Trigger ="Logon"}


	If ($LogonType -eq "Run only when user is logged on")
	{
		$LoggedOn = $true
	}
	Else
	{
		$LoggedOn = $false
	}

	If (!($Credentials.Username))
	{
			# No credentials supplied, use service account
			$Credentials = $AMDataManager.ReadEnvironment($AMEnvironment.Id,$true).ServiceAccount
	}
	If (!($Credentials.Username))
	{throw "No credentials were specified, and Service Account for environment is not set, unable to create scheduled task"}

	If ($Trigger -eq "Event")
	{
		Register-AMScheduledTask -TaskName $Taskname -Command $Command -Arguments $Arguments -WorkingDir $WorkingDir -HighestPrivilege:$HighestPrivileges -RunOnlyWhenLoggedOn:$LoggedOn -Trigger $Trigger -Credentials $Credentials -EventLog $EventLog -EventID $EventID -RepetitionInterval $RepetitionInterval -RepetitionDuration $RepetitionDuration
	}
	else
	{
		Register-AMScheduledTask -TaskName $Taskname -Command $Command -Arguments $Arguments -WorkingDir $WorkingDir -HighestPrivilege:$HighestPrivileges -RunOnlyWhenLoggedOn:$LoggedOn -Trigger $Trigger -Credentials $Credentials -At $At -DaysInterval $DaysInterval -DaysOfWeek $DaysOfWeek -WeeksInterval $WeeksInterval -RepetitionInterval $RepetitionInterval -RepetitionDuration $RepetitionDuration
	}
}