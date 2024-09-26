param
(
	$Plugins
)



# Set context
Set-Variable -Name am_context -Value "system" -Scope 3

If ((Test-AMElevation) -ne $true)
{
	throw "Process is not running elevated, unable to run startup"
}



#override abort and reboot preferences
$AMDataManager.RebootPreference = [AutomationMachine.Data.RebootPreference]::Reboot


# Some platform/event specific actions
Wait-AMSystemEvent
# Write status
Write-AMStatus "Processing Startup"
Update-AMCache
Enable-AMSystemEventFlag
#Disable-AMLogons
Wait-AMTrustedInstaller
Update-AMGroupPolicyObjects

# update cache on firstboot (after imaging)
$FirstBoot = $false
try
{
    $FirstBoot = ([boolean] (Get-ItemProperty -Path "HKLM:\SOFTWARE\Automation Machine\Status" -Name FirstBootAfterSeal -ErrorAction SilentlyContinue).FirstBootAfterSeal)

}catch{}

<#
# check if re-init is needed by cache update
$StatusPath = Join-Path $([AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT).Replace("HKEY_LOCAL_MACHINE","HKLM:") "Status"
$MaintenanceFlag = (Get-ItemProperty -Path $StatusPath -Name "Maintenance" -ErrorAction SilentlyContinue) 
$InitRequired = (Get-ItemProperty -Path $StatusPath -Name InitRequired -ErrorAction SilentlyContinue)


If (($InitRequired.InitRequired -eq $true) -and ($MaintenanceFlag.Maintenance -eq $true))
{
	Write-AMInfo "Re-init of system is required, because AM was updated, reiniting and rebooting..."
	Disable-AMSystemEventFlag	

	# Retrieve admin module and set scheduled task name/action
	$AMCentralPathEnvFolder = Join-Path $env:am_files $AMEnvironment.Id.ToString()
	Import-module "$AMCentralPathEnvFolder\bin\modules\admin\Automation Machine.psm1" -ArgumentList @($AMEnvironment.Id.ToString(),$true)

	# Set variables for scheduled task
	$SchTaskName = "Automation Machine Re-Init"
	Write-Verbose "Scheduled task name: $SchTaskName"
	$SchTaskCommand = "$AMCentralPathEnvFolder\Initialize-AM.ps1"
	Write-Verbose "Scheduled task command:`n    $SchTaskCommand"
	$SchTaskUserName = $AMEnvironment.ServiceAccount.UserName
	if($SchTaskUserName.StartsWith(".\")) {	$SchTaskUserName = $SchTaskUserName.Replace(".\",$env:COMPUTERNAME + "\")}
	if ([string]::IsNullOrEmpty($SchTaskUserName)) { throw "Service account is not set for the environment" }
	$SchTaskPassword = $AMEnvironment.ServiceAccount.Password

	# Connect to scheduled task com object & remove tasks
	$ScheduleService = New-Object -ComObject "Schedule.Service"
	$ScheduleService.Connect()
	$TaskFolder = $ScheduleService.GetFolder("\Automation Machine")
	$TaskFolder.GetTasks(1) | foreach {$TaskFolder.DeleteFolder($_.Name,0)}

	# Create new task
	$AMReInitTask = $ScheduleService.NewTask(0)
	$AMReInitTask.Principal.RunLevel = 1
	$AMReInitTask.Settings.RunOnlyIfIdle = $false
	$AMReInitTask.Settings.IdleSettings.StopOnIdleEnd = $false
	$AMReInitTask.Settings.DisallowStartIfOnBatteries = $false
	$AMReInitTask.Settings.StopIfGoingOnBatteries = $false
	$AMReInitTask.Settings.DisallowStartIfOnBatteries = $true
	$AMReInitTask.Settings.RunOnlyIfNetworkAvailable = $false
	$AMReInitTask.Settings.AllowDemandStart = $true
	$AMReInitTask.Settings.RestartInterval = "PT5M"
	$AMReInitTask.Settings.RestartCount = 3
	$AMReInitTask.Settings.StartWhenAvailable = $true
	$AMReInitTask.Settings.Enabled = $true
	$AMReInitTask.Settings.Priority = 3
	$RegInfo = $AMReInitTask.RegistrationInfo
	$RegInfo.Author = "Login AM"
	$RegInfo.Description = "Automation Machine Re-Init Task"
	$Triggers = $AMReInitTask.Triggers
	$Trigger = $Triggers.Create(8)
	$Trigger.Delay = "PT2M"
	$Action = $AMReInitTask.Actions.Create(0)
	$Action.Path = "powershell.exe"
	$Action.Arguments = "-file $SchTaskCommand"
	$SchTasksOutput = $TaskFolder.RegisterTaskDefinition($SchTaskName, $AMReInitTask, 6, $SchTaskUserName, $SchTaskPassword, 1)
	if ($SchTasksOutput.Xml) { Write-Verbose $SchTasksOutput.Xml }

	Enable-AMMaintenance
	$global:am_rebooting = $true
}
#>


& "$am_env_files\config\plugins\2933a65d-1b32-4600-b288-325fa550f2f4\Optional\WUA-AsConfigured.ps1"   #Deployment plugin

# Get me those variables
ForEach ($Plugin in $Plugins)
{
        Invoke-AMPluginInitialization -Plugin $Plugin
}
If (Test-Path Variable:Plugin) {. remove-Item variable:plugin -force}


# Execute optional plugin functions
& "$am_env_files\config\plugins\6952e8c1-459a-4ed3-b4ec-2506575e2069\Optional\RenameCPU.ps1" # System configuration plugin
Set-Variable -name image_enabled -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId 3efa9468-86b6-46a5-88e1-9c905a1226aa -CollectionId $am_col.Id).Value) | Expand-AMEnvironmentVariables
Set-Variable -Name am_col_removeam -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000005 -ParentId 3efa9468-86b6-46a5-88e1-9c905a1226aa -CollectionId $am_col.Id).Value)

if ($image_enabled -eq $false)
{
	& "$am_env_files\config\plugins\6952e8c1-459a-4ed3-b4ec-2506575e2069\Optional\AddToCollection.ps1" # System configuration plugin
}
else
{
	if ($am_col_removeam -eq $false)
	{
		& "$am_env_files\config\plugins\6952e8c1-459a-4ed3-b4ec-2506575e2069\Optional\AddToCollection.ps1" # System configuration plugin	
	}
}
& "$am_env_files\config\plugins\a28d9155-af9a-4f2a-81f1-c85fef611a21\Optional\Clear-ShortcutsCache.ps1" # Shortcuts plugin
& "$am_env_files\config\plugins\6952e8c1-459a-4ed3-b4ec-2506575e2069\Optional\MoveComputerToOU.ps1" # System configuration plugin


