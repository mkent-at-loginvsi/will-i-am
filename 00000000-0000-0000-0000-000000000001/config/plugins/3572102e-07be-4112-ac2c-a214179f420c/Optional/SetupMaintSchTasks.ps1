
$PluginID = Split-Path (Split-Path (Split-Path $script:MyInvocation.MyCommand.Path -Parent) -Parent) -Leaf
$Plugin = Get-AMPlugin -Id $PluginId
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $PluginID -CollectionId $am_col.Id).Value)

# Setup variables to use
Set-Variable -name am_maint_schedule -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000028 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_sch_days -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000029 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_sch_time -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000030 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -name am_maint_reporting_schedule -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000040 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_sch_days -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000041 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_sch_time -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000042 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_enable -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000043 -ParentId $PluginID -CollectionId $am_col.Id).Value)


#set up a connection to scheduled tasks management
$ScheduleService = New-Object -ComObject "Schedule.Service"
$ScheduleService.Connect()

#get Automation Machine's scheduled tasks folder
$TaskFolder = $ScheduleService.GetFolder("\") # root folder
	Try { $TaskFolder = $TaskFolder.GetFolder("Automation Machine")	}
	Catch { $TaskFolder = $TaskFolder.CreateFolder("Automation Machine") }
	

	
If ($am_aborting -eq $true)
{
	Write-AMInfo "System is going down for reboot, not setting up maintenance tasks"
}
elseif ($pluginenabled -eq $true)
{
	write-aminfo "Enabling maintenance configuration tasks"
	#get user credentials
	$SA = Get-AMServiceAccount
	$TaskUserName = $SA.UserName
	if($TaskUserName.StartsWith(".\")) {$TaskUserName = $TaskUserName.Replace(".\",$env:COMPUTERNAME + "\")}
	$TaskPassword = $SA.Password	
	if ([string]::IsNullOrEmpty($TaskUserName) -or [string]::IsNullOrEmpty($TaskPassword)) 
	{ 
		throw "Service account is not set for the environment" 
	}
	#region Maintenance task
	$TaskName = "Automation Machine Maintenance"	
	$TaskCommand = "Import-Module AMClient;Update-AMCache;Invoke-AMEvent -Name `"SystemMaintenance`"" 

	$Task = $ScheduleService.NewTask(0)
	$Task.Principal.RunLevel = 1
	$Task.Settings.RunOnlyIfIdle = $false
	$Task.Settings.IdleSettings.StopOnIdleEnd = $false
	$Task.Settings.DisallowStartIfOnBatteries = $false
	$Task.Settings.StopIfGoingOnBatteries = $false
	$Task.Settings.DisallowStartIfOnBatteries = $true
	$Task.Settings.RunOnlyIfNetworkAvailable = $false
	
	#task settings help - http://msdn.microsoft.com/en-us/library/aa383512.aspx
	$Task.Settings.AllowDemandStart = $true
	#$Task.Settings.RestartInterval = "PT5M"
	#$Task.Settings.RestartCount = 3
	$Task.Settings.StartWhenAvailable = $false
	$Task.Settings.Enabled = $true
	$Task.Settings.Priority = 1
	
	$RegInfo = $Task.RegistrationInfo
	$RegInfo.Author = "Login AM"
	$RegInfo.Description = "Automation Machine Maintenance Task"
	
	$Action = $Task.Actions.Create(0)
	$Action.Path = "$($env:windir)\system32\windowspowershell\v1.0\powershell.exe"
	$Action.Arguments = "-Command $TaskCommand"

	# Set trigger
	$Triggers = $Task.Triggers
	If ($am_maint_schedule -eq "Daily")
	{
		$Trigger = $Triggers.Create(2) # Daily trigger
		$Trigger.StartBoundary = ([datetime]$am_maint_sch_time).ToString("yyyy-MM-ddTHH:mm:ss")
		$Trigger.DaysInterval = 1
	}
	elseif ($am_maint_schedule -eq "Weekly")
	{
		$Trigger = $Triggers.Create(3)
		$Trigger.StartBoundary = ([datetime]$am_maint_sch_time).ToString("yyyy-MM-ddTHH:mm:ss")
		$Trigger.WeeksInterval = 1
		# Create array for days of week	and count bitmask value of given days
		$ArrDaysOfWeek = $am_maint_sch_days.Split(",")
		$daysOfWeekEnumValue = 0
		foreach($day in $ArrDaysOfWeek)
		{
			if($day -eq "Sunday"){ $daysOfWeekEnumValue += 1}
			if($day -eq "Monday"){ $daysOfWeekEnumValue += 2}
			if($day -eq "Tuesday"){ $daysOfWeekEnumValue += 4}
			if($day -eq "Wednesday"){ $daysOfWeekEnumValue += 8}
			if($day -eq "Thursday"){ $daysOfWeekEnumValue += 16}
			if($day -eq "Friday"){ $daysOfWeekEnumValue += 32}
			if($day -eq "Saturday"){ $daysOfWeekEnumValue += 64}
		}
		if($daysOfWeekEnumValue -lt 1)
		{ 
			$Trigger.DaysInterval = 1
		}
		else 
		{ 
			$Trigger.DaysOfWeek = $daysOfWeekEnumValue 
		}	
	}
	#$Trigger.Repetition.Interval = $Int
	
	# http://msdn.microsoft.com/en-us/library/windows/desktop/aa381365%28v=vs.85%29.aspx
	$TasksOutput = $TaskFolder.RegisterTaskDefinition($TaskName, $Task, 6, $TaskUserName, $TaskPassword, 1)
	Write-Verbose $TasksOutput.Xml
	#endregion
	
	#region Maintenance reporting task
	if ($am_maint_reporting_enable -eq $true)
	{		
		$TaskName = "Automation Machine Maintenance Reporting"	
		$MyPath = (Split-Path $script:MyInvocation.MyCommand.Path -Parent)
		$TaskCommand = "Import-Module AMClient;Update-AMCache;& '$($MyPath)\Reporting.ps1'" 

		$Task = $ScheduleService.NewTask(0)
		$Task.Principal.RunLevel = 1
		$Task.Settings.RunOnlyIfIdle = $false
		$Task.Settings.IdleSettings.StopOnIdleEnd = $false
		$Task.Settings.DisallowStartIfOnBatteries = $false
		$Task.Settings.StopIfGoingOnBatteries = $false
		$Task.Settings.DisallowStartIfOnBatteries = $true
		$Task.Settings.RunOnlyIfNetworkAvailable = $false
		$Task.Settings.ExecutionTimeLimit = 'PT30S'
		
		#task settings help - http://msdn.microsoft.com/en-us/library/aa383512.aspx
		$Task.Settings.AllowDemandStart = $true
		#$Task.Settings.RestartInterval = "PT5M"
		#$Task.Settings.RestartCount = 3
		$Task.Settings.StartWhenAvailable = $true
		$Task.Settings.Enabled = $true
		$Task.Settings.Priority = 1
		
		$RegInfo = $Task.RegistrationInfo
		$RegInfo.Author = "Login AM"
		$RegInfo.Description = "Automation Machine Maintenance Reporting Task"
		
		$Action = $Task.Actions.Create(0)
		$Action.Path = "$($env:windir)\system32\windowspowershell\v1.0\powershell.exe"
		$Action.Arguments = "$TaskCommand"

		# Set trigger
		$Triggers = $Task.Triggers
		If ($am_maint_reporting_schedule -eq "Daily")
		{
			$Trigger = $Triggers.Create(2) # Daily trigger
			$Trigger.StartBoundary = ([datetime]$am_maint_reporting_sch_time).ToString("yyyy-MM-ddTHH:mm:ss")
			$Trigger.DaysInterval = 1
		}
		elseif ($am_maint_reporting_schedule -eq "Weekly")
		{
			$Trigger = $Triggers.Create(3)
			$Trigger.StartBoundary = ([datetime]$am_maint_reporting_sch_time).ToString("yyyy-MM-ddTHH:mm:ss")
			$Trigger.WeeksInterval = 1
			# Create array for days of week	and count bitmask value of given days
			$ArrDaysOfWeek = $am_maint_reporting_sch_days.Split(",")
			$daysOfWeekEnumValue = 0
			foreach($day in $ArrDaysOfWeek)
			{
				if($day -eq "Sunday"){ $daysOfWeekEnumValue += 1}
				if($day -eq "Monday"){ $daysOfWeekEnumValue += 2}
				if($day -eq "Tuesday"){ $daysOfWeekEnumValue += 4}
				if($day -eq "Wednesday"){ $daysOfWeekEnumValue += 8}
				if($day -eq "Thursday"){ $daysOfWeekEnumValue += 16}
				if($day -eq "Friday"){ $daysOfWeekEnumValue += 32}
				if($day -eq "Saturday"){ $daysOfWeekEnumValue += 64}
			}
			if($daysOfWeekEnumValue -lt 1)
			{ 
				$Trigger.DaysInterval = 1
			}
			else 
			{ 
				$Trigger.DaysOfWeek = $daysOfWeekEnumValue 
			}	
		}
		#$Trigger.Repetition.Interval = $Int
		
		# http://msdn.microsoft.com/en-us/library/windows/desktop/aa381365%28v=vs.85%29.aspx
		$TasksOutput = $TaskFolder.RegisterTaskDefinition($TaskName, $Task, 6, $TaskUserName, $TaskPassword, 1)
		Write-Verbose $TasksOutput.Xml
	}
	else
	{
		# Reporting is disabled, disable the task
        try
        {
            $Task = $TaskFolder.GetTask("Automation Machine Maintenance Reporting")
        }
        catch [Exception]
        {
            Write-AMInfo "No reporting tasks exist so no need to disable"
            $task = $null
        }

		If ($Task -is [Object])
		{
			Write-AMInfo "Disabling $($Task.name)"
			$Task.Enabled = $false
		}
	}
	#endregion
	
}
else
{
	$Tasks = $TaskFolder.GetTasks(1) | ? {$_.Name -like "Automation Machine Maintenance*"}
    ForEach ($Task in $Tasks)
	{
		If ($Task -is [Object]) 
		{
			write-aminfo "Disabling $($Task.Name)"
			$Task.Enabled = $false
		}
	}
}
# Close com
[void] [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService)
Remove-Variable ScheduleService