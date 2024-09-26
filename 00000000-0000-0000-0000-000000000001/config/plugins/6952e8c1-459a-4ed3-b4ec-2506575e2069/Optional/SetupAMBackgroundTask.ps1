if ($null -ne (Get-Command -Name "Install-AMStartupTask" -ErrorAction SilentlyContinue)) {
    Install-AMStartupTask
}

if ($null -ne (Get-Command -Name "Install-AMLogshippingTask" -ErrorAction SilentlyContinue)) {
    Install-AMLogshippingTask
}

if ($null -ne (Get-Command -Name "Install-AMUserUsageTask" -ErrorAction SilentlyContinue)) {
    Install-AMUserUsageTask
}

$TaskName = "Automation Machine Scheduled System Configuration"
$PluginId = $AmWellKnown::Plugins.SystemConfiguration.Id
Set-Variable -Name PluginEnabled -Value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.EnableSystemConfigurationVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)

# Setup variables to use
Set-Variable -Name am_col_enableschedule -Value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.EnableBackgroundConfigurationVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)
Set-Variable -Name am_col_scheduletimer -Value([string] (Get-AMVariable -Id $AmWellKnown::Plugins.SystemConfiguration.ConfigurationScheduleIntervalVariable.Id -ParentId $PluginId -CollectionId $am_col.Id).Value)

#set up a connection to scheduled tasks management
$ScheduleService = New-Object -ComObject "Schedule.Service"
$ScheduleService.Connect()

#get Automation Machine's scheduled tasks folder
$TaskFolder = $ScheduleService.GetFolder("\") # root folder
$StartBoundary = $null
try {
    $TaskFolder = $TaskFolder.GetFolder("Automation Machine")
    try {
      $ExistingTask = $TaskFolder.GetTask($TaskName)
      $TaskXml = [xml] $ExistingTask.Xml
      $StartBoundary = $TaskXml.Task.Triggers.TimeTrigger.StartBoundary
    }
    catch {}
}
catch { $TaskFolder = $TaskFolder.CreateFolder("Automation Machine") }

If ($am_aborting -eq $true) {
    Write-AMInfo "System is going down for reboot, not setting up background tasks"
}
elseif ($pluginenabled -eq $true -and ($am_col_enableschedule -eq $true)) {
    write-aminfo "Enabling background configuration task"
    #get user credentials
    $SA = Get-AMServiceAccount
    $TaskUserName = $SA.UserName
    if ($TaskUserName.StartsWith(".\")) { $TaskUserName = $TaskUserName.Replace(".\", $env:COMPUTERNAME + "\") }
    $TaskPassword = $SA.Password
    if ([string]::IsNullOrEmpty($TaskUserName) -or [string]::IsNullOrEmpty($TaskPassword)) {
        throw "Service account is not set for the environment"
    }

    $TaskCommand = "Start-Sleep -Seconds 180;Import-Module AMClient;Update-AMCache;Invoke-AMEvent -Name `"SystemScheduled`""

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
    $Task.Settings.RestartInterval = "PT5M"
    $Task.Settings.RestartCount = 3
    $Task.Settings.StartWhenAvailable = $true
    $Task.Settings.Enabled = $true
    $Task.Settings.Priority = 1

    $RegInfo = $Task.RegistrationInfo
    $RegInfo.Author = "Login AM"
    $RegInfo.Description = "Automation Machine Scheduled System Configuration Task"

    $Action = $Task.Actions.Create(0)
    $Action.Path = "$($env:windir)\system32\windowspowershell\v1.0\powershell.exe"
    $Action.Arguments = "-Command $TaskCommand"

    # Set interval
    Switch ($am_col_scheduletimer) {
        "Every 5 minutes" { $Int = "PT5M" }
        "Every 10 minutes" { $Int = "PT10M" }
        "Every 15 minutes" { $Int = "PT15M" }
        "Every 30 minutes" { $Int = "PT30M" }
        "Every 1 hour" { $Int = "PT1H" }
        default { $Int = "PT1H" }
    }

    $Triggers = $Task.Triggers
    $Trigger = $Triggers.Create(1) # time trigger

    if ([string]::IsNullOrEmpty($StartBoundary)) {
        $FirstStartDelay = 15
        switch ($am_col_scheduletimer) {
            "Every 5 minutes" { $FirstStartDelay = 5 }
            "Every 10 minutes" { $FirstStartDelay = 10 }
            "Every 15 minutes" { $FirstStartDelay = 15 }
            "Every 30 minutes" { $FirstStartDelay = 30 }
            "Every 1 hour" { $FirstStartDelay = 60 }
        }
        $Trigger.StartBoundary = [DateTime]::Now.AddMinutes($FirstStartDelay).ToString("yyyy-MM-ddTHH:mm:ss")
    }
    else {
        $Trigger.StartBoundary = $StartBoundary
    }
    
    $Trigger.Repetition.Interval = $Int

    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa381365%28v=vs.85%29.aspx
    $TasksOutput = $TaskFolder.RegisterTaskDefinition($TaskName, $Task, 6, $TaskUserName, $TaskPassword, 1)
    Write-Verbose $TasksOutput.Xml
}
else {
    $Task = $TaskFolder.GetTasks(1) | ? { $_.Name -eq "$TaskName" } | Select-Object -First 1

    If ($Task -is [Object]) {
        write-aminfo "Disabling background configuration task"
        $Task.Enabled = $false
    }
}
# Close com
[void] [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService)
Remove-Variable ScheduleService