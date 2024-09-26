param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)



# SCRIPT: Plugin Initialization
# PLUGIN: Maintenance

If (!(Test-AMElevation)) 
{
	. Set-Variable -name "plugin_$($plugin.id)_enabled" -value $false
    throw "Process is not running elevated, unable to process deployment plugin"   
}

#region Get plugin variables

Set-Variable -name am_maint_schedule -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000028 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_sch_days -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000029 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_sch_time -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000030 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_drain_enable -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000031 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_maint_drain_minutes -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000032 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_mode -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000033 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_maint_exclusions -Scope 3 -Value((Get-AMVariable -Id 00000000-0000-0000-0000-000000000034 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value| Expand-AMEnvironmentVariables)

Set-Variable -Name am_maint_pre_shutdown_script -Scope 3 -Value (Get-AMVariable -Id 00000000-0000-0000-0000-000000000035 -ParentId $Plugin.Id -CollectionId $am_col.Id)
Set-Variable -Name am_maint_verification_script -Scope 3 -Value (Get-AMVariable -Id 00000000-0000-0000-0000-000000000036 -ParentId $Plugin.Id -CollectionId $am_col.Id)
Set-Variable -Name am_maint_rnd_delay -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000037 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

Set-Variable -Name am_maint_msg -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000039 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -name am_maint_reporting_schedule -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000040 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_sch_days -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000041 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_sch_time -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000042 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

Set-Variable -Name am_maint_reporting_to -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000044 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_port -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000050 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_ssl -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000049 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
[AutomationMachine.Data.Types.Credentials] $am_maint_reporting_cred = (Get-AMVariable -Id 00000000-0000-0000-0000-000000000048 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value
Set-Variable -Name am_maint_reporting_cred -Scope 3
Set-Variable -Name am_maint_reporting_smtp -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000047 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_subject -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000046 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_from -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000045 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_reporting_enable -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000043 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)

Set-Variable -Name am_max_batch_size -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000058 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_batch_interval -Scope 3 -Value ([string]  (Get-AMVariable -Id 00000000-0000-0000-0000-000000000059 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
Set-Variable -Name am_maint_if_failed_enable -Scope 3 -Value ([boolean] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000068 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_maint_max_wait_time -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000069 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)
Set-Variable -Name am_max_failure_rate -Scope 3 -Value ([string] (Get-AMVariable -Id b92f6901-e6b7-431a-8b45-bbcc0466a294 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value)


Set-Variable -Name am_wait_time_for_peers -Scope 3 -Value ([string] (Get-AMVariable -Id 00000000-0000-0000-0000-000000000075 -ParentId $Plugin.Id -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

Set-Variable -Name am_maint_statuspath -scope 3 -Value "$AMCentralPath\$($AMEnvironment.id)\monitoring\maintenance"



#endregion


#endregion

#region Setup environment variables
[System.Environment]::SetEnvironmentVariable("am_maint_schedule",($am_maint_schedule.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_sch_days",($am_maint_sch_days.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_sch_time",($am_maint_sch_time.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_drain_enable",($am_maint_drain_enable.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_drain_minutes",($am_maint_drain_minutes.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_max_batch_size",($am_max_batch_size.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_batch_interval",($am_batch_interval.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_mode",($am_maint_mode.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_exclusions",($am_maint_exclusions.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_msg",($am_maint_msg.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_rnd_delay",($am_maint_rnd_delay.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_schedule",($am_maint_reporting_schedule.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_sch_days",($am_maint_reporting_sch_days.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_sch_time",($am_maint_reporting_sch_time.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_statuspath",($am_maint_statuspath.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_to",($am_maint_reporting_to.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_port",($am_maint_reporting_port.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_ssl",($am_maint_reporting_ssl.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_smtp",($am_maint_reporting_smtp.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_subject",($am_maint_reporting_subject.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_from",($am_maint_reporting_from.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_enable",($am_maint_reporting_enable.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_if_failed_enable",($am_maint_if_failed_enable.ToString()),[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_max_failure_rate",($am_max_failure_rate.ToString()),[System.EnvironmentVariableTarget]::Process)

#endregion
	
