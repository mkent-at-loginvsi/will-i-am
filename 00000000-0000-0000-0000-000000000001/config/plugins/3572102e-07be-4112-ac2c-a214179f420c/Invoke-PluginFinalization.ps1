param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)


#region Get plugin variables

Remove-Variable -name am_maint_schedule -Scope 3
Remove-Variable -Name am_maint_sch_days -Scope 3
Remove-Variable -Name am_maint_sch_time -Scope 3
Remove-Variable -Name am_maint_drain_enable -Scope 3
Remove-Variable -Name am_maint_drain_minutes -Scope 3
Remove-Variable -Name am_max_batch_size -Scope 3
Remove-Variable -Name am_batch_interval -Scope 3
Remove-Variable -Name am_maint_mode -Scope 3
Remove-Variable -Name am_maint_exclusions -Scope 3
Remove-Variable -Name am_maint_pre_shutdown_script -Scope 3
Remove-Variable -Name am_maint_verification_script -Scope 3
Remove-Variable -Name am_maint_rnd_delay -Scope 3
Remove-Variable -Name am_maint_msg -Scope 3
Remove-Variable -name am_maint_reporting_schedule -Scope 3
Remove-Variable -Name am_maint_reporting_sch_days -Scope 3
Remove-Variable -Name am_maint_reporting_sch_time -Scope 3
Remove-Variable -Name am_maint_statuspath -scope 3
Remove-Variable -Name am_maint_reporting_to -Scope 3 
Remove-Variable -Name am_maint_reporting_port -Scope 3
Remove-Variable -Name am_maint_reporting_ssl -Scope 3
Remove-Variable -Name am_maint_reporting_cred -Scope 3
Remove-Variable -Name am_maint_reporting_smtp -Scope 3
Remove-Variable -Name am_maint_reporting_subject -Scope 3
Remove-Variable -Name am_maint_reporting_from -Scope 3
Remove-Variable -Name am_maint_reporting_enable -Scope 3
Remove-Variable -Name am_maint_if_failed_enable -Scope 3
Remove-Variable -Name am_maint_max_wait_time -Scope 3
Remove-Variable -Name am_max_failure_rate -Scope 3


#endregion


#endregion

#region Remove environment variables
[System.Environment]::SetEnvironmentVariable("am_maint_schedule","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_sch_days","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_sch_time","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_drain_enable","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_drain_minutes","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_max_batch_size","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_batch_interval","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_mode","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_exclusions","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_msg","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_rnd_delay","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_schedule","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_sch_days","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_sch_time","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_statuspath","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_to","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_port","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_ssl","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_smtp","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_subject","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_from","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_reporting_enable","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_if_failed_enable","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_maint_max_wait_time","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_max_failure_rate","",[System.EnvironmentVariableTarget]::Process)

#endregion
	
	
