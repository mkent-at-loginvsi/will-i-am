param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

# Cleanup environment variables
[System.Environment]::SetEnvironmentVariable("am_col_createou","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_ou","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_ou_dn","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_movecomputers","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_enableschedule","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_scheduletimer","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_matchvm","",[System.EnvironmentVariableTarget]::Process)

# Cleanup global plugin variables
Remove-Variable -name am_col_createou -Scope 3
Remove-Variable -name am_col_ou -Scope 3
Remove-Variable -name am_col_ou_dn -Scope 3
Remove-Variable -name am_col_movecomputers -Scope 3
Remove-Variable -name am_col_enableschedule -Scope 3
Remove-Variable -name am_col_scheduletimer -Scope 3
Remove-Variable -name am_col_matchvm -Scope 3