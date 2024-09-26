param(
	[parameter(Mandatory=$true,ValueFromPipeline=$false)]
	[AutomationMachine.Data.Plugin] $Plugin
)

[System.Environment]::SetEnvironmentVariable("am_col_template","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_sealcmd","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_removeam","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_sealargs","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_sealcmdreturn","",[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_col_waitforsealcmd","",[System.EnvironmentVariableTarget]::Process)


# Cleanup global plugin variables
Remove-Variable -name am_col_template -Scope 3
Remove-Variable -name am_col_sealcmd -Scope 3
Remove-Variable -name am_col_removeam -Scope 3
Remove-Variable -name am_col_sealargs -Scope 3
Remove-Variable -name am_col_sealcmdreturn -Scope 3
Remove-Variable -name am_col_waitforsealcmd -Scope 3