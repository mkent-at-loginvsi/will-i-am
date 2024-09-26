param
(
	$Plugins
)

# user triggered event on RDS 2012R2 Session Host

# Set context
Set-Variable -Name am_context -Value "system" -Scope 3

throw "UserTriggered event cannot be invoked by using Invoke-AMEvent, it is an internal event used by the User Installed applications dialog"