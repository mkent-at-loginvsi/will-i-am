<#
	.Synopsis
	Invokes the Reboot action item.

	.Description
 	Invokes the specified Reboot actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemReboot -ActionItem $ActionItem
#>
function Invoke-AMActionItemReboot
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[AutomationMachine.Data.ActionItem] $ActionItem
	)
	Write-AMInfo "Invoking $($ActionItem.Name)"
	If ($AMDataManager.RebootPreference -ne [AutomationMachine.Data.RebootPreference]::Continue)
	{
		$AMDataManager.RebootNeeded = $true
		Disable-AMSystemEventFlag
		$global:am_aborting = $true
	}
	else
	{
		$AMDataManager.RebootNeeded = $true
	}
}