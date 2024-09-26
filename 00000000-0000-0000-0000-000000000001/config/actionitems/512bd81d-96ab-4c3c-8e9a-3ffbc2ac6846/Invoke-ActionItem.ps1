<#
	.Synopsis
	Invokes the map network drive action item.

	.Description
 	Invokes the specified map network drive actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemMapDrive -ActionItem $ActionItem
#>
function Invoke-AMActionItemMapDrive
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
	$UNCPath = $($Variables | ? {$_.name -eq "UNC Path"}).Value.Path | Expand-AMEnvironmentVariables
	$DriveLetter = $($Variables | ? {$_.name -eq "Driveletter"}).Value | Expand-AMEnvironmentVariables
	$Credentials =  $($Variables | ? {$_.name -eq "Credentials"}).Value
	$Force =  $($Variables | ? {$_.name -eq "Force"}).Value
	
	$net = New-Object -ComObject WScript.Network
	$continue = $false
	Write-Verbose "Checking existing drivemaps"
	If ($net.EnumNetworkDrives() -contains "$($Driveletter):")
	{
		If ($Force -eq $true)
		{
			Write-Verbose "$Driveletter already mapped and force is specified, removing existing drivemap"
			$net.RemoveNetworkDrive("$($Driveletter):",$true,$true)
			$continue = $true
		}
		else
		{
			Write-Verbose "$Driveletter already mapped and force was not specified, not mapping drive"
			$continue = $false
		}
	}
	else
	{
		$continue = $true
	}
	
	If ($continue -eq $true)
	{
		If ([string]::IsNullOrEmpty($Credentials.Username))
		{
			Write-Verbose "Mapping network drive $UNCPath to driveletter $Driveletter with currently logged on user context"
			Connect-AMDrive -Driveletter $Driveletter -UNCPath $UNCPath
		}
		else
		{
			Write-Verbose "Mapping network drive $UNCPath to driveletter $Driveletter with username $($Credentials.Username)"
			Connect-AMDrive -Driveletter $Driveletter -UNCPath $UNCPath -Username $Credentials.Username -Password $Credentials.Password
		}
	}	
	

	
}