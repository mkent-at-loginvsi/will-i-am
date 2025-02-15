<#
	.Synopsis
	Enables a windows feature

	.Description
 	Enables windows features by name or display name
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemApplyFolderPermissions -ActionItem $ActionItem
#>
function Invoke-AMActionItemEnableFeature 
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[AutomationMachine.Data.ActionItem] $ActionItem
	)
	$OSVersionLessThen61 = [Environment]::OSVersion.Version -lt (new-object 'Version' 6,1)
	If ($OSVersionLessThen61 -eq $true)
	{
		Write-AMWarning "Unable to enable windows feature, only supported on Windows Server 2008R2 (or Windows 7) and higher"
	}
	else
	{
		Import-Module servermanager
		
		Write-AMInfo "Invoking $($ActionItem.Name)"
		# Resolve the variables including the filters,
		$Variables = $ActionItem.Variables
		$Variables | % {Resolve-AMVariableFilter $_}
		$Variables | % {Resolve-AMMediaPath $_}
		
		
		# Get the variables from the actionitem
		[string] $Name = $($Variables | ? {$_.name -eq "Feature name"}).Value | Expand-AMEnvironmentVariables
		[string] $Recursive = $($Variables | ? {$_.name -eq "Install all subfeatures"}).Value
		[string] $Tools = $($Variables | ? {$_.name -eq "Install management features"}).Value
		 $OSVersionLessThen62 = [Environment]::OSVersion.Version -lt (new-object 'Version' 6,2)
		 
		if (($Recursive -eq $true) -and ($Tools -eq $true))
		{
			if($OSVersionLessThen62 -eq $true){
				write-AMWarning "Cannot include management tools on OS version less then Server 2012"
				$result = Add-WindowsFeature -ErrorAction Stop -Name $Name -IncludeAllSubFeature -WarningAction SilentlyContinue
			}
			else
			{
				$result = Add-WindowsFeature -ErrorAction Stop -Name $Name -IncludeAllSubFeature -IncludeManagementTools -WarningAction SilentlyContinue
			}		
		}
		elseif (($Recursive -eq $true) -and ($Tools -eq $false))
		{
			$result = Add-WindowsFeature -ErrorAction Stop -Name $Name -IncludeAllSubFeature -WarningAction SilentlyContinue
		}
		elseif(($Recursive -eq $false) -and ($Tools -eq $true))
		{
			if($OSVersionLessThen62 -eq $true){
				write-AMWarning "Cannot include management tools on OS version less than Server 2012"
				$result = Add-WindowsFeature -ErrorAction Stop -Name $Name -WarningAction SilentlyContinue
			}
			else
			{
				$result = Add-WindowsFeature -ErrorAction Stop -Name $Name -IncludeManagementTools -WarningAction SilentlyContinue
			}		
		}
		else
		{
			$result = Add-WindowsFeature -ErrorAction Stop -Name $Name -WarningAction SilentlyContinue
		}
		
		if ($result.Success -ne $true)
		{
			throw "Installing windows feature $name failed. ErrorCode: $($result.ExitCode.tostring())"
		}
		else
		{
			foreach ($Feature in $result.FeatureResult)
			{
				Write-AMInfo "Succesfully installed: $($Feature.DisplayName)"
			}
			
			if ($result.RestartNeeded -eq "Yes")
			{
				Write-AMInfo "Reboot required"
				$AMDataManager.RebootNeeded = $true
			}
		}
	}
	
}