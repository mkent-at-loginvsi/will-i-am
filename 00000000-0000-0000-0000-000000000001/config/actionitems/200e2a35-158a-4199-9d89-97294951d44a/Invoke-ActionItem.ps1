<#
	.Synopsis
	Invokes the Create ODBC DSN action item.

	.Description
 	Invokes the specified Create ODBC DSN actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCreateODBCDSN -ActionItem $ActionItem
#>
function Invoke-AMActionItemCreateODBCDSN
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
	$Name = $($Variables | ? {$_.name -eq "Name"}).Value | Expand-AMEnvironmentVariables
	$Description = $($Variables | ? {$_.name -eq "Description"}).Value | Expand-AMEnvironmentVariables
	$Server = $($Variables | ? {$_.name -eq "Server"}).Value | Expand-AMEnvironmentVariables
	$Database = $($Variables | ? {$_.name -eq "Database"}).Value | Expand-AMEnvironmentVariables
	$Driver = $($Variables | ? {$_.name -eq "Driver"}).Value | Expand-AMEnvironmentVariables
	$Platform = $($Variables | ? {$_.name -eq "Platform"}).Value | Expand-AMEnvironmentVariables
	$Type = $($Variables | ? {$_.name -eq "Type"}).Value | Expand-AMEnvironmentVariables
	$Authentication = $($Variables | ? {$_.name -eq "Authentication"}).Value | Expand-AMEnvironmentVariables
	
	If ($Type -eq "System")
	{
		$ODBCKey = Get-Item "HKLM:\Software\ODBC"
		
		If ($Platform -eq "32-bit" -and (Test-AMOSArch -OSArch "x64"))
		{
			$ODBCKey = Get-Item "HKLM:\Software\Wow6432Node\ODBC"
		}
	}
	If ($Type -eq "User")
	{
		$ODBCKey = Get-Item "HKCU:\Software\ODBC"
		If ($Platform -eq "32-bit" -and (Test-AMOSArch -OSArch "x64"))
		{
			$ODBCKey = Get-Item "HKCU:\Software\Wow6432Node\ODBC"
		}
	}
	
	# Test if driver is available
	$AvailableDrivers = $ODBCKey.OpenSubKey("ODBCINST.INI").OpenSubKey("ODBC Drivers").GetValueNames()
	If (-not ($AvailableDrivers.Contains($Driver)))
	{
		throw "ODBC driver: $Driver is not available on this system, unable to create ODBC DSN"
	}
	else
	{
		
		# Add  the odbc name and driver entry
		$DSPath = (Join-path $ODBCKey.PSPath "ODBC.INI\ODBC Data Sources")
		If (-not (test-path $DSPath))
		{
			[void] (New-Item $DSPath)
		}
		Set-ItemProperty -Path $DSPath -Name $Name -Value $Driver -Type String -Force
		
		$DSNPath = (Join-path $ODBCKey.PSPath "ODBC.INI\$($Name)")
		If (-not (test-path $DSNPath))
		{
			[void] (New-Item $DSNPath)
		}
		Set-ItemProperty -Path $DSNPath -Name Database -Value $Database -Type String -Force
		Set-ItemProperty -Path $DSNPath -Name Description -Value $Description -Type String -Force
		$DriverPath = $ODBCKey.OpenSubKey("ODBCINST.INI").OpenSubKey($Driver).GetValue("Driver")
		Set-ItemProperty -Path $DSNPath -Name Driver -Value $DriverPath -Type String -Force
		Set-ItemProperty -Path $DSNPath -Name LastUser -Value "$env:USERDOMAIN\$env:USERNAME" -Type String -Force
		Set-ItemProperty -Path $DSNPath -Name Server -Value $Server -Type String -Force
		If ($Authentication -eq "Windows")
		{
			Set-ItemProperty -Path $DSNPath -Name "Trusted_Connection" -Value "Yes" -Type String -Force
		}
		else
		{
			Remove-ItemProperty -Path $DSNPath -Name "Trusted_Connection" -Force -ErrorAction SilentlyContinue
		}
		
	}
		
	
}