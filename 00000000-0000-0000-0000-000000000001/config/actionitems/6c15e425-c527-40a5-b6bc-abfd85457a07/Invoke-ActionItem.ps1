<#
	.Synopsis
	Invokes the create group action item.

	.Description
 	Invokes the specified create group actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemCreateGroup -ActionItem $ActionItem
#>
function Invoke-AMActionItemCreateGroup
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
	$Name = [String] $($Variables | ? {$_.name -eq "Name"}).Value | Expand-AMEnvironmentVariables
	$UsePrefixSuffix = [Boolean] $($Variables | ? {$_.name -eq "AutoAdd Prefix/Suffix"}).Value
	$Scope = [String] $($Variables | ? {$_.name -eq "Scope"}).Value | Expand-AMEnvironmentVariables
	
	
	If ($UsePrefixSuffix -eq $true)
	{
		$Name = $am_col_gprefix + $Name + $am_col_gsuffix
	}

	If ((Get-AMComputerDomain) -eq $null)
	{
		If ($Scope -ne [AutomationMachine.Plugins.ActiveDirectory.GroupScope]::Local) 
		{
			Write-AMWarning "The groupscope was set to: $Scope, but this computer is not a member of a domain, reverting to local groups"
			$Scope = ([AutomationMachine.Plugins.ActiveDirectory.GroupScope]::Local)
		}
		[string] $OULDAP = "WinNT://$env:computername"
	}
	else
	{
		[string] $OULDAP = "LDAP://$am_col_gou_dn,$(Get-AMDomainDN)"			
	}
	$Group = Get-AMLDAPPath -Name $Name
	If ($Group -is [Object])
	{
		Write-AMInfo "Security group $Name already exists"
	}
	Else
	{
		[void] (New-AMGroup -Name $Name -LDAPPath $OULDAP -Scope $Scope -Description ($am_col_gdescription | Expand-AMEnvironmentVariables))
	}
	
}