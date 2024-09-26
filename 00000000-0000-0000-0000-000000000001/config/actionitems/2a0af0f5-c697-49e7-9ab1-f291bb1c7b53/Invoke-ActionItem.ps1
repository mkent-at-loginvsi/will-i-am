<#
	.Synopsis
	Invokes the nest group action item.

	.Description
 	Invokes the specified nest group actionitem.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
	$Pkg = Get-AMPackage -Name "TestPackage"
	Read-AMActionItems -Component $pkg
	$ActionSet = $Pkg.ActionSet | Select -First 1
	$ActionItem = $ActionSet.ActionItems | Select -First 1
 	Invoke-AMActionItemNestGroup -ActionItem $ActionItem
#>
function Invoke-AMActionItemNestGroup
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
	$MemberOf = [String] $($Variables | ? {$_.name -eq "Member Of"}).Value | Expand-AMEnvironmentVariables
	
	
	If ($UsePrefixSuffix -eq $true)
	{
		$Name = $am_col_gprefix + $Name + $am_col_gsuffix
		$MemberOf = $am_col_gprefix + $MemberOf + $am_col_gsuffix
	}

	If ((Get-AMComputerDomain) -eq $null)
	{
		Write-AMWarning "This computer is not member of a domain, unable to nest groups (local groups cannot be nested)"	
	}
	
	Write-AMInfo "Looking for $MemberOf"
	$MemberOfGroup = Get-AMLDAPPath -Name $MemberOf
	If ($MemberOfGroup -is [Object])
	{
		
		Write-AMInfo "Looking for $Name"
		$GroupToNest = Get-AMLDAPPath -Name $Name
		If ($GroupToNest -is [Object])
		{
			Write-AMInfo "Adding $GroupToNest to $MemberOfGroup"
			Add-AMGroupMember -Group $MemberOfGroup -GroupToAdd $GroupToNest
		}
		Else
		{
			Throw "The security group $Name does not exist, unable to nest group"
		}
	}
	Else
	{
		throw "The security group $MemberOf does not exist, unable to nest group"
	}
	
}