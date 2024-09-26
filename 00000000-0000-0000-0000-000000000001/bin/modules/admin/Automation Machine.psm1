param (
[string] $EnvironmentID,
[boolean] $NoTranscript = $false,
[string] $AMCentralPath,
[string] $AMLocalPath
)
function Convert-AMSiteNameToLdapPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $SiteName,
    
        [Parameter(Mandatory = $true)]
        [string]
        $DirectoryEntryPath,

        [Parameter(Mandatory = $false)]
        [string]
        $DomainControllerName
    )

    if ([string]::IsNullOrEmpty($DomainControllerName)) {
        $Path = $($DirectoryEntry.Path.Insert(7, "$($SiteName)/"))
    }
    else {
        $Path = [System.Text.RegularExpressions.Regex]::Replace($DirectoryEntryPath, $DomainControllerName, "$($SiteName)/", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }

    return $Path
}
<#
	.Synopsis
	Adds a group to another group

	.Description
 	Adds a group to another group in AD or on the local system.
  
	.Parameter Group
 	The name or ldap path of a group to add a member to.
	
	.Parameter GroupToAdd
	The name or ldappath of a group to add to the group specified in the Group parameter
	
	.Parameter Username
	The username to connect to AD with
	
	.Parameter Password
	The password for the username.
  
 
 	.Example
 	Add-AMGroupMember -Group Test1 -GroupToAdd Group1
	
	.Example
	Add-AMGroupMember -Group LDAP://CN=Test1,OU=AutomationMachine,DC=AM,DC=LAN" -GroupToAdd LDAP://CN=Group1,OU=AutomationMachine,DC=AM,DC=LAN"

#>
function Add-AMGroupMember
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Group,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=1)]
		[string]
		$GroupToAdd,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=2)]
		[string]
		$Username,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=3)]
		[string]
		$Password
		
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
			Write-Verbose "Getting LDAP paths for groups"
			$ldapPathGroup = Get-AMLDAPPath $Group
			$ldapPathObject = Get-AMLDAPPath $GroupToAdd
			
			

            Write-Verbose "Checking format of ldap paths"
            if ($ldapPathGroup.StartsWith("LDAP://") -and $ldapPathObject.StartsWith("WinNT://"))
            {
                Write-AMWarning "Adding a local group to a domain group is not allowed"
                break
            }
			if ($ldapPathGroup.StartsWith("WinNT://") -and $ldapPathObject.StartsWith("LDAP://"))
			{
                Write-Verbose "$Group has WinNT style LDAP Path, converting $GroupToAdd to WinNT style"
                $SID = Get-AMSID $ldapPathObject                
				$ldapPathObject = "WinNT://$(($SID.Translate([System.Security.Principal.NTAccount])).Value -replace '\\','/')"			    
            }	
			Write-Verbose "Getting Group directoryEntry"
			$groupobject = Get-AMDirectoryEntry -ldappath $ldapPathGroup -username $username -password $password
			Write-Verbose "Group object: $($Groupobject.path)"
			[bool] $ObjectExists = $false
			
			Write-Verbose "Getting group members"		
			If (($groupobject | Get-AMDirectoryEntryMember -MemberLDAPPath $ldappathobject) -ne $null) 
			{ 
				$ObjectExists = $true 
			}			
			
			if ($ObjectExists -eq $false)
			{
				Write-Verbose "Getting GroupToAdd directoryEntry"
				$object = Get-AMDirectoryEntry -ldappath $ldappathobject -username $username -password $password		
				Write-Verbose "GroupToAdd object: $($object.path)"
				Write-Verbose "Adding $($object.path) to $($groupobject.path)"
				$groupobject.PSBase.Invoke("Add",$object.PSBase.Path)
				Write-Verbose "Comitting info"
				$groupobject.SetInfo()
			}
			else
			{
				Write-AMInfo "$GroupToAdd is already a member of $Group"
			}
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Gets a directoryentry object.

	.Description
	Gets the directoryentry object for the specified LDAP path
	
	.Parameter LDAPPath
 	The LDAPPath to get the directoryentry from.
	
	.Parameter Username
	The username to connect to the domain controller(s) with.
	
	.Parameter Password
	The password for the username to connect to the domain controller(s) with
   
 	.Example
 	"LDAP://CN=UserName,OU=AM,DC=AM,DC=LAN" | Get-AMDirectoryEntry
 	
 	.Example
	$LDAPPath = Get-AMLDAPPath -Name "UserName"
	Get-AMDirectoryEntry -LDAPPath $LDAPPath

#>
function Get-AMDirectoryEntry
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$LDAPPath,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Username,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Password
	)
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


		$ReturnValue = $null
		switch -wildcard ($ldappath)
		{
			"LDAP://" {
				if ([string]::IsNullOrEmpty($Username) -and [string]::IsNullOrEmpty($Password))
				{
					[System.DirectoryServices.DirectoryEntry] $ReturnValue = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$(Get-AMDomainDN)")
				}
				else
				{
					[System.DirectoryServices.DirectoryEntry] $ReturnValue = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$(Get-AMDomainDN)",$username,$password)
				}
				break;
			}
			"LDAP://*" {
				if ([string]::IsNullOrEmpty($Username) -and [string]::IsNullOrEmpty($Password))
				{
					if ([System.DirectoryServices.DirectoryEntry]::Exists("$ldappath,$(Get-AMDomainDN)"))
					{
						[System.DirectoryServices.DirectoryEntry] $ReturnValue = New-Object System.DirectoryServices.DirectoryEntry("$ldappath,$(Get-AMDomainDN)")
					}
					else
					{
						trap {continue}
						if ([System.DirectoryServices.DirectoryEntry]::Exists($ldappath))
						{
							[System.DirectoryServices.DirectoryEntry] $ReturnValue = New-Object System.DirectoryServices.DirectoryEntry($ldappath)
							}
						else
						{
							$ReturnValue = $null
						}
					}				
				}
				else
				{
					if ([System.DirectoryServices.DirectoryEntry]::Exists("$ldappath,$(Get-AMDomainDN)"))
					{
						[System.DirectoryServices.DirectoryEntry] $ReturnValue = New-Object System.DirectoryServices.DirectoryEntry("$ldappath,$(Get-AMDomainDN)",$username,$password)
					}
					else
					{
						trap {continue}
						if ([System.DirectoryServices.DirectoryEntry]::Exists($ldappath))
						{
							[System.DirectoryServices.DirectoryEntry] $ReturnValue = New-Object System.DirectoryServices.DirectoryEntry($ldappath,$username,$password)
							}
						else
						{
							$ReturnValue = $null
						}
					}
				}
				break
			}
			"WinNT://*" {
				[System.DirectoryServices.DirectoryEntry] $ReturnValue = New-Object System.DirectoryServices.DirectoryEntry($ldappath)
				break
			}
			default {
				throw "ldappath specified could not be resolved"
			}
		}
				
		return $ReturnValue

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Gets the members for a directory entry.

	.Description
 	Gets the members for a directory entry, without having the 2500 object limit.
  
	.Parameter DirectoryEntry
 	The directoryEntry from which the members are retrieved
	
	.Parameter MemberLDAPPath
	The LDAPPath of a member to look for in the DirectoryEntry (returns $Null if Member was not found)
  
	 .Example
 	$DE = Get-AMDirectoryEntry LDAP://CN=Group,OU=Automation Machine,DC=AM,DC=LAN"
	$DE | Get-AMDirectoryEntryMember
	
	.Example
	$DE = Get-AMDirectoryEntry LDAP://CN=Group,OU=Automation Machine,DC=AM,DC=LAN"
	$DE | Get-AMDirectoryEntryMember -MemberLDAPPath LDAP://CN=MemberGroup,OU=Automation Machine,DC=AM,DC=LAN"
	

#>
function Get-AMDirectoryEntryMember
{
	[cmdLetbinding()]		
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[System.DirectoryServices.DirectoryEntry]
		$DirectoryEntry,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=1)]
		[String]
		$MemberLDAPPath="*"		
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


		$rangeStep = 999
		$startRange = 0
		$lastQuery = $false
        $allMembers = New-Object System.Collections.Generic.List[string]
        $ldapObject = $MemberLDAPPath

		Write-Verbose "Looking for members in $($DirectoryEntry.Path)"           
        If ($DirectoryEntry.Path.StartsWith("WinNT://"))
        {
            If ($MemberLDAPPath.StartsWith("LDAP://"))
            {
                Write-Verbose "$($DirectoryEntry.Path) has WinNT style LDAP Path, converting $MemberLDAPPath to WinNT style"
                $SID = Get-AMSID $MemberLDAPPath
				$ldapObject = "WinNT://$(($SID.Translate([System.Security.Principal.NTAccount])).Value -replace '\\','/')"
            }
            $Members = $DirectoryEntry.psbase.Invoke("Members") | % {$_.GetType().InvokeMember("ADsPath", 'GetProperty', $Null, $_, $Null)}
            $membersToAdd = $members | Where-Object { $_ -like $ldapObject }
			if ($membersToAdd -ne $null) {
				$allMembers.AddRange([string[]] $membersToAdd)	
			}
            return $allMembers
        }
		
		if ($ldapObject -eq $null) { $ldapObject = "*" }
		if ($ldapObject.ToUpper().StartsWith("LDAP://")) {
			$ldapObject = $ldapObject.Replace("LDAP://","")
		}
			
			
			
		while ($lastQuery -ne $true) 
		{
			$endRange = $startRange + $rangeStep
			[string[]] $attributes = @("member;range=$startRange-$endRange")
			#[string[]] $attributes = @("member;range=$startRange-*")
			# Perform a search using the group entry as the base
			#Write-Host $attributes
			$memberSearcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry, "(objectClass=*)", $attributes, [System.DirectoryServices.SearchScope]::Base)
			$results = $memberSearcher.FindAll()
			foreach ($result in $results) {
				$propertyNames = $result.Properties.PropertyNames | Where-Object {$_.GetType().ToString() -eq "System.String" -and $_.StartsWith("member;")}
				if ($propertyNames)
				{
					foreach ($propertyName in $propertyNames) 
					{
						#Write-Host $propertyName -ForegroundColor Cyan
						$members = $result.Properties[$propertyName]
						#Write-Host $members.Count -ForegroundColor Yellow
						if ($members.Count -lt $rangeStep + 1) {
							$lastQuery = $true
						}
						$membersToAdd = $members | Where-Object { $_ -like $ldapObject }
						if ($membersToAdd -ne $null) {
							$allMembers.AddRange([string[]] $membersToAdd)	
						}
					}
				}
				else
				{
					return $null
				}
			}
			if ($memberSearcher -ne $null) { $memberSearcher.Dispose() }
			$startRange += $rangeStep + 1
		}
		return $allMembers
		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Gets the domain name for current user credentials.

	.Description
 	Gets the domain name for current user credentials and returns it in LDAP from. (DC=MyDomain,DC=Local)
    
	.NOTES
	Distributed filesystems are NOT supported
 
 	.Example
 	Get-AMDomainDN
#>
function Get-AMDomainDN {

	[CmdletBinding()]
	Param()

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


	[string] $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry().distinguishedName
	<#[string] $DomainControllerName = [string] (Get-AMVariable `
		-Id 30751e04-9bda-402a-8a5d-1fb26171fc09 `
		-ParentId 9662ad7d-3fb6-4180-84fd-bb4715374b0a `
		-CollectionId (Get-AMCollection -Current).Id `
	).Value
	
	If (-Not ([string]::IsNullOrEmpty($DomainControllerName))) 
	{
		return "DC=$($DomainControllerName),$($DomainName)"
	} 	
	Else 
	{
		return $DomainName
	}
	#>
	return $DomainName

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Gets the ldappath for the specified name.

	.Description
 	Gets the ldappath for the specified name. Looks for name in AD or in local system. 
  
	.Parameter Name
 	The name to lookup the ldapppath for. Can be just the name, but also a SID or an ldap string.
   
 	.Example
 	"TestUser" | Get-AMLDAPPath
 	
 	.Example
 	Get-AMLDAPPath -Name "LDAP://CN=TestUser,OU=AM,DC=AM,DC=LOCAL"
	
	
 	.Example
 	Get-AMLDAPPath -Name "LDAP://CN=TestUser,OU=AM"
#>
function Get-AMLDAPPath
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Name
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
    # First check if the name is not a special NT Authority name, if it is we return null
    $NTAuthoritySID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-2")
	$NTName = @($($($NTAuthoritySID.Translate([System.Security.Principal.NTAccount])).Value).Split('\'))[0]
    If ($Name.Split("\")[0].ToLower() -eq $NTName.ToString().ToLower())
    {
        return $null
    }

    If ($Name.Startswith("WinNT://"))
	{
		If ([System.DirectoryServices.DirectoryEntry]::Exists($Name))
		{
			return $Name
		}
	}
	
	# If computer is not part of a domain, we search only in local computer
	If ($null -eq (Get-AMComputerDomain))
	{
		If ($Name.Startswith("WinNT://"))
		{
			If ([System.DirectoryServices.DirectoryEntry]::Exists($Name))
			{
				return $Name
			}
		}
		elseif ([System.DirectoryServices.DirectoryEntry]::Exists("WinNT://$env:computername/$Name"))
		{
			return "WinNT://$env:computername/$name"
		}
		else
		{
			Write-Verbose "Computer is not joined to a domain and unable to find a user account with the name $($name) on the local computer"
			return $null			
		}
	}
	
	If ($Name.StartsWith("LDAP://"))
	{
		
		if ([System.Text.RegularExpressions.Regex]::IsMatch($Name,"dc=",[System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
		{
			
			if ([System.DirectoryServices.DirectoryEntry]::Exists($name))
			{
				return $Name
			}
			else
			{
				Write-Verbose "Unable to find $Name"
				return $null
			}
		}
		else
		{
			
			 if ([System.DirectoryServices.DirectoryEntry]::Exists("$name,$(Get-AMDomainDN)"))
			 {
				return "$name,$(Get-AMDomainDN)"
			 }
			 else
			 {
				Write-Verbose "Unable to find $Name,$(Get-AMDomainDN)"
				return $null
			 }
		}
	}
		
		<# #Check if an ldap string was specified
		if ([System.Text.RegularExpressions.Regex]::IsMatch($Name,"ou=|cn=|dc=",[System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
		{
			if ($Name.StartsWith("LDAP://") -eq $true)
			{
				if ([System.DirectoryServices.DirectoryEntry]::Exists($name) -eq $true)
				{
					$ReturnValue = $name
				}
			}
			elseif ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$name,$(Get-AMDomainDN)") -eq $true)
			{
				$ReturnValue = "LDAP://$name,$(Get-AMDomainDN)"
			} 
			else
			{
				if ([System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$name") -eq $true)
				{
					$ReturnValue = "LDAP://$name"
				}
				else
				{
					return $null
					#throw "Unable to find a user account with the name $($name) in the domain"
				}
			}
		} #>
		else
		{
			#Let's look at regular NT4 Style domain name
			if (($Name.Split('\')).Count -eq 2)
			{
				$Domain = $Name.Split('\')[0]
				$ObjName = $Name.Split('\')[1]
					
				#Determine BUILTIN name
				$objSID = New-Object System.Security.Principal.SecurityIdentifier ("S-1-5-32-544")
				$BuiltinName = @($($($objSID.Translate([System.Security.Principal.NTAccount])).Value).Split('\'))[0]			
			
				if (($Domain -eq $env:COMPUTERNAME) -or ($Domain -eq $BuiltinName))
				{
					#Local
					if ([System.DirectoryServices.DirectoryEntry]::Exists("WinNT://$env:COMPUTERNAME/$ObjName"))
					{
						$ReturnValue = "WinNT://$env:COMPUTERNAME/$ObjName"
					}
				else
					{
						Write-Verbose "Unable to find a user account with the name $($name) on the local computer"
						Return $null
						
					}
				}
				else
				{
					$dEntry = $null
		    		[System.DirectoryServices.ActiveDirectory.DirectoryContext] $DC = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $Domain)
		    	    [System.DirectoryServices.ActiveDirectory.Domain] $DOM = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DC)
		    	    [System.DirectoryServices.DirectoryEntry] $DE = $DOM.GetDirectoryEntry()
					[System.DirectoryServices.DirectorySearcher] $DS = new-object System.DirectoryServices.DirectorySearcher($DE,"sAMAccountName=$ObjName")
					[void] $DS.PropertiesToLoad.Add("distinguishedname")
					$dEntry = $DS.FindOne()

					if ($null -eq $dEntry)
					{
						Write-Verbose "Unable to find a user account with the name $($name) in the domain"
						return $null 
					}
					else
					{
						$dName = ($DS.FindOne()).Properties["distinguishedname"]
						$ReturnValue = "LDAP://$dName"
					}
				}
			}
			else {
				try 
				{
					#Finally, try name only. ONLY search in own domain and local machine, not the complete forest!!!
					$dEntry = $null
					[System.DirectoryServices.ActiveDirectory.Domain] $DOM = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
					[System.DirectoryServices.DirectoryEntry] $DE = $DOM.GetDirectoryEntry()
					
					#The check below is because if AM is initializing there is no collection to check for and everything loops
					if ($AmInitializationMode){
						$DS = new-object System.DirectoryServices.DirectorySearcher($DE,"sAMAccountName=$Name")
					} else {
						[string] $DomainControllerValue = [string] (Get-AMVariable `
							-Id $AmWellKnown::Plugins.ActiveDirectory.DomainControllerNameVariable.Id `
							-ParentId $AmWellKnown::Plugins.ActiveDirectory.Id `
							-CollectionId (Get-AMCollection -Current).Id `
							).Value

						[System.DirectoryServices.DirectorySearcher] $DS = $null
						if (![string]::IsNullOrEmpty($DomainControllerValue))  {
							$DomainControllerEntry = [adsi] "LDAP://$DomainControllerValue/$($DE.distinguishedName)"
							#$DS = [adsisearcher] $DomainControllerEntry
							$DS = new-object System.DirectoryServices.DirectorySearcher($DomainControllerEntry,"sAMAccountName=$Name")
						}
						else {
							$DS = new-object System.DirectoryServices.DirectorySearcher($DE,"sAMAccountName=$Name")
						}
					}
					
					[void] $DS.PropertiesToLoad.Add("distinguishedname")

					$dEntry = $DS.FindOne()
						
					if ($null -eq $dEntry)
					# Couldn't find the username, try if it's a computername
					{
							[System.DirectoryServices.DirectorySearcher] $DS = new-object System.DirectoryServices.DirectorySearcher($DE,"sAMAccountName=$Name`$")
							[void] $DS.PropertiesToLoad.Add("distinguishedname")
							$dEntry = $DS.FindOne()
					}
				}
				catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException]
				{					
					# Something went wrong looking in the domain, probably machine is not part of the domain
					Write-Verbose "An error occured while looking up the user in the domain, probably the machine is not joined to any domain"	
					return $null
					
				}
					
					if ($null -eq $dEntry)
					{
					# If we still did not find anything in the domain, look in the local machine
						if ([System.DirectoryServices.DirectoryEntry]::Exists("WinNT://$env:computername/$Name"))
						{
							$ReturnValue = "WinNT://$env:computername/$name"
						}
						else
						{
							write-verbose "Computer is joined to a domain but we were unable to find a user account with the name $($name) on the local computer or in the domain"
							return $null
							
						}
					}
					else
					{
						$dEntry = $DS.FindOne()
                        if ($dEntry -is [Object]) {
                            $dName = $dEntry.Properties["distinguishedname"]
                            $ReturnValue = "LDAP://$dName"
                        }
                        else {
                            $ReturnValue = $null
                        }
					}
					
			}	
		}
			return $ReturnValue
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Retrieves the SID for the specified name.

	.Description
 	Retrieves the SID for the specified name, also supports LDAPPaths
  
	.Parameter Name
 	The name of the group or user to retrieve the sid for.
  
	.Parameter Username
	Username that is used to connect to AD with.
	
	.Parameter Password
	The password for the username to connect to AD with.
 
 	.Example
 	"UserName" | Get-AMSID
 	
 	.Example
 	Get-AMSID -Name "LDAP://CN=UserName,OU=AM,DC=AM,DC=LAN"
#>
function Get-AMSID
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Name,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Username,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Password		
	)

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
    if($Name.Contains("\")) 
	{ 
		$ADName = $Name.Split("\")[1] 
	}
	else
	{
		$ADName = $Name
	}
		
    
	if ($Name -match "^S-\d-(\d+-){1,14}\d+$")		
	{
		# SID constructor detected, directly determine SID
		$SID = New-Object System.Security.Principal.SecurityIdentifier($Name)
        return $SID
	}
	# If no valid LDAP path can be found, see if it's a BUILTIN/WellKnownSID account
	ForEach ($WellKnownSID in [Security.Principal.WellKnownSidType].GetEnumValues()) 
	{				  
		try 
		{
		$SID = New-Object Security.Principal.SecurityIdentifier($WellKnownSID, $null)
		if ($SID.Translate([Security.Principal.NTAccount]).Value -eq $Name)
		{
			return $SID
		}
		}
		catch {}
	}
	# Special names that are not translateble with wellknownSids
	Switch ($ADName)
	{
		"ALL APPLICATION PACKAGES"	{return (new-object Security.Principal.SecurityIdentifier("S-1-15-2-1"))}
		"ALL_APP_PACKAGES"	{return (new-object Security.Principal.SecurityIdentifier("S-1-15-2-1"))}						
	}
		
	#Handle Well Known SIDs in case of translated OS
	Switch ($Name.ToUpper())
	{
		"NULL SID" {return (new-object Security.Principal.SecurityIdentifier("S-1-0-0"))}
		"EVERYONE" {return (new-object Security.Principal.SecurityIdentifier("S-1-1-0"))}						
		"LOCAL" {return (new-object Security.Principal.SecurityIdentifier("S-1-2-0"))}
		"CONSOLE LOGON" {return (new-object Security.Principal.SecurityIdentifier("S-1-2-1"))}
		"CREATOR OWNER" {return (new-object Security.Principal.SecurityIdentifier("S-1-3-0"))}
		"CREATOR GROUP" {return (new-object Security.Principal.SecurityIdentifier("S-1-3-1"))}
		"CREATOR OWNER SERVER" {return (new-object Security.Principal.SecurityIdentifier("S-1-3-2"))}
		"CREATOR GROUP SERVER" {return (new-object Security.Principal.SecurityIdentifier("S-1-3-3"))}
		"OWNER RIGHTS" {return (new-object Security.Principal.SecurityIdentifier("S-1-3-4"))}
		"NT SERVICE\ALL SERVICES" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-80-0"))}
		"NT AUTHORITY\DIALUP" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-1"))}
		"NT AUTHORITY\NETWORK" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-2"))}
		"NT AUTHORITY\BATCH" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-3"))}
		"NT AUTHORITY\INTERACTIVE" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-4"))}
		"NT AUTHORITY\SERVICE" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-6"))}
		"NT AUTHORITY\ANONYMOUS LOGON" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-7"))}
		"NT AUTHORITY\PROXY" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-8"))}
		"NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-9"))}
		"NT AUTHORITY\SELF" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-10"))}
		"NT AUTHORITY\AUTHENTICATED USERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-11"))}
		"NT AUTHORITY\RESTRICTED" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-12"))}
		"NT AUTHORITY\TERMINAL SERVER USER" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-13"))}
		"NT AUTHORITY\REMOTE INTERACTIVE LOGON" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-14"))}
		"NT AUTHORITY\THIS ORGANIZATION" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-15"))}
		"NT AUTHORITY\IUSR" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-17"))}
		"NT AUTHORITY\SYSTEM" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-18"))}
		"NT AUTHORITY\LOCAL SERVICE" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-19"))}
		"NT AUTHORITY\NETWORK SERVICE" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-20"))}
		"BUILTIN\ADMINISTRATORS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-544"))}
		"BUILTIN\USERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-545"))}
		"BUILTIN\GUESTS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-546"))}
		"BUILTIN\POWER USERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-547"))}
		"BUILTIN\BACKUP OPERATORS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-551"))}
		"BUILTIN\REPLICATOR" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-552"))}
		"NT AUTHORITY\NTLM AUTHENTICATION" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-64-10"))}
		"NT AUTHORITY\SCHANNEL AUTHENTICATION" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-64-14"))}
		"NT AUTHORITY\DIGEST AUTHENTICATION" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-64-21"))}
		"NT SERVICE\NT SERVICE" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-80"))}
		"MANDATORY LABEL\UNTRUSTED MANDATORY LEVEL" {return (new-object Security.Principal.SecurityIdentifier("S-1-16-0"))}
		"MANDATORY LABEL\LOW MANDATORY LEVEL" {return (new-object Security.Principal.SecurityIdentifier("S-1-16-4096"))}
		"MANDATORY LABEL\MEDIUM MANDATORY LEVEL" {return (new-object Security.Principal.SecurityIdentifier("S-1-16-8192"))}
		"MANDATORY LABEL\MEDIUM PLUS MANDATORY LEVEL" {return (new-object Security.Principal.SecurityIdentifier("S-1-16-8448"))}
		"MANDATORY LABEL\HIGH MANDATORY LEVEL" {return (new-object Security.Principal.SecurityIdentifier("S-1-16-12288"))}
		"MANDATORY LABEL\SYSTEM MANDATORY LEVEL" {return (new-object Security.Principal.SecurityIdentifier("S-1-16-16384"))}
		"MANDATORY LABEL\PROTECTED PROCESS MANDATORY LEVEL" {return (new-object Security.Principal.SecurityIdentifier("S-1-16-20480"))}		
		"NT SERVICE\ALL SERVICES" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-80-0"))}
		"BUILTIN\REMOTE DESKTOP USERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-555"))}
		"BUILTIN\NETWORK CONFIGURATION OPERATORS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-556"))}
		"BUILTIN\PERFORMANCE MONITOR USERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-558"))}
		"BUILTIN\PERFORMANCE LOG USERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-559"))}
		"BUILTIN\DISTRIBUTED COM USERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-562"))}
		"BUILTIN\CRYPTOGRAPHIC OPERATORS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-569"))}
		"BUILTIN\EVENT LOG READERS" {return (new-object Security.Principal.SecurityIdentifier("S-1-5-32-573"))}
	}
			
	$SID = $null
	# Try to find ldap path for full name first
	$LDAPFullPath = Get-AMLDAPPath -Name $Name
	If ($LDAPFullPath -ne $null)
	{
		$DirectoryEntry = Get-AMDirectoryEntry -LDAPPath $ldapfullpath -Username $username -Password $password
		$SID = New-Object System.Security.Principal.SecurityIdentifier($($DirectoryEntry.objectSid),0)
		return $SID
	}
	Else
	{
		# Try resolving name from AD accounts first				
		$LDAPPath = Get-AMLDAPPath -Name $ADName												
		If ($LDAPPath -ne $null)
		{
			$DirectoryEntry = Get-AMDirectoryEntry -LDAPPath $ldappath -Username $username -Password $password
			$SID = New-Object System.Security.Principal.SecurityIdentifier($($DirectoryEntry.objectSid),0)
			return $SID
		}
		else			
		{
			Write-AMWarning "Cannot find LDAP path or BUILTIN account name for $($Name)"
		}			
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


}

<#
	.Synopsis
	Moves directoryentry object.

	.Description
	Moves an object the specified LDAP path and return true when object was moved, false if object was not moved.
	
	.Parameter DirectoryEntry
	The DirectoryEntry object to move
	
	.Parameter Destination
 	The LDAPPath where to move the directoryentry to.
	
	.Parameter Username
	The username to connect to the domain controller(s) with.
	
	.Parameter Password
	The password for the username to connect to the domain controller(s) with
   
 	.Example
 	Get-AMDirectoryEntry -LDAPPath "LDAP://CN=Computer,OU=Computers" | Move-AMDirectoryEntry -Destination "LDAP://OU=AM"
 	
 	.Example
	$LDAPPath = Get-AMLDAPPath -Name "Computer"
	$DirEntry = Get-AMDirectoryEntry -LDAPPath $LDAPPath -Username "AM\Administrator" -Password "somepassword"
	Move-AMDirectoryEntry -DirectoryEntry $DirEntry -Destination "LDAP://OU=AM" -Username "AM\Administrator" -Password "somepassword"

#>
function Move-AMDirectoryEntry {
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory = $true, ValueFromPipeline = $false)]
		[System.DirectoryServices.DirectoryEntry]
		$DirectoryEntry,
		[parameter(mandatory = $false, ValueFromPipeline = $false)]
		[string]
		$Destination,
		[parameter(mandatory = $false, ValueFromPipeline = $false)]
		[string]
		$Username,
		[parameter(mandatory = $false, ValueFromPipeline = $false)]
		[string]
		$Password
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		
	# Put object path in variable to which we can compare later
	$OriginalPath = $DirectoryEntry.Path
			
		
	# Put object path in variable to which we can compare later
	$OriginalPath = $DirectoryEntry.Path
	# Get the OU, or create it if it doesn't exist
	$OU = New-AMOU -LDAPPath $Destination -Username $Username -Password $Password			
	# Move the directory entry
	Write-AMInfo "Moving $($DirectoryEntry.Name) to $($OU.Path)"
	$DirectoryEntry.psbase.MoveTo($OU)
			
	Wait-AMObjectReplication -DirectoryEntry $DirectoryEntry
			
	# Check if object was moved
	If ($DirectoryEntry.Path -ne $OriginalPath) {
		return $true 
	}
	else {
		return $false
	}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Creates a new group.

	.Description
 	Creates a new group and returns the DirectoryEntry object, or returns the existing DirectoryEntry object if it already exists. ParentOU's are created if they don't exist.
  
	.Parameter Name
	The name of the group to create

	.Parameter LDAPPath
 	The LDAPPath of the OU where to create the group.
	
	.Parameter Scope
	The scope of the group to create
	
	.Parameter Description
	The description to add to the AD group
	
	.Parameter Username
	The username to connect to AD with
	
	.Parameter Password
	The password to connect to AD with
  
	.Example
 	"OU=Automation Machine Root,OU=AM" | New-AMOU
 	
 	.Example
 	New-AMOU -LDAPPath "LDAP://OU=Automation Machine Root,OU=AM,DC=AM,DC=lan" -Username "AM\Administrator" -Password "SomePassword"
#>
function New-AMGroup
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Name,
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[AutomationMachine.Plugins.ActiveDirectory.GroupScope]
		$Scope,
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$LDAPPath,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Username,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Password,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$description = "Managed by Automation Machine"
	)
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

				
		#Setup the ADSI paths
		switch ($scope)
		{
			([AutomationMachine.Plugins.ActiveDirectory.GroupScope]::Local) {
				$FullLdapPath = "WinNT://$env:computername/$name"
				break;
			}
			default {
				#Strip LDAP://
				$ldappath = [System.Text.RegularExpressions.Regex]::Replace($ldappath,"LDAP://","",[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
				$FullLdapPath = "LDAP://cn=$name,$ldappath"
				$FullOULdapPath = "LDAP://$ldappath"
				break;
			}
		}
				
		#Check if the group already exists
		Write-Verbose "Checking if group exists"
		if (Get-AMLDAPPath -Name $Name)
		{
			return $(Get-AMLDAPPath -Name $Name)
		}
				
		#Create the OU if needed (AD Only)
		Write-Verbose "Creating OU, if needed" 
		[System.DirectoryServices.DirectoryEntry] $DE = $null
		if ($scope -ne [AutomationMachine.Plugins.ActiveDirectory.GroupScope]::Local) {
				$DE = New-AMOU -LDAPPath $FullOULdapPath -Username $Username -Password $Password
		}
		else
		{
			$DE = Get-AMDirectoryEntry -LDAPPath "WinNT://$env:computername"
		}

		if ($DE -eq $null) {
			return $null
		}

		#Finally, create the group
		Write-AMInfo "Creating security group: $Name"
		if ($scope -ne [AutomationMachine.Plugins.ActiveDirectory.GroupScope]::Local) 
		{			     
			Write-Verbose "Creating AD group with scope $Scope"
			$Group = $DE.Create("group","cn=$name")
			[void] $Group.Put("sAMAccountName", $name)
			if ($description -ne "") { [void] $Group.Put("description", $description) }
			[void] $Group.Put("grouptype", $scope)
			[void] $Group.SetInfo()
			$ReturnValue = $Group

			Wait-AMObjectReplication -DirectoryEntry $ReturnValue
		}
		else
		{
			Write-Verbose "Creating local group"
			$Group = $DE.Create("group",$name)
			if ($description -ne "") { [void] $Group.Put("description", $description) }
			[void] $Group.SetInfo()
			$ReturnValue = $Group
		}
							
		return $ReturnValue
		
    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Creates a new OU.

	.Description
 	Creates a new OU and returns the DirectoryEntry object, or returns the existing DirectoryEntry object if it already exists. ParentOU's are created if they don't exist.
  
	.Parameter LDAPPath
 	The LDAPPath of the new OU to create.
	
	.Parameter Username
	The username to connect to AD with
	
	.Parameter Password
	The password to connect to AD with
  
	.Example
 	"OU=Automation Machine Root,OU=AM" | New-AMOU
 	
 	.Example
 	New-AMOU -LDAPPath "LDAP://OU=Automation Machine Root,OU=AM,DC=AM,DC=lan" -Username "AM\Administrator" -Password "SomePassword"
#>
function New-AMOU {
    param
    (
        [cmdLetbinding()]
        [parameter(mandatory = $true, ValueFromPipeline = $false)]
        [string]
        $LDAPPath,
        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $Username,
        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $Password
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    $ReturnValue = $null
    [string] $DomainControllerValue = [string] (Get-AMVariable `
            -Id 30751e04-9bda-402a-8a5d-1fb26171fc09 `
            -ParentId 9662ad7d-3fb6-4180-84fd-bb4715374b0a `
            -CollectionId (Get-AMCollection -Current).Id `
    ).Value
    $DomainControllerName = ""
    if (-not [string]::IsNullOrEmpty($DomainControllerValue)) {
        $DomainControllerName = "$DomainControllerValue/"
    }
    $LdapPrefix = "LDAP://$DomainControllerName"
    $LDAPPath = $LDAPPath.TrimStart("LDAP://")
    $LDAPPath = "$($LdapPrefix)$($LDAPPath)"			

    Write-Verbose "Checking if OU already exists"	
    #Check if OU exists
    $OU = Get-AMDirectoryEntry -LDAPPath $LDAPPath -Username $username -Password $password
    if ($null -ne $OU) {
        $ReturnValue = $OU 
    }
    else {
        Write-AMInfo "Creating OU: $($ldapPath)"
        #Find first available LDAP path
        $ldappath = [System.Text.RegularExpressions.Regex]::Replace($ldappath, $LdapPrefix, "", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        $PathTokens = $ldappath.Split(",")
        $ToBeAdded = New-Object System.Collections.ArrayList
        [System.DirectoryServices.DirectoryEntry] $NewOU = $null
				
        :FoundParent for ([int] $index = 0 ; $index -lt $PathTokens.Count ; $index++) {	
            [void] $ToBeAdded.Insert(0, $PathTokens[$index])
            $PathTokens[$index] = $null
            $TmpParentPath = ""
            $PathTokens | % { $TmpParentPath += "$_," }
            $TmpParentPath = $TmpParentPath | % { $_.TrimStart(",") } | % { $_.TrimEnd(",") } | % { $_.TrimStart() } | % { $_.TrimEnd() } 
					
            $NewOU = Get-AMDirectoryEntry -LDAPPath "$($LdapPrefix)$($TmpParentPath)" -Username $Username -Password $Password
            if ($null -ne $NewOU) {
                break FoundParent
            }	
        }

        foreach ($Token in $ToBeAdded) {
            $NewOU = $NewOU.Create("organizationalUnit", $token)
            [void] $NewOU.SetInfo()
        }
        $ReturnValue = Get-AMDirectoryEntry -ldappath "$($LdapPrefix)$($ldappath)" -username $username -password $password
    }

    Wait-AMObjectReplication -DirectoryEntry $ReturnValue
				
    return $ReturnValue

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Sets the ACL buffer size.

	.Description
 	By default, the ACL buffer is set to support a maximum of 120 groups. Use this cmdlet to expand the buffer to support more groups.
	
	.Parameter MaxTokenSize
	Specifies the buffer size for the ACL buffer. Default: 65535
	
	.Parameter Reset
	Resets the ACL buffer to the original value.
	
 	.Example
 	Set-AMMaxTokenSize
 		
	.LINK
	http://support.microsoft.com/kb/327825
	
#>
function Set-AMMaxTokenSize
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$false)]
		[int]
		$MaxTokenSize = 65535,
		
		[parameter(mandatory=$false)]
		[switch]
		$Reset
	)

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

						

		
		If (-not $Reset)
		{
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "MaxTokenSize" -Type DWORD -Value $MaxTokenSize -Backup
		}
		If ($Reset)
		{
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "MaxTokenSize" -Reset			
		}

	
    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Applies permissions to registry or filesystem objects.

	.Description
 	Applies permissions to registry or filesystem objects.
  
	.Parameter Path
 	The path to apply permissions to, can be folder,file or registry location.
	
	.Parameter Permissions
	The permissions to apply
	
	.Parameter PrincipalName
	The security principal to set the permissions for (user or group)
	
	.Parameter Type
	The type of permissions to set, can be Allow or Deny
	
	.Parameter Username
	The username to connect to AD with to lookup the SID for the principalname
	
	.Parameter Password
	The password to connect to AD with
	
	.Parameter Recurse
	Switch parameter to specify if permissions need to be set recursively
	
	.Parameter Append
	Switch parameter to specify if permissions need to be appended to current ACL of object (default is to replace existing ACL)
  
	.NOTES
	Be aware that the registry has different permissions then the filesytem.
	See [System.Security.AccessControl.RegistryRights] enumeration for supported values for the registry
	See [System.Security.AccessControl.FileSystemRights] enumeration for supported values for filesystem
 
 	.Example
 	Set-AMPermissions -Path D:\Test -Permissions "FullControl" -PrincipalName "Domain\Testuser" -Type "Allow" -Recurse
 	
 	.Example
 	Set-AMPermissions -Path D:\Test\tesfile.exe -Permissions "FullControl" -PrincipalName "Domain\Testuser" -Type "Allow"
	
	.Example
 	Set-AMPermissions -Path "HKLM:\Sofware\Automation Machine" -Permissions "CreateSubkey" -PrincipalName "Domain\Testuser" -Type "Allow"
	
	.Example
 	Set-AMPermissions -Path "HKLM:\Sofware\Automation Machine" -Permissions "SetValue" -PrincipalName "Domain\Testuser" -Type "Deny" -Username "AM\Administrator" -Password "SomePassword"
#>
function Set-AMPermissions
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Path,
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Permissions,
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$PrincipalName,
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[ValidateSet("Allow","Deny")]
		[string]
		$Type,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Username,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Password,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$Recurse,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$Append

	)

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
	$Path = Convert-AMRegistryPath -Path $Path

	If (!(Test-Path $Path)) {throw "$Path was not found"}
	Write-Verbose "Setting up ACL object for $Path"
	#Get Security Identifiers of system and local admins
	$systemAccount = New-Object system.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid,$null)
	$AdminsAccount = New-Object system.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
		
	#Get-ACLs
	$acls = Get-Acl $Path
	Write-Verbose "Setting owner"
	if (Test-AMElevation) {		$acls.SetOwner($AdminsAccount) }
		
	#Get Current ACL
	foreach ($acl in $acls)
	{
		#Remove inheritance and do not copy inherited rules
		$acl.SetAccessRuleProtection($true, $false)
			
		#Remove all existing accessrules
		If (-not ($Append))
		{
			foreach ($ace in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
			{
				$acl.RemoveAccessRuleAll($ace)
			}
		}
		#Add local system and local administrators accounts
		switch ($acl.GetType())
		{
			"System.Security.AccessControl.DirectorySecurity"
			{
				$AccessRuleSystem = New-Object system.Security.AccessControl.FileSystemAccessRule($systemAccount,[System.Security.AccessControl.FileSystemRights]::FullControl,[System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit", [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
				$AccessRuleAdmins = New-Object system.Security.AccessControl.FileSystemAccessRule($AdminsAccount,[System.Security.AccessControl.FileSystemRights]::FullControl,[System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit", [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
			}
			"System.Security.AccessControl.FileSecurity"
			{
				$AccessRuleAdmins = New-Object system.Security.AccessControl.FileSystemAccessRule($AdminsAccount,[System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
				$AccessRuleSystem = New-Object system.Security.AccessControl.FileSystemAccessRule($systemAccount,[System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
			}
			"System.Security.AccessControl.RegistrySecurity"
			{
				$AccessRuleAdmins = New-Object System.Security.AccessControl.RegistryAccessRule($AdminsAccount,[Security.AccessControl.RegistryRights]::FullControl,[System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit", [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
				$AccessRuleSystem = New-Object System.Security.AccessControl.RegistryAccessRule($systemAccount,[Security.AccessControl.RegistryRights]::FullControl,[System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit", [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
			}
			default
			{
				throw "Unable to determine ACL type, cannot continue"
			}
		}
		Write-Verbose "Adding local admins and system principals to ACL"
		$acl.addaccessrule($AccessRuleSystem) 
		$acl.addaccessrule($AccessRuleAdmins)
	}
				

			
		Write-Verbose "Getting SID for $PrincipalName"			
		# translate the groupname to a SID
		$SID = Get-AMSID -Name $PrincipalName -Username $Username -Password $Password
			

		Switch ($acl.GetType().ToString())
		{
			"System.Security.AccessControl.DirectorySecurity" {
				If ($Recurse)
				{
					$PropogationFlag = [System.Security.AccessControl.PropagationFlags]::None
					$Inherit = $([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
				}
				else # Not recursive, set propopgation
				{
					$acl.SetAccessRuleProtection($true, $false)	
					$PropogationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
					$Inherit = $([System.Security.AccessControl.InheritanceFlags]::None)
			
				}
				$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SID,$Permissions,$Inherit,$PropogationFlag,$Type)

			}
				
			"System.Security.AccessControl.FileSecurity" { 
				$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SID,$Permissions,$Type)
			}
				
			"System.Security.AccessControl.RegistrySecurity" {
				If ($Recurse)
				{
						
					$PropogationFlag = [System.Security.AccessControl.PropagationFlags]::None
					$Inherit = $([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
				}
				else # Not recursive, set propopgation
				{
					$acl.SetAccessRuleProtection($true, $false)	
					$PropogationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
					$Inherit = $([System.Security.AccessControl.InheritanceFlags]::None)
				}
				$accessRule = New-Object System.Security.AccessControl.RegistryAccessRule($SID,$Permissions,$Inherit,$PropogationFlag,$Type)	
			}
				
		}
		Write-Verbose "Adding accessrule $Permissions for $PrincipalName"
		$acl.AddAccessRule($accessRule)
		$acl | Set-Acl $Path
			
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
.SYNOPSIS
Waits for AD object to exist at any replication neighbour.

.DESCRIPTION
The AMObjectReplication cmdlet waits for AD object to be replicated to any replication neighbour.

.PARAMETER DirectoryEntry
Specified an AD DirectoryEntry object that should be replicated.

.PARAMETER DomainController
Specified a domain controller.

.PARAMETER Domain
Specifies a domain object.

.EXAMPLE
Wait-AMObjectReplication -DirectoryEntry (Get-AMDirectoryEntry -LDAPPath (Get-AMLDAPPath -Name "ADObjectPath"))
#>
function Wait-AMObjectReplication {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName="Default", Mandatory=$true)]
        [Parameter(ParameterSetName="DomainController", Mandatory=$true)]
        [System.DirectoryServices.DirectoryEntry]
        $DirectoryEntry,

        [Parameter(ParameterSetName="DomainController", Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectory.DomainController]
        $DomainController,

        [Parameter(ParameterSetName="DomainController", Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectory.Domain]
        $Domain
    )

    [string] $DomainControllerValue = [string] (Get-AMVariable `
            -Id $AmWellKnown::Plugins.ActiveDirectory.DomainControllerNameVariable.Id `
            -ParentId $AmWellKnown::Plugins.ActiveDirectory.Id `
            -CollectionId (Get-AMCollection -Current).Id `
    ).Value

    $DomainControllerName = ""
    if (-not [string]::IsNullOrEmpty($DomainControllerValue)) {
        $DomainControllerName = "$DomainControllerValue/"
    }

    if ([string]::IsNullOrEmpty($DomainControllerValue)) {
        # Wait for group to exist at first replication neighbour
        Write-Verbose "Getting DC replication neighbors"
        Write-AMInfo "Getting DC replication neighbors"
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        if ($PSCmdlet.ParameterSetName -eq "Default") {
            $DC = $Domain.DomainControllers[0]
        }
        else {
            $DC = $DomainController
        }
        Write-AMInfo "Domain controller: $($DC.Name)"
        $SiteDCs = $Domain.FindAllDiscoverableDomainControllers($DC.SiteName) | Select-Object -ExpandProperty Name
		
        $ReplicationNeighbors = $DC.GetAllReplicationNeighbors() | Where-Object { $SiteDCs -Contains $_.sourceserver } | Select-Object -Unique -ExpandProperty SourceServer
        $ReplicationNeighbor = $ReplicationNeighbors | Select-Object -First 1
        If ($null -ne $ReplicationNeighbor) {
            $MaxCount = 1800
            $i = 0;
            $LDAPReplicationNeighbor = Convert-AMSiteNameToLdapPath -SiteName $ReplicationNeighbor -DirectoryEntryPath $DirectoryEntry.Path -DomainControllerName $DomainControllerName
            Write-AMInfo "Replication neighbor: $LDAPReplicationNeighbor"
            $NeighborIndex = 0
            while ($null -eq (Get-AMLDAPPath $($LDAPReplicationNeighbor))) {
                $i += 1
                if (($i % 16 -eq 0) -and ($NeighborIndex -lt ($ReplicationNeighbors.Count - 1))) {
                    $NeighborIndex++
                    $LDAPReplicationNeighbor = Convert-AMSiteNameToLdapPath -SiteName $ReplicationNeighbors[$NeighborIndex] -DirectoryEntryPath $DirectoryEntry.Path -DomainControllerName $DomainControllerName
                    Write-AMInfo "Replication neighbor: $LDAPReplicationNeighbor"
                }
                if ($i -eq 64) {
                    $index = $Domain.DomainControllers.IndexOf($DC) + 1
                    if ($index -lt $Domain.DomainControllers.Count) {
                        try {
                            Wait-AMObjectReplication -DirectoryEntry $DirectoryEntry -DomainController $Domain.DomainControllers[$index] -Domain $Domain
                            break
                        }
                        catch {
                        }
                    }
                }
                if ($i -ge $MaxCount) { throw "Unable to find AD object: $($DirectoryEntry.Path) on $($ReplicationNeighbor) after $($MaxCount) seconds" }
                Write-Verbose "Waiting for $($DirectoryEntry.Path) to appear on $ReplicationNeighbor"
                Write-AMInfo "Waiting for $($DirectoryEntry.Path) to appear on $ReplicationNeighbor"

                Start-Sleep -Seconds 1
            }
        }
        else {
            Write-Verbose "No DC replication neighbors found, not waiting for replication"
        }
    }
}
<#
	.Synopsis
	Copies over one directory's content to the other directory over AM File Service.

	.Description
 	Copies over one directory's content to the other directory over AM File Service.
	
	.Parameter Source
	Specifies the name of the source directory.
	
	.Parameter Destination
	Specifies the name of the destination directory.
	
	.Example
	Copy-Directory-OverFileService -Source "c:/myData" -Destination "d:/myDataCopy"
#>
function Copy-AMSDirectory
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Path,
		
		[cmdLetbinding()]
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Destination		
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	Write-Verbose "Copying directory $Path over the file service to $Destination"
	try
	{
		$proxy  = Get-AMSFileServiceProxy

		ForEach ($file in (Get-ChildItem $Path -File -Recurse))
		{
			$fileStream = $null
			$downloadStream = $null
			try
			{
			$relativePath = $file.FullName.Replace($Path, "")
			$destinationPath = Join-Path $Destination $relativePath

			$request = New-Object AutomationMachine.Services.Clients.AmFileServiceClient.AmFileServiceReference.DownloadRequest
			$request.FileName = $file.FullName

			$downloadStream = $proxy.DownloadFile($request)

			$destinationDirectory = Split-Path $destinationPath
			if(!(Test-Path $destinationDirectory)) 
			{
				New-Item -Path $destinationDirectory -ItemType Directory
			}

			$fileStream = [System.IO.File]::Create($destinationPath)
			$downloadStream.FileStream.CopyTo($fileStream)
			$downloadStream.FileStream.Close()
			
			$fileStream.Close()
			$fileStream.Dispose()
			$downloadStream.FileStream.Dispose()
		}	
			finally
			{
				if ($fileStream -ne $null) {
					$fileStream.Close()
					$fileStream.Dispose()
				}
				if (($downloadStream -ne $null) -and ($downloadStream.FileStream -ne $null)) {
					$downloadStream.FileStream.Dispose()
				}
			}
		}	

		$proxy.Close()
		Write-Verbose "Copied directory succesfully over the file service"
	}
	catch
	{
		Write-Host "There were errors during directory copy over the file service"
		Write-Verbose $_
		
		$proxy.Close()
		
		throw;
	}

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the action item templates of the current environment.

	.Description
 	The Get-AMActionItemTemplates cmdlet gets the action item templates of the current environment. You can filter the templates returned by ID or name.
	
	.Parameter Name
	Specifies the name of the action item template.
	
	.Parameter Id
	Specifies the ID of the action item variable.
	
	.Example
	Get-AMActionItemTemplate
	This command displays all action item templates of the current environment.
	
	.Example
	Get-AMActionItemTemplate -Name "D*"
	This command displays action item templates with names that begin with the letter "D".
#>
function Get-AMActionItemTemplate
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*"
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

	$AMDataManager.Environment.ActionItemTemplates | Where-Object {($_.name -like $Name) -and ($_.Id -like $Id)}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the collections of the current environment.

	.Description
 	The Get-AMCollection cmdlet gets the collections of the current environment. You can filter the collections returned by ID, name or parent.
	
	.Parameter Name
	Specifies the name of the collection.
	
	.Parameter Id
	Specifies the ID of the collection.
	
	.Parameter ParentId
	Specifies the Parent ID of the collection.
	
	.Parameter ParentName
	Specifies the Parent name of the collection.
	
	.Parameter Current
	Specifies to get the collection for the current computer
	
	.Example
	Get-AMCollection
	This command displays all collection of the current environment.
	
	.Example
	Get-AMCollection -Name "D*"
	This command displays collection with names that begin with the letter "D".
#>
function Get-AMCollection
{
	[CmdletBinding(DefaultParameterSetName="Default")]
	param
	(
		
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*",
		
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$ParentName = "*",
		
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$ParentId = "*",
		
		[parameter(ParameterSetName="Current",mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$Current
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		If ($PSCmdlet.ParameterSetName -eq "Current")
		{
			Write-Verbose "Current computer name: $($Env:COMPUTERNAME)"
			$Computer = Get-AMComputer -Name $Env:COMPUTERNAME | Select-Object -First 1 # The select-object was put there to prevent getting an array back in case of multiple machine
			
			if ($Computer -is [object]) {
				$Collection = $AMDataManager.Environment.Collections | Where-Object { $_.Id -eq $Computer.CollectionId }
				if ($Collection -is [object]) {
					return $Collection
				}
			}
			
			$Collections = Get-AMCollection -Name *
			foreach ($Col in $Collections) {
				if($(Resolve-AMFilterExpression -Expression $Col.AutoAddRule))
				{
					Write-Verbose "Computer matched auto-add rules for collection: $($Col.Name)"
					return $Col
				}
			}
			
			Write-Verbose "Computer account not found in AM database"

            # This computer does not exist in AM. We need to check if this computer
            # has a collection ID in the registry
            try
            {
                $AMRegConfig = Get-Item -Path "HKLM:\Software\Automation Machine" -ErrorAction Stop
                $RegCollectionId = $AMRegConfig.GetValue("AMCollectionID")					
                $Collection = Get-AMCollection -Id $RegCollectionId
				If ($Collection -eq $null) {throw "Could not find collection in registry"}
                Write-Verbose "Got collection `"$($Collection.Name)`" from registry"
			    return $Collection
            }
            catch [Exception]
            {
				Write-AMWarning "Could not determine collection from registry setting"
				return $null
			}
		}
		else
		{
			$Collection = $AMDataManager.Environment.Collections | Where-Object {($_.name -like $Name) -and ($_.Id -like $Id) -and ($_.Parent -like $ParentName) -and ($_.ParentId -like $ParentId)}
		}
		
		return $Collection

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets event map of the specified collection.

	.Description
 	The Get-AMCollectionEventMap cmdlet gets event map object of the specified collection.
	
	.Parameter Id
	Specifies the ID of the collection.
	
	.Parameter Name
	Specifies the name of the collection.
	
	.Parameter Collection
	Specifies the collection object.
	
	.Example
	$EventMap = Get-AMCollectionEventMap -Name "MyCollection"
	This command returnes EventMap object of the "MyCollection" collection.
#>
function Get-AMCollectionEventMap
{
	[CmdletBinding(DefaultParameterSetName="CollectionName")]
	param
	(
		[parameter(ParameterSetName="CollectionId",mandatory=$true,ValueFromPipeline=$false)]
		[Guid]
		$Id,
		
		[parameter(ParameterSetName="CollectionName",mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Name,
		
		[parameter(ParameterSetName="CollectionObject",mandatory=$true,ValueFromPipeline=$false)]
		[AutomationMachine.Data.Collection]
		$Collection
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		if ($PSCmdlet.ParameterSetName -eq "CollectionId") {
			$Collection = Get-AMCollection -Id $Id | Select-Object -First 1
			if ($Collection -eq $null) { throw "Collection with the specified ID not found: `"$Id`"." }
		}
		if ($PSCmdlet.ParameterSetName -eq "CollectionName") {
			$Collection = Get-AMCollection -Name $Name | Select-Object -First 1
			if ($Collection -eq $null) { throw "Collection with the specified name not found: `"$Name`"." }
		}
		if (($Collection.EventMapId -eq [Guid]::Empty) -and ($Collection.Parent -ne $null)) {
			return Get-AMCollectionEventMap -Collection $Collection.Parent
		}
		elseif (($Collection.EventMapId -eq [Guid]::Empty) -and ($Collection.Parent -eq $null)) {
			return $null
		}
		else {
			return $AMDataManager.Environment.EventMap | Where-Object { $_.Id -eq $Collection.EventMapId }
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the computers of the current environment.

	.Description
 	The Get-AMComputer cmdlet gets the computers of the current environment. You can filter the computers returned by ID and name.
	
	.Parameter Name
	Specifies the name of the computer.
	
	.Parameter Id
	Specifies the ID of the computer.
	
	.Example
	Get-AMComputer
	This command displays all computers of the current environment.
	
	.Example
	Get-AMComputer -Name "A*"
	This command displays computers with names that begin with the letter "A".
#>

function Get-AMComputer
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*"
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	$Result = $AMDatamanager.Environment.Computers | Where-Object {($_.name -like $Name) -and ($_.Id -like $Id)}
	if ($Result -eq $null) {
		$DomainName = Get-AMComputerDomain
		if (![string]::IsNullOrEmpty($DomainName)) {
			if ($Name.EndsWith(("." + $DomainName))) {
				# try to convert FQDN to short name and then get computer
				$regex = New-Object System.Text.RegularExpressions.Regex([System.Text.RegularExpressions.Regex]::Escape(("." + $DomainName)), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
				$ShortName = $regex.Replace($Name, "", 1)
				$Result = $AMDatamanager.Environment.Computers | Where-Object {($_.name -like $ShortName) -and ($_.Id -like $Id)}
			}
			if ($Result -eq $null) {
				# try to convert short name to FQDN and then get computer
				$Result = $AMDatamanager.Environment.Computers | Where-Object {($_.name -like ($Name + "." + $DomainName)) -and ($_.Id -like $Id)}
			}
		}
	}
	
	return $Result
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the configuration categories of the current environment.

	.Description
 	The Get-AMConfigurationCategory cmdlet gets the configuration categories of the current environment. You can filter the configuration categories returned by ID or name.
	
	.Parameter Id
	Specifies the ID of the variable.
	
	.Parameter Name
	Specifies the name of the configuration category.
	
	.Example
	Get-AMConfigurationCategory
	This command displays all configuration categories of the current environment.
	
	.Example
	Get-AMConfigurationCategory -Name "C*"
	This command displays configuration categories with names that begin with the letter "C".
#>
function Get-AMConfigurationCategory
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*"

	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
			
	$AMDataManager.Environment.ConfigurationCategories | Where-Object {($_.Id -like $Id) -and ($_.name -like $Name)}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the active drecrory's FQDN for the environment's current collection.

	.Description
	Gets configured FQDN. If the current collection's type is Golden Image the FQDN from the Hypervisor plugin will be returned.
    Otherwise the FQDN from the Active Directory plugin will be returned.
    
    .Parameter Collection
    Environment's collection. If the Collection parameter is not specified, the environment's current collection will be used.
	
	.Example
 	Get-AMDomain
	This will return the FQDN for the environment's current collection.
#>
function Get-AMDomain
{
    [CmdLetBinding()]
    param (
        [parameter(mandatory=$false,ValueFromPipeline=$false)]
        [AutomationMachine.Data.Collection] $Collection
    )

	[string] $fqdn = $null

	if ($Collection -eq $null) {
        $Collection = Get-AMCollection -Current
    }

	if ($Collection.EventMapId -eq [AM.Data.WellKnown.WellKnown]::EventMaps.GoldenImageEventMap.Id) {
		$hypervisorPlugin = [AM.Data.WellKnown.WellKnown]::Plugins.Hypervisor
		$fqdn = (Get-AMVariable -Id $hypervisorPlugin.AdDomainConfigVariable.Id -ParentId $hypervisorPlugin.Id -Collection $Collection).Value
	}
	else {
		$adPlugin = [AM.Data.WellKnown.WellKnown]::Plugins.ActiveDirectory
		$fqdn = (Get-AMVariable -Id $adPlugin.DomainFqdnVariable.Id -ParentId $adPlugin.Id -Collection $Collection).Value
	}

	return $fqdn
}
<#
	.Synopsis
	Gets event maps of the current environment.

	.Description
 	The Get-AMEventMap gets event maps of the current environment. You can filter the event maps returned by ID or name.
	
	.Parameter Id
	Specifies ID of the event map.
	
	.Parameter Name
	Specifies name of the event map.
	
	.Parameter Current
	The event map of the current computer's collection will be returned. If the collection and its parent collections have no event map configured, exception will be thrown.
  	 
 	.Example
 	Get-AMEventMap -Name "S*"
	This command returns all event maps with names that begin with the letter "S".
	
	.Example
	Get-AMEventMap -Current
	This command returns the event map of the current computer's collection.
#>
function Get-AMEventMap
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*",
	
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",

		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch] $Current
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		If ($Current)
		{
			Write-Verbose "Current computer name: $($Env:COMPUTERNAME)"
			
			$Collection = Get-AMCollection -Current
			if ($Collection -eq $null) {
				throw "Current computer doesn't belong to any collection."
			}
			Write-Verbose "Computer's collection: $Collection"
			$EventMap = Get-AMCollectionEventMap -Collection $Collection
			if ($EventMap -eq $null) {
				throw "No event map has been configured for the collection and its parents."
			}
			Write-Verbose "Collection's event map: $($EventMap.Name)"
			$EventMap
		}
		Else
		{
			$AMDataManager.Environment.EventMap | Where-Object { ($_.Id -like $Id) -and ($_.name -like $Name) }
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the path of imported file.

	.Description
 	Gets the path of imported file, if it's a legacy type file (e.g. filename.ext.guid), it will copy the file to temp and strip it of the guid extension.

	.Parameter Id
	Specifies the ID of the imported file.

	.Parameter Variable
	Specifies an variable object.

	.Example
	$Pkg = Get-AMPackage -Name examplePkg
	Read-AMPrivateVariables $Pkg
	$Variable = Get-AMVariable -Component $pkg -Name "ImportedFile"
	Get-AMImportedFilePath -Variable $Variable
#>
function Get-AMImportedFilePath {
    [CmdletBinding(DefaultParameterSetName = "Object")]
    param
    (
        [parameter(mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "Object", Position = 0)]
        [AutomationMachine.Data.IVariable]
        $Variable
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    $Path = $AMEnvironment.GetImportedFileOrFolderPath($Variable)

    if ([string]::IsNullOrEmpty($Path)) { return $null }
    $Random = Get-Random
    if (-not (Test-Path "$($env:temp)\$($Random)")) { [void] (New-Item -Path "$($env:temp)\$($Random)" -Force -ItemType Directory) }

    if ([System.IO.Path]::GetExtension($Path).TrimStart(".") -eq $Variable.Value.Id.ToString()) {
        # Legacy imported file, copy it to temp, strip guid extension and return path in temp
        $Destination = Join-Path "$($env:temp)\$($Random)" ([System.IO.Path]::GetFileNameWithoutExtension($Path)).ToString()
        Copy-Item -Path $Path -Destination $Destination -Force
        return $Destination
    }
    else {
        # New imported file, copy it to temp, remove guid part and rteurn path in temp
        $DestinationFileName = [System.IO.Path]::GetFileName($Path.Replace(".$($Variable.Value.Id.ToString())", ""))
        $Destination = Join-Path "$($env:temp)\$($Random)" $DestinationFileName
        Copy-Item -Path $Path -Destination $Destination -Force
        return $Destination
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the path of imported media.

	.Description
 	Gets the path of imported media.
	
	.Parameter Id
	Specifies the ID of the imported media.
	
	.Example
	Get-AMImportedMediaPath -Id "2f7e40a5-f461-47a1-8adf-8ba07704991b"
#>
function Get-AMImportedMediaPath
{
	[cmdLetbinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[System.Guid]
		$Id
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

	$AMDataManager.MediaPathResolver.GetImportedMediaDirectoryPath($Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the layers of the current environment.

	.Description
 	The Get-AMLayer cmdlet gets the layers of the current environment. You can filter the layers returned by ID, name or parent.
	
	.Parameter Name
	Specifies the name of the layer.
	
	.Parameter Id
	Specifies the ID of the layer.
	
	.Example
	Get-AMLayer
	This command displays all layers of the current environment.
	
	.Example
	Get-AMLayer -Name "A*"
	This command displays layers with names that begin with the letter "A".
#>
function Get-AMLayer
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*"
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	
	$AMDataManager.Environment.Layers | Where-Object {($_.name -like $Name) -and ($_.Id -like $Id)}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets logon mode of the current computer.

	.Description
 	Gets logon mode of the current computer. Return Enabled,Disabled,Drain or DrainUntilRestart	
	
 	.Example
 	Get-AMLogonMode
#>
function Get-AMLogonMode
{
	[CmdletBinding()]
	param 
	(
	
	)

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


 
		$Mode = $null
		
		$logons = Get-WmiObject -ns "root\cimv2\terminalservices" -class "win32_terminalservicesetting"
		if (($logons.logons -eq 0) -and ($logons.sessionbrokerdrainmode -eq 0)) 
		{
			$Mode = "Enabled"			
		}
		elseif (($logons.logons -eq 1)) 
		{
			$Mode = "Disabled"			
		}
		elseif (($logons.logons -eq 0) -and ($logons.sessionbrokerdrainmode -eq 2)) 
		{
			$Mode = "Drain"
		}
		elseif (($logons.logons -eq 0) -and ($logons.sessionbrokerdrainmode -eq 1)) 
		{
			$Mode = "DrainUntilRestart"
		}
		
		
		Return $Mode


    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Gets media from AM.

	.Description
 	Gets the media from the current AM installation, media is shared across environments.
	
	.Parameter Id
	Specifies the ID of the media to get.
	
	.Parameter Vendor
	Specifies the vendor of the media to get.
	
	.Parameter Software
	Specifies the name of the media to get.
	
	.Parameter Version
	Specifies the version of the media to get.
	
	.Parameter Language
	Specifies the language of the media to get
	
	.Example
	Get-AMMedia 
	This command displays all media.
	
	.Example
	Get-AMMedia -Vendor "M*"
	This command displays media from all vendor that start with "M".
#>
function Get-AMMedia
{
	param
	(
		[cmdLetbinding()]
		
		[parameter(ParameterSetName="Id",mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Id = "*",
		
		[parameter(ParameterSetName="Named",mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Vendor = "*",
		
		[parameter(ParameterSetName="Named",mandatory=$false,ValueFromPipeline=$false,Position=1)]
		[string]
		$Software = "*",
		
		[parameter(ParameterSetName="Named",mandatory=$false,ValueFromPipeline=$false,Position=2)]
		[string]
		$Version = "*",
		
		[parameter(ParameterSetName="Named",mandatory=$false,ValueFromPipeline=$false,Position=3)]
		[string]
		$Language = "*"
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
	If ($PSCmdlet.ParameterSetName -eq "Named")
	{
	
		return ($AMDataManager.ReadMedia() | Where-Object {($_.Vendor -like $Vendor) -and ($_.SoftwareName -like $Software) -and ($_.Version -like $Version) -and ($_.Language -like $Language)})
	}
	else
	{
		return ($AMDataManager.ReadMedia() | Where-Object {($_.Id -like $Id)})
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the packages of the current environment.

	.Description
 	The Get-AMPackage cmdlet gets the packages of the current environment. You can filter the packages returned by ID, name or category.
	
	.Parameter Name
	Specifies the name of the package.
	
	.Parameter Id
	Specifies the ID of the variable.
	
	.Parameter Category
	Gets only the packages which belongs to the specified category.
	
	.Example
	Get-AMPackage
	This command displays all packages of the current environment.
	
	.Example
	Get-AMPackage -Name "A*"
	This command displays packages with names that begin with the letter "A".
#>
function Get-AMPackage
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Category = "*"
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	
	$AMDataManager.Environment.Packages | Where-Object {($_.name -like $Name) -and ($_.Id -like $Id) -and ($_.PackageCategory -like $Category)}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the package categories of the current environment.

	.Description
 	The Get-AMPackageCategory cmdlet gets the package categories of the current environment. You can filter the package categories returned by ID, name or parent.
	
	.Parameter Id
	Specifies the ID of the variable.
	
	.Parameter Name
	Specifies the name of the package category.
	
	.Parameter ParentId
	Specifies the Parent ID of the package category.
	
	.Parameter ParentName
	Specifies the Parent name of the package category.
	
	.Example
	Get-AMPackageCategory
	This command displays all package categories of the current environment.
	
	.Example
	Get-AMPackageCategory -Name "A*"
	This command displays package categories with names that begin with the letter "A".
#>
function Get-AMPackageCategory
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$ParentId = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$ParentName = "*"

	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	
	$AMDataManager.Environment.PackageCategories | Where-Object {($_.Id -like $Id) -and ($_.name -like $Name) -and ($_.ParentId -like $ParentId) -and ($_.Parent -like $ParentName)}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the plugins of the current environment.

	.Description
 	The Get-AMPlugin cmdlet gets the plugins of the current environment. You can filter the plugins returned by ID or name.
	
	.Parameter Name
	Specifies the name of the plugin.
	
	.Parameter Id
	Specifies the ID of the plugin.
	
	.Parameter EventMapId
	Specifies the ID of the event map.
	
	.Parameter EventMapName
	Specifies the name of the event map.
	
	.Parameter EventMap
	Specifies the event map object.
	
	.Parameter EventId
	Specifies the ID of the event.
	
	.Parameter EventName
	Specifies the name of the event.
	
	.Parameter Event
	Specifies the event object.
	
	
	.Example
	Get-AMPlugin
	This command displays all plugins of the current environment.
	
	.Example
	Get-AMPlugin -Name "A*"
	This command displays plugins with names that begin with the letter "A".
	
	.Example
	Get-AMPlugin -EventMapName "SBC" -EventName "Startup"
	This command gets all plugins of "SBC" event map's "Startup" event.
#>
function Get-AMPlugin
{
	[cmdLetbinding(DefaultParameterSetName="Default")]
	param
	(	
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventId",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventName",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventObject",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventId",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventName",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventObject",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventId",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventName",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventObject",mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*",
		
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventId",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventName",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventObject",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventId",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventName",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventObject",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventId",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventName",mandatory=$false,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventObject",mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[parameter(ParameterSetName="EventMapIdAndEventId",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventName",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapIdAndEventObject",mandatory=$true,ValueFromPipeline=$false)]
		[Guid]
		$EventMapId,
		
		[parameter(ParameterSetName="EventMapNameAndEventId",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventName",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventObject",mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$EventMapName = "*",
		
		[parameter(ParameterSetName="EventMapObjectAndEventId",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventName",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventObject",mandatory=$true,ValueFromPipeline=$false)]
		[AutomationMachine.Data.EventMap]
		$EventMap,
		
		[parameter(ParameterSetName="EventMapIdAndEventId",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventId",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventId",mandatory=$true,ValueFromPipeline=$false)]
		[Guid]
		$EventId,
		
		
		[parameter(ParameterSetName="EventMapIdAndEventName",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventName",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventName",mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$EventName,
		
		[parameter(ParameterSetName="EventMapIdAndEventObject",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapNameAndEventObject",mandatory=$true,ValueFromPipeline=$false)]
		[parameter(ParameterSetName="EventMapObjectAndEventObject",mandatory=$true,ValueFromPipeline=$false)]
		[AutomationMachine.Data.Event]
		$Event
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		if ($PSCmdlet.ParameterSetName -eq "Default") {
			return $AMDataManager.Environment.Plugins | Where-Object {($_.Name -like $Name) -and ($_.Id -like $Id)}
		}
			
		#region Parameter check
		if (($PSCmdlet.ParameterSetName -eq "EventMapIdAndEventId") -or
			($PSCmdlet.ParameterSetName -eq "EventMapIdAndEventName") -or
			($PSCmdlet.ParameterSetName -eq "EventMapIdAndEventObject")) {
			$EventMap = Get-AMEventMap -Id $EventMapId | Select-Object -First 1
			if ($EventMap -eq $null) {
				Write-Warning "Event map with the specified ID not found: `"$EventMapId`"."
				return $null
			}
		}
		if (($PSCmdlet.ParameterSetName -eq "EventMapNameAndEventId") -or
			($PSCmdlet.ParameterSetName -eq "EventMapNameAndEventName") -or
			($PSCmdlet.ParameterSetName -eq "EventMapNameAndEventObject")) {
			$EventMap = Get-AMEventMap -Name $EventMapName | Select-Object -First 1
			if ($EventMap -eq $null) {
				Write-Warning "Event map with the specified name not found: `"$EventMapName`"."
				return $null
			}
		}
		if (($PSCmdlet.ParameterSetName -eq "EventMapIdAndEventId") -or
			($PSCmdlet.ParameterSetName -eq "EventMapNameAndEventId") -or
			($PSCmdlet.ParameterSetName -eq "EventMapObjectAndEventId")) {
			$Event = $AMDataManager.Environment.Events | Where-Object { $_.Id -eq $EventId } | Select-Object -First 1
			if ($Event -eq $null) {
				Write-Warning "Event with the specified ID not found: `"$EventId`"."
				return $null
			}
		}
		if (($PSCmdlet.ParameterSetName -eq "EventMapIdAndEventName") -or
			($PSCmdlet.ParameterSetName -eq "EventMapNameAndEventName") -or
			($PSCmdlet.ParameterSetName -eq "EventMapObjectAndEventName")) {
			$Event = $AMDataManager.Environment.Events | Where-Object { $_.Name -eq $EventName } | Select-Object -First 1
			if ($Event -eq $null) {
				Write-Warning "Event with the specified name not found: `"$EventName`"."
				return $null
			}
		}
		#endregion
	    
        if ($EventMap.Events[$Event.Id] -is [object]) # this if statement is needed. If the eventmap doesn't contain an entry for the event specified in $Event.Id it will fail!
        { 
		    $PluginIDs = $EventMap.Events[$Event.Id].Plugins
		    [AutomationMachine.Data.Plugin[]] $Plugins = @()
		    foreach ($P in $PluginIDs) {
			    $Plugin = Get-AMPlugin -Id $P | Select-Object -First 1
			    if ($Plugin) 
                {
				    $Plugins += $Plugin
			    }
			    else {
				    Write-Warning "Plugin `"$($P)`" that is specified in `"$($EventMap.Name)`" event map's event `"$($Event.Name)`" doesn't exist."
			    }
		    }
		    return $Plugins | Where-Object {($_.Name -like $Name) -and ($_.Id -like $Id)}
        }
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the active drecrory's OU for the environment's collection.

	.Description
	Gets configured organziation unit. If the collection's type is Golden Image the organizational unit from the System Configuration plugin will be returned.
	Otherwise the organizational unit from the Active Directory plugin will be returned.
    
    .Parameter Collection
    Environment's collection. If the Collection parameter is not specified, the environment's current collection will be used.
    
	.Example
 	Get-AMRootOU
	This will return the configured organizational unit for the environment's current collection.
#>
function Get-AMRootOU
{
    [CmdLetBinding()]
    param (
        [parameter(mandatory=$false,ValueFromPipeline=$false)]
        [AutomationMachine.Data.Collection] $Collection
    )

	[string] $rootOu = $null

    if ($null -eq $Collection) {
        $Collection = Get-AMCollection -Current
    }

	$adPlugin = [AM.Data.WellKnown.WellKnown]::Plugins.ActiveDirectory
	$rootOu = (Get-AMVariable -Id $adPlugin.RootOuVariable.Id -ParentId $adPlugin.Id -Collection $Collection).Value

	return $rootOu
}
<#
	.Synopsis
	Gets the service account configured for the environment's current collection.

	.Description
	Gets the service account credentials. If the current collection's type is Golden Image the service account from the Hypervisor plugin will be returned.
	Otherwise the service account from the Active Directory plugin will be returned.

	.Parameter Collection
	Environment's collection. If the Collection parameter is not specified, the environment's current collection will be used.
	
	.Example
 	Get-AMServiceAccount
	This will return the credentials object for the environment's current collection.
#>
function Get-AMServiceAccount
{
	[CmdLetBinding()]
    param (
        [parameter(mandatory=$false,ValueFromPipeline=$false)]
        [AutomationMachine.Data.Collection] $Collection
    )

	[AutomationMachine.Data.Types.Credentials] $svcAccVariable = $null

	if ($Collection -eq $null) {
        $Collection = Get-AMCollection -Current
    }

	if ($Collection.EventMapId -eq [AM.Data.WellKnown.WellKnown]::EventMaps.GoldenImageEventMap.Id) {
		$hypervisorPlugin = [AM.Data.WellKnown.WellKnown]::Plugins.Hypervisor
		$svcAccVariable = (Get-AMVariable -Id $hypervisorPlugin.AdCredentialsConfigVariable.Id -ParentId $hypervisorPlugin.Id -Collection $Collection).Value
	}
	else {
		$adPlugin = [AM.Data.WellKnown.WellKnown]::Plugins.ActiveDirectory
		$svcAccVariable = (Get-AMVariable -Id $adPlugin.ServiceAccountVariable.Id -ParentId $adPlugin.Id -Collection $Collection).Value
	}

	return $svcAccVariable
}
<#
	.Synopsis
	Creates AmFileService's proxy.

	.Description
 	Creates AmFileService's proxy.

	.Example
	$proxy = Get-AMSFileServiceProxy
#>
function Get-AMSFileServiceProxy
{
	[CmdletBinding()]
	Param
	(
		
	)

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


	$proxy = [AutomationMachine.Utilities.Services]::GetAmFileServiceProxy()

	return $proxy

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the user targeted layers of the current environment.

	.Description
 	The Get-AMUserTargetedLayer cmdlet gets the user targeted layers(UTL) of the current environment. You can filter the UTLs returned by ID or name.
	
	.Parameter Name
	Specifies the name of the user targeted layer.
	
	.Parameter Id
	Specifies the ID of the user targeted layer.
	
	.Example
	Get-AMUserTargetedLayer
	This command displays all user targeted layers of the current environment.
	
	.Example
	Get-AMUserTargetedLayer -Name "A*"
	This command displays user targeted layers with names that begin with the letter "A".
#>
function Get-AMUserTargetedLayer
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Name = "*",
		
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Id = "*"
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	
	$AMDataManager.Environment.UserTargetedLayers | Where-Object {($_.name -like $Name) -and ($_.Id -like $Id)}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets the Automation Machine variables.

	.Description
 	Gets the Automation Machine variables. You can get overridden variables if you specify collection, computer, component (package or plugin) objects or their IDs depending on scope for which you want to get variables. You can filter the variables returned by ID, parant ID, name or type.
  
	.Parameter Id
	Specifies the ID of the variable.
	
	.Parameter ParentId
	Specifies the parent ID of the variable.
	
	.Parameter Name
	Specifies the name of the variable.
	
	.Parameter Type
	Specifies the data type of the variable.
	
	.Parameter Collection
	If a collection specified then overidden variables of it will be used to replace global variables.
	
	.Parameter Computer
	If a computer specified then overidden variables of it will be used to replace global variables.
	
	.Parameter Component
	If a component (package or plugin) specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ActionItem
	If an action item specified then overidden variables of it will be used to replace global variables.
	
	.Parameter CollectionId
	ID of a collection. If a collection specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ComputerId
	ID of a computer. If a computer specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ComponentId
	ID of a component (package or plugin). If a component specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ActionSetId
	ID of an action set to which action item belongs.
	
	.Parameter ActionItemId
	ID of an action item. If an action item specified then overidden variables of it will be used to replace global variables.
		 
 	.Example
	Get-AMVariable
	This command gets all public variables of the current environment.
	
	.Example
	Get-AMVariable -CollectionId "019cd113-456b-42f2-bb76-a28d040b0c18" -ComputerId "92c58e1f-23b5-471e-a980-460c5ac95b9f" -ComponentId "ca5e4850-9cc5-4edd-bcdf-23671c71dfea"
	
	
	.Example
	$Component = Get-AMPackage -Name "Adobe Reader X"
	C:\PS>Get-AMVariable -Component $Component
#>
function Get-AMVariable
{
	[CmdletBinding(DefaultParameterSetName="Default")]
	param 
	(	
		<#
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Scope")]
		[AutomationMachine.Data.Scope]
		$Scope,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Scope")]
		[System.Guid]
		$ScopeElementId,
		#>
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.Collection]
		$Collection = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.Computer]
		$Computer = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.Component]
		$Component = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.ActionItem]
		$ActionItem = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$CollectionId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ComputerId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ComponentId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ActionSetId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ActionItemId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Default")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[string]
		$Id = "*",
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Default")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[string]
		$ParentId = "*",
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Default")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[string]
		$Name = "*",
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Default")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[string]
		$Type = "*"
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		switch ($PSCmdlet.ParameterSetName) {
			"Element" {
				if (($Component -ne $null) -and (($Component.PrivateVariables -eq $null) -or ($Component.PrivateVariables.Count -eq 0))) {
					Read-AMPrivateVariables -Component $Component
				}
				If ($Collection -eq $null) {$CollectionId = [guid]::Empty} else {$CollectionId = $Collection.Id}
				if ($Computer -eq $null) {$ComputerId = [guid]::Empty} else {$ComputerId = $Computer.Id}
				If ($Component -eq $null) {$ComponentId = [guid]::Empty} else {$ComponentID = $Component.Id}
				if ($ActionItem -eq $null) 
				{	
					$ActionSetId = [guid]::Empty
					$ActionItemId = [guid]::Empty
				}
				else
				{
					$ActionSetId = $ActionItem.ActionSetId
					$ActionItemId = $ActionItem.Id
				}
			
				$Variables = $AMDataManager.Environment.GetVariables($CollectionId, $ComputerId, $ComponentId, $ActionSetId, $ActionItemId) | Where-Object {($_.Id -like $Id) -and ($_.Name -like $Name) -and ($_.ParentId -like $ParentId) -and ($_.Type -like $Type)}
			}
			"ElementId" {
				if (($ActionItemId -ne [Guid]::Empty) -and ($ActionSetId -eq [Guid]::Empty)) {
					Write-Warning "Action Set ID is not specified for Action Item ID"
				}
				if ($ComponentId -ne [Guid]::Empty) {
					$Component = $AMDataManager.Environment.GetComponent($ComponentId)
					if (($Component -ne $null) -and (($Component.PrivateVariables -eq $null) -or ($Component.PrivateVariables.Count -eq 0))) {
						Read-AMPrivateVariables -Component $Component
					}
				}
				$Variables = $AMDataManager.Environment.GetVariables($CollectionId, $ComputerId, $ComponentId, $ActionSetId, $ActionItemId) | Where-Object {($_.Id -like $Id) -and ($_.Name -like $Name) -and ($_.ParentId -like $ParentId) -and ($_.Type -like $Type)}
			}
			"Default" {
				$Variables = $AMDataManager.Environment.Variables | Where-Object {($_.Id -like $Id) -and ($_.Name -like $Name) -and ($_.ParentId -like $ParentId) -and ($_.Type -like $Type)}
			}
		}
		if ((Test-Path "Function:\Resolve-AMVariableFilter") -and ($Variables -ne $null)) {
			$Variables | % { Resolve-AMVariableFilter -Variable $_ }
		}
		$Variables | % {Resolve-AMMediaPath -Variable $_}
		
		return $Variables

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
.SYNOPSIS
Installs AM Logshipping scheduled task.

.DESCRIPTION
Installs AM Logshipping scheduled task.

.EXAMPLE
Install-AMStartupTask
#>
function Install-AMLogshippingTask {
    $SchTaskName = "Automation Machine Logshipping"
    Write-Verbose "Scheduled task name: $SchTaskName"
    $SchTaskCommand = "Import-Module `'amclient`' -ArgumentList @(`'`',1);Copy-AMLogfiles;Invoke-AMMonitoringFramework"
    Write-Verbose "Scheduled task command:`n    $SchTaskCommand"

    # Get username and password from environment and use it for the scheduled task
    $ServiceAccount = Get-AMServiceAccount
    $SchTaskUserName = $ServiceAccount.UserName
    if ($SchTaskUserName.StartsWith(".\")) { $SchTaskUserName = $SchTaskUserName.Replace(".\", $env:COMPUTERNAME + "\") }
    $SchTaskPassword = $ServiceAccount.Password

    if ([string]::IsNullOrEmpty($SchTaskUserName)) { throw "Service account is not set for the environment" }

    $ScheduleService = New-Object -ComObject "Schedule.Service"
    $ScheduleService.Connect()
    $TaskFolder = $ScheduleService.GetFolder("\") # root folder
    $StartBoundary = $null
    Try {
        $TaskFolder = $TaskFolder.GetFolder("Automation Machine")
        try {
            $ExistingTask = $TaskFolder.GetTask($SchTaskName)
            $TaskXml = [xml] $ExistingTask.Xml
            $StartBoundary = $TaskXml.Task.Triggers.TimeTrigger.StartBoundary
          }
          catch {}
    }
    Catch {
        $TaskFolder = $TaskFolder.CreateFolder("Automation Machine")
    }
    Try {
        $TaskFolder.DeleteTask($SchTaskName, 0)
    }
    Catch {

    }

    $AMLogTask = $ScheduleService.NewTask(0)
    $AMLogTask.Settings.RunOnlyIfIdle = $false
    $AMLogTask.Settings.IdleSettings.StopOnIdleEnd = $false
    $AMLogTask.Settings.DisallowStartIfOnBatteries = $false
    $AMLogTask.Settings.StopIfGoingOnBatteries = $false
    $AMLogTask.Settings.AllowDemandStart = $true
    $AMLogTask.Settings.Enabled = $true
    $AMLogTask.Settings.Priority = 6
    $AMLogTask.Principal.RunLevel = 1
    $RegInfo = $AMLogTask.RegistrationInfo
    $RegInfo.Author = "Login AM"
    $RegInfo.Description = "Automation Machine logshipping task"
    $Triggers = $AMLogTask.Triggers
    $Trigger = $Triggers.Create(1) # time trigger
    $Trigger.Repetition.Interval = "PT5M" # Repeat every 5 minutes
    if ([string]::IsNullOrEmpty($StartBoundary)) {
        $Trigger.StartBoundary = [DateTime]::Now.AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ss")
    }
    else {
        $Trigger.StartBoundary = $StartBoundary
    }
    $Trigger.Repetition.Interval = "PT5M"
    $Action = $AMLogTask.Actions.Create(0)
    $Action.Path = "powershell.exe"
    $Action.Arguments = "-Command $SchTaskCommand"
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa381365%28v=vs.85%29.aspx
    $SchTasksOutput = $TaskFolder.RegisterTaskDefinition($SchTaskName, $AMLogTask, 6, $SchTaskUserName, $SchTaskPassword, 1)
    if ($SchTasksOutput.Xml) { Write-Verbose $SchTasksOutput.Xml }
}
<#
.SYNOPSIS
Installs AM Startup scheduled task.

.DESCRIPTION
Installs AM Startup scheduled task.

.EXAMPLE
Install-AMStartupTask
#>
function Install-AMStartupTask {
    $SchTaskName = "Automation Machine Startup"
    Write-Verbose "Scheduled task name: $SchTaskName"
    $SchTaskCommand = "Import-Module `'amclient`';Update-AMCache;Disable-AMSystemEventFlag;Invoke-AMEvent -Name `"Startup`""
    Write-Verbose "Scheduled task command:`n    $SchTaskCommand"

    # Get username and password from environment and use it for the scheduled task
    $ServiceAccount = Get-AMServiceAccount
    $SchTaskUserName = $ServiceAccount.UserName
    if ($SchTaskUserName.StartsWith(".\")) { $SchTaskUserName = $SchTaskUserName.Replace(".\", $env:COMPUTERNAME + "\") }
    $SchTaskPassword = $ServiceAccount.Password

    if ([string]::IsNullOrEmpty($SchTaskUserName)) { throw "Service account is not set for the environment" }
    $ScheduleService = New-Object -ComObject "Schedule.Service"
    $ScheduleService.Connect()
    $TaskFolder = $ScheduleService.GetFolder("\") # root folder
    try {
        $TaskFolder = $TaskFolder.GetFolder("Automation Machine")
    }
    catch {
        $TaskFolder = $TaskFolder.CreateFolder("Automation Machine")
    }
    try {
        $TaskFolder.DeleteTask($SchTaskName, 0)
    }
    catch {
    }

    $AMStartupTask = $ScheduleService.NewTask(0)
    $AMStartupTask.Principal.RunLevel = 1
    $AMStartupTask.Settings.RunOnlyIfIdle = $false
    $AMStartupTask.Settings.IdleSettings.StopOnIdleEnd = $false
    $AMStartupTask.Settings.DisallowStartIfOnBatteries = $false
    $AMStartupTask.Settings.StopIfGoingOnBatteries = $false
    $AMStartupTask.Settings.DisallowStartIfOnBatteries = $true
    $AMStartupTask.Settings.RunOnlyIfNetworkAvailable = $false
    $AMStartupTask.Settings.AllowDemandStart = $true
    $AMStartupTask.Settings.RestartInterval = "PT5M"
    $AMStartupTask.Settings.RestartCount = 3
    $AMStartupTask.Settings.StartWhenAvailable = $true
    $AMStartupTask.Settings.Enabled = $true
    $AMStartupTask.Settings.Priority = 3
    $RegInfo = $AMStartupTask.RegistrationInfo
    $RegInfo.Author = "Login AM"
    $RegInfo.Description = "Automation Machine Startup Task"
    $Triggers = $AMStartupTask.Triggers
    $Trigger = $Triggers.Create(8)
    $Trigger.Delay = "PT2M"
    $Action = $AMStartupTask.Actions.Create(0)
    $Action.Path = "powershell.exe"
    $Action.Arguments = "-Command $SchTaskCommand"
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa381365%28v=vs.85%29.aspx
    $SchTasksOutput = $TaskFolder.RegisterTaskDefinition($SchTaskName, $AMStartupTask, 6, $SchTaskUserName, $SchTaskPassword, 1)
    if ($SchTasksOutput.Xml) { Write-Verbose $SchTasksOutput.Xml }
}
<#
.SYNOPSIS
Installs AM User Count scheduled task.

.DESCRIPTION
Installs AM User Count (Automation Machine User Count) scheduled task.

.EXAMPLE
Install-AMUserUsageTask
#>
function Install-AMUserUsageTask {

    $AMCurrentUtilsFolder = Join-Path $AMLocalPath "\bin\utilities"

    Write-Verbose "Creating User Count scheduled task"
    $SchTaskName = "Automation Machine User Count"
    $AmTaskFolderName = "Automation Machine"
    Write-Verbose "Scheduled task name: $SchTaskName"
    $UserCounterPath = Join-Path $AMCurrentUtilsFolder "\AMUsageReporter.exe"
    $SchTaskCommand = $UserCounterPath
    Write-Verbose "Scheduled task command:`n    $SchTaskCommand"

    # Get username and password from AD plugin and use it for the scheduled task
    $ServiceAccount = Get-AMServiceAccount
    $SchTaskUserName = $ServiceAccount.UserName
    if ($SchTaskUserName.StartsWith(".\")) { $SchTaskUserName = $SchTaskUserName.Replace(".\", $env:COMPUTERNAME + "\") }
    $SchTaskPassword = $ServiceAccount.Password

    if ([string]::IsNullOrEmpty($SchTaskUserName)) { throw "Service account is not set for the environment" }

    $TaskFolder = Get-AMScheduledTaskFolder -Path $AmTaskFolderName
    $StartBoundary = $null
    if ($null -eq $TaskFolder) {
        $TaskFolder = $TaskFolder.CreateFolder($AmTaskFolderName)
    }
    try {
        $ExistingTask = $TaskFolder.GetTask($SchTaskName)
        $TaskXml = [xml] $ExistingTask.Xml
        $StartBoundary = $TaskXml.Task.Triggers.TimeTrigger.StartBoundary
    }
    catch {}

    $ScheduleService = New-Object -ComObject "Schedule.Service"
    $ScheduleService.Connect()

    $AMTask = $ScheduleService.NewTask(0)
    $AMTask.Settings.RunOnlyIfIdle = $false
    $AMTask.Settings.IdleSettings.StopOnIdleEnd = $false
    $AMTask.Settings.DisallowStartIfOnBatteries = $false
    $AMTask.Settings.StopIfGoingOnBatteries = $false
    $AMTask.Settings.AllowDemandStart = $true
    $AMTask.Settings.Enabled = $AMEnvironment.IsReportingEnabled
    $AMTask.Settings.Priority = 6
    $AMTask.Principal.RunLevel = 1
    $RegInfo = $AMTask.RegistrationInfo
    $RegInfo.Author = "Login AM"
    $RegInfo.Description = "Login AM User Count task"
    $Triggers = $AMTask.Triggers
    $Trigger = $Triggers.Create(1) # time trigger
    if ([string]::IsNullOrEmpty($StartBoundary)) {
        $Trigger.StartBoundary = [DateTime]::Now.AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ss")
    }
    else {
        $Trigger.StartBoundary = $StartBoundary
    }
    $Trigger.Repetition.Interval = "PT1H" # Repeat every 1 hour
    $Action = $AMTask.Actions.Create(0)
    $Action.Path = $UserCounterPath
    $SchTasksOutput = $TaskFolder.RegisterTaskDefinition($SchTaskName, $AMTask, 6, $SchTaskUserName, $SchTaskPassword, 1)
    if ($SchTasksOutput.Xml) { Write-Verbose $SchTasksOutput.Xml }
}

<#
    .Synopsis
    Reboots the machine if needed.

    .Description
	Reboots the machine if needed. Takes in account RebootPreference setting.

	.PARAMETER Info
	Invocation info.

    .Example
    Invoke-AMReboot -Info $MyInvocation
#>
function Invoke-AMReboot {
	[CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [System.Management.Automation.InvocationInfo] $Info
	)

    if ($AMDataManager.RebootNeeded -eq $true) {
        if ($AMDataManager.RebootPreference -eq [AutomationMachine.Data.RebootPreference]::Reboot) {
            # Call the shutdown event, (we can configure what shutdown event does per eventmap, in case of SBC, update the cache and restart the computer
			$AMDataManager.RebootNeeded = $false

            $global:am_rebooting = $true
            $global:am_aborting = $true
        }
        if ($AMDataManager.RebootPreference -eq [AutomationMachine.Data.RebootPreference]::Continue) {
            Write-AMInfo "A reboot was needed, but RebootPreference is set to continue, ignoring reboot"
            $AMDataManager.RebootNeeded = $false
            $global:am_aborting = $false
        }
        elseif ($AMDataManager.RebootPreference -eq [AutomationMachine.Data.RebootPreference]::Ask) {
            if (-not ($global:am_aborting)) {
                # prevents from showing the confirmation message several times in a row
                $IsElevated = $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
                if (-not $IsElevated) {
                    throw "Process is not running elevated, unable to set reboot flag"
                }
                $hkcuRoot = [string]::Format("HKLM:\{0}", [AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT_WITHOUT_HIVE)
                Set-ItemProperty -Path $hkcuRoot -Name $([AutomationMachine.Data.DataFilePath]::REGISTRY_VALUE_IS_REBOOT_NEEDED) -Value "True"
                $UserResponse = [AutomationMachine.Utilities.Windows.TerminalServices.WtsMessageBox]::SendConfirmation("One or more packages require this computer to be restarted, would you like to restart now?", "Login AM")
                if ($UserResponse -eq "Yes") {
                    $global:am_rebooting = $true
                    $global:am_aborting = $true
                    Restart-AMComputer -ShutdownTimer 0
                }
                else {
                    $global:am_rebooting = $false
                    $global:am_aborting = $true
                }
            }
        }
    }

    if ($PSBoundParameters['Verbose']) {
        Write-Verbose "$([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")): #### Exit $($Info.MyCommand) ####"
        Write-Verbose "$([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")): Completed commandline: $($Info.Line)"
    }
    if ($PSBoundParameters['Debug']) { $DebugPreference = "Continue"; Write-Debug "Dumping variables to screen"; Get-Variable }
}
<#
	.Synopsis
	Reads a list of action items.

	.Description
 	Reads a list of action items for the specified component.
	
	.Parameter Component
	A component which action items will be readen.
	
 	.Example
	$component = Get-AMPackage -Name "Adobe Reader X"
 	C:\PS>Read-AMActionItems -Component $component
	C:\PS>$component.ActionSets[0].ActionItems
#>
function Read-AMActionItems
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

	$AMDataManager.ReadActionItems($Component.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Reads status of the specified computer.

	.Description
 	Reads status of the specified computer from the Automation Machine file share.
	
	.Parameter Computer
	The computer which status will be read.
	
 	.Example
 	$pc = $AMEnvironment.Computers | Where-Object { $_.Name -eq "AT-SRV005" }
	$status = Read-AMComputerStatus -Computer $pc
#>
function Read-AMComputerStatus
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Computer]
		$Computer
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

	return $AMDataManager.ReadComputerStatus($Computer.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Reads environment's data from the share.

	.Description
 	Reads environment from Automation Machine file share.

 	.Example
 	Read-AMEnvironment
#>
function Read-AMEnvironment {
    [CmdletBinding()]
    param
    (
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    Set-Variable -Name AMEnvironment -Value $AMDataManager.Environment -Scope "Global"
    [void] $AMDataManager.ReadEnvironment($AMEnvironment.Id, $true)

    if ($am_module -eq "client") {
        $AMEnvironment.ServiceAccount = $null
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Reads a list of global variables.

	.Description
 	Reads a list of global variables of the specified environment.
	 
 	.Example
 	Read-AMGlobalVariables
#>
function Read-AMGlobalVariables
{
	[CmdletBinding()]
	param 
	(
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

	$AMDataManager.ReadGlobalVariables()
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Reads a list of private variables.

	.Description
 	Reads a list of private variable for a specified component.
	
	.Parameter Component
	A component which private variables will be readen.
	
 	.Example
	$component = Get-AMPackage -Name "Adobe Reader X"
 	C:\PS>Read-AMPrivateVariables -Component $component
	C:\PS>$component.PrivateVariables
#>
function Read-AMPrivateVariables
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

	$AMDataManager.ReadPrivateVariables($Component.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Resolves a filterexpression

	.Description
	Resolves the filterexpression, expands environmentvariables in the filterexpression if there are any.

	.Parameter Expression
 	The filterexpression to resolve.

 	.Example
 	"OSArch='x64'" | Resolve-AMFilterExpression

 	.Example
 	Resolve-AMFilterExpression -Expression "OSArch='x64'"

	.Example
	Resolve-AMFilterExpressoin "OSArch='x64'"
#>
function Resolve-AMFilterExpression {
    param (
        [CmdletBinding()]
        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 0)]
        [string]
        $Expression
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    if (!(Test-Path variable:RegExFilter)) { $RegExFilter = "[a-zA-Z0-9]+=`'*[a-zA-Z0-9 .()`$`*`?=,_`\-:`\+\\\[\]\{\}]+`'*" }
    if (!(Test-Path variable:FilterRegExObj)) { $FilterRegExObj = New-Object System.Text.RegularExpressions.Regex($RegExFilter) }

    switch ($Expression) {
        $null { return $false }
        ([System.DBNull]::Value) { return $false }
        " " { return $false }
        default {
            Write-Debug "Evaluating expresssion $($Expression)"
            $Expression = $Expression | Expand-AMEnvironmentVariables
            Write-Debug "Expression after variable expansion: $($Expression)"

            try {
                $FilterResult = Invoke-Expression $Expression
            }
            catch [System.Management.Automation.CommandNotFoundException] {
                foreach ($match in $FilterRegExObj.Matches($Expression)) {
                    $splitResult = $match.Value.Split('=', 2)
                    $command = "Test-AM$($splitResult[0])"
                    if (Test-Path function:\$($command)) {
                        $param = $splitResult[1].Trim().Trim("`'")
                        $Expression = $Expression.Replace($match.Value, "`$$(& $command $param)")
                    }
                    else {
                        $Expression = $Expression.Replace($match.Value, "`$$false")
                    }
                }
                $FilterResult = Invoke-Expression $Expression
            }

            Write-Debug "FilterResult was: $($FilterResult)"

            return $FilterResult
        }
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Resolves media path of file/folder type variables.

	.Description
 	The Resolve-AMMediaPath cmdlet resolves the media path for specified variable.
  	
	.Parameter Variable
	Variable for which media path needs to be resolved.
	
 	.Example
 	Resolve-AMMediaPath -Variable $Variable
#>
function Resolve-AMMediaPath
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.IVariable] $Variable
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
		If ($Variable.type -eq [AutomationMachine.Data.Types.File] -or $Variable.type -eq [AutomationMachine.Data.Types.Folder])
		{
			
			$Pkg = Get-AMPackage -Id $Variable.ParentId
			If ($Pkg -ne $null)
			{
				If ($Pkg.MediaRevision -ne $null)
				{
					If (-not [String]::IsNullOrEmpty($Variable.Value.Path))
					{
						# do a double expand to account for escaped variables (between < >) 
						$Path = $Variable.Value.Path | Expand-AMEnvironmentVariables | Expand-AMEnvironmentVariables
						If (-not ([System.IO.Path]::IsPathRooted($Path)))
						{
							$MediaPath = $AMDataManager.GetPackageMediaRevisionPath($pkg.MediaRevision).Replace($AMDataManager.AMFileShare,$env:am_files) | Expand-AMEnvironmentVariables
							$Variable.Value.Path = Join-Path $MediaPath $Path
						}	
					}
				}
			}
		}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Set a flag for the maintenance process.

	.Description
 	The Set-AMMaintenanceFlag cmdlet sets a flag for the maintenance process.

	.Parameter Flag
	The maintenace flag to set.

 	.Example
 	Set-AMMainteanceFlag -Flag cpu_started
#>
function Set-AMMaintenanceFlag {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string] $Flag
    )

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    # Set statuspath locations

    Set-AMMaintenanceStatusPathVariables

    if (!(test-path $am_maint_cpu_statuspath)) {
        [void] (New-Item -Type Directory -Path $am_maint_cpu_statuspath -Force)
    }
	
	Remove-AMMaintenanceStatuses -Flag $Flag

    Switch ($Flag) {
        "cpu_skipped" {
            Set-Content -Path "$($am_maint_cpu_statuspath)\Skipped" -Value (Get-Date) -Force
        }
        "cpu_started" {
            Set-Content -Path "$($am_maint_cpu_statuspath)\Started" -Value (Get-Date) -Force
        }
        "cpu_failed" {
            Set-Content -Path "$($am_maint_cpu_statuspath)\Failed" -Value (Get-Date) -Force
        }
        "cpu_ready" {
            Set-Content -Path "$($am_maint_cpu_statuspath)\Queued" -Value (Get-Date) -Force
        }
        "cpu_finished" {
            Set-Content -Path "$($am_maint_cpu_statuspath)\Finished" -Value (Get-Date) -Force
        }
        "cpu_excluded" {
            Set-Content -Path "$($am_maint_cpu_statuspath)\Excluded" -Value (Get-Date) -Force
        }
        "col_started" {
            Set-Content -Path "$($am_maint_col_statuspath)\Started" -Value (Get-Date) -Force
        }
        "col_failed" {
            Set-Content -Path "$($am_maint_col_statuspath)\Failed" -Value (Get-Date) -Force
        }
        "col_finished" {
            Set-Content -Path "$($am_maint_col_statuspath)\Finished" -Value (Get-Date) -Force
        }
    }

    if (-not (Test-AMMaintenanceFlag -Flag $Flag)) {
        $ComputerStatus = Get-AMMaintenanceStatus -Computer
        throw "Failed to set the flag [$Flag] for the maintenance process, the cpu status is $ComputerStatus"
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

function Start-AMSplashScreen {
	
	[CmdletBinding()]
	param(
		[string] $Text
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
	Stop-AMSplashScreen
	
	$userEnvironmentPluginId = $AmWellKnown::Plugins.UserEnvironment.Id
	$currentCollectionId = $(Get-AMCollection -Current).Id
	$splashScreenEnabledVariable = Get-AMVariable -Id $AmWellKnown::Plugins.UserEnvironment.EnableAmSplashScreenVariable.Id -ParentId $userEnvironmentPluginId -CollectionId $currentCollectionId
	$splashScreenEnabled = $true
	if ($null -ne $splashScreenEnabledVariable) {
		$splashScreenEnabled = [boolean] $splashScreenEnabledVariable.Value
	}
	
	if ($splashScreenEnabled -eq $true) {
		if ($null -eq (Get-Variable -Name am_splash_process_id -Scope Global -ErrorAction SilentlyContinue)) {
			$startInfo = New-Object System.Diagnostics.ProcessStartInfo
			$startInfo.FileName = "powershell.exe"
			$startInfo.Arguments = @("-WindowStyle Hidden", '-Command & {
			Import-Module AMClient -ArgumentList @($null, $true)
			$splashScreen = New-Object AutomationMachine.Utilities.Forms.SplashScreen' + "`n"
			'$splashScreen.LabelText = ' + "'$Text'`n"
			'$splashScreen.ShowDialog()
			}')
			$startInfo.WindowStyle = "Hidden"

			$process = New-Object System.Diagnostics.Process
			$process.StartInfo = $startInfo
			[void] $process.Start()
		
			Set-Variable -Name am_splash_process_id -Value $process.Id -Scope Global
		}
	}
	else{
		Write-AMInfo "AM splashscreen is not shown because it is disabled in User Environment plugin"
	}
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
function Stop-AMSplashScreen {
	
	[CmdletBinding()]
	param(
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
	if ((Get-Variable -Name am_splash_process_id -Scope Global -ErrorAction SilentlyContinue) -ne $null) {
		try {
			if (Get-Process -Id $am_splash_process_id){
				Stop-Process -Id $am_splash_process_id -Force				
			}
			Remove-Variable -Name am_splash_process_id -Scope Global			
		}
		catch{
			Write-AMWarning "There was a problem stopping AM Splash Screen"
		}
	}
	
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Tests if two folders are equal.

	.Description
 	Compares if two folders are equal. Returns 0 if the folders are equal.
	
	.Parameter Source
	A path to the source directory.
	
	.Parameter Destination
	A path to the destination directory.
  	 
 	.Example
 	Test-AMFolderChanges -Source C:\MyFolder -Destination D:\MyFolder
#>
function Test-AMFolderChanges
{
	[CmdletBinding()]
	param 
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$false)]
		[string] $Source,
		
		[parameter(Mandatory=$true,ValueFromPipeline=$false)]
		[string] $Destination
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
	If (-not (Test-Path $Source)){return 0}
		
	$RoboInfo = robocopy "$Source" "$Destination" /mir /l /njh /nfl /ndl | ? {$_.length -gt 0} | Select-Object -Last 6
	Write-Verbose "$RoboInfo"
	if ($LASTEXITCODE -ge 8) { throw "robocopy.exe command failed, exit code: $LASTEXITCODE" }
    [ref] $result = $null
	$DirInfo = $RoboInfo[1].Split($null) | ? {[int]::TryParse($_,$result)}
	$FileInfo = $RoboInfo[2].Split($null) | ? {[int]::TryParse($_,$result)}

	$DirsCopied = [int] $DirInfo[1] + $DirInfo[5]
	$FilesCopied = [int] $FileInfo[1] + $FileInfo[5]

	[int] $Changes = $DirsCopied + $FilesCopied
	return $Changes

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Tests a flag for the maintenance process.

	.Description
 	The Test-AMMaintenanceFlag cmdlet gets a flag for the maintenance process.
	
	.Parameter Flag
	The maintenance flag to test for.
	
	.Parameter Id
	The Id of the computer to test the maintenance flag for,
	
	.Parameter CollectionId
	The Id for the collection to test the maintenance flag for.
	
 	.Example
 	Test-AMMainteanceFlag -Flag cpu_started
#>
function Test-AMMaintenanceFlag {
	[CmdletBinding()]
	param 
	(
		[Parameter(Mandatory = $true)]
		[string] $Flag,
		[Parameter(Mandatory = $false)]
		[guid] $Id = $([guid]::Empty),
		[Parameter(Mandatory = $false)]
		[guid] $CollectionId = $([guid]::Empty)
	)

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	# Set statuspath locations
	Set-AMMaintenanceStatusPathVariables -CollectionId $CollectionId -ComputerId $Id
	

	Switch ($Flag) {
		
		"cpu_skipped" {
			return $(Test-Path "$($am_maint_cpu_statuspath)\Skipped")
		}
		"cpu_started" {
			return $(Test-Path "$($am_maint_cpu_statuspath)\Started")
		}
		"cpu_failed" {
			return $(Test-Path "$($am_maint_cpu_statuspath)\Failed")
		}
		"cpu_ready" {
			return $(Test-Path "$($am_maint_cpu_statuspath)\Queued")
		}
		"cpu_finished" {
			return $(Test-Path "$($am_maint_cpu_statuspath)\Finished")
		}
		"cpu_excluded" {
			return $(Test-Path "$($am_maint_cpu_statuspath)\Excluded")
		}
		"col_started" {
			return $(Test-Path "$($am_maint_col_statuspath)\Started")
		}
		"col_failed" {
			return $(Test-Path "$($am_maint_col_statuspath)\Failed")
		}
		"col_finished" {
			return $(Test-Path "$($am_maint_col_statuspath)\Finished")
		}
		
	}

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Updates the cache on the current machine.

	.Description
 	Updates the Automation Machine cache on the current machine.
	
	.Parameter Async
	Specifies if the update needs to be done asynchronous.
  	 
 	.Example
 	Update-AMCache
#>
function Update-AMCache {
	
	[CmdletBinding()]
    param 
    (
        [switch] $Async
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    if (Test-Path $am_files) { $am_offline = $false } else { $am_offline = $true }
	
    if ($am_offline -eq $false) {
        $retry = $true
        $maxcount = 10
        $count = 0
        while ($retry -eq $true) {
			$count++

            try {
                Write-AMInfo "Checking Cache"
                $AMCache = Join-Path $AMLocalPath "Cache"
                if (-not (Test-Path $AMCache)) {
                    [void] (New-Item -Path $AMCache -ItemType "Directory" -Force)
                }
                $AMCurrentEnvFolder = Join-Path $AMCache "CurrentCache\$($AMEnvironment.Id)"
                $AMCurrentEnvConfig = Join-Path $AMCurrentEnvFolder "config"
                #$AMCurrentAppStoreFolder = Join-Path $AMLocalPath "bin\appstore"
                #$AMCurrentUtilsFolder = Join-Path $AMLocalPath "bin\utilities"
				
                $AMCentralPathEnvFolder = Join-Path $AMCentralPath $AMEnvironment.Id
                $AMCentralPathEnvConfig = Join-Path $AMCentralPathEnvFolder "config"
                #$AMCentralPathAppStoreFolder = Join-Path $AMCentralPathEnvFolder "bin\appstore"
                #$AMCentralPathUtilsFolder = Join-Path $AMCentralPathEnvFolder "bin\utilities"
                #$AMCurrentPathClientModulesFolder = Join-Path $AMLocalPath "bin\modules\client"

                $CacheUpdate = $true
                #$UtilsUpdate = $false
                #$AppStoreUpdate = $false    

				
                #$CentralVersion = ([xml] (Get-content (Join-Path $AMCentralPathEnvConfig "Environment.xml"))).Environment.Version
                #$LocalVersion = $AMEnvironment.Version.ToString()
                #$StatusPath = Join-Path $([AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT).Replace("HKEY_LOCAL_MACHINE", "HKLM:") "Status"
                #$MaintenanceFlag = Get-ItemProperty -Path $StatusPath -Name "Maintenance" -ErrorAction SilentlyContinue
		
                if ((Test-AMFolderChanges -Source $AMCentralPathEnvConfig -Destination $AMCurrentEnvConfig) -eq 0) {
                    $CacheUpdate = $false
                }

                if (($CacheUpdate -eq $false) <#-and ($AppStoreUpdate -eq $false) -and ($UtilsUpdate -eq $false)#>) {
                    Write-AMInfo "Cache is up to date"
                }
		
                if ($CacheUpdate -eq $true) {
                    Write-AMInfo "Updating Cache"
                    $NewCacheFolder = Join-Path $AMCache $(New-AMRandomItemName -Path $AMCache)
                    $AMNewCacheEnvFolder = Join-Path $NewCacheFolder "$($AMEnvironment.Id)"
                    [void] (New-Item -Path $AMNewCacheEnvFolder -ItemType "Directory" -Force)
                    $StatusXmlContent = "<Cache><Status>{0}</Status></Cache>"
                    [xml] $StatusXml = [string]::Format($StatusXmlContent, "Updating")
                    $StatusXml.Save($(Join-Path $NewCacheFolder "status.xml"))
				
                    $SyncNeeded = $true
                    if (Test-Path $AMCurrentEnvFolder) {
                        Copy-Item -Path "$AMCurrentEnvFolder\*" -Destination $AMNewCacheEnvFolder -Recurse -Force -Include @("config")
                    }
                    else {
                        Copy-Item -Path "$AMCentralPathEnvFolder\*" -Destination $AMNewCacheEnvFolder -Recurse -Force -Include @("config")
                        $SyncNeeded = $false
                    }
                    if ($SyncNeeded) {
                        $AMNewCacheEnvConfig = Join-Path $AMNewCacheEnvFolder "config"
                        $robocopyOutput = robocopy.exe "$AMCentralPathEnvConfig" "$AMNewCacheEnvConfig" /MIR /R:0 /XD .svn /NP
                        Write-Verbose "$robocopyOutput"								
                        if ($LASTEXITCODE -ge 8) { throw "robocopy.exe command failed, exit code: $LASTEXITCODE" }
                    }
                    [xml] $StatusXml = [string]::Format($StatusXmlContent, "Updated")
                    $StatusXml.Save($(Join-Path $NewCacheFolder "status.xml"))
                }
                
                if (-not $Async) {

                    Update-AMCacheLink
                    #$global:AMEnvironment = $AMDataManager.ReadEnvironment($AMEnvironment.Id,$true)
                    #Set-AMCacheSecurity
                    Read-AMEnvironment

                }
                Set-AMClientUninstallData
                
                $retry = $false
            }
            catch {
                $retry = $true
                $Reason = $_
                Write-Verbose "Something went wrong during cache update, retrying cache update $($maxcount - $count) more times"
                Write-Verbose $_				          
                Write-Verbose "Sleeping for 10 seconds"                
                Start-Sleep -Seconds 10                            
            }

            if ($count -ge $maxcount) {                
                throw $Reason
            }

        }
    }
    else {
        Write-AMWarning "Unable to contact the central share, cannot update the cache"
    }
		
    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Updates the cache link to the most recent version of the cache.

	.Description
 	Switches to the most recent version of the Automation Machine cache.
  	 
 	.Example
 	Update-AMCacheLink
#>
function Update-AMCacheLink
{
	[CmdletBinding()]
	param 
	(
	)
		
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMCache = Join-Path $AMLocalPath "Cache"
		if (-not (Test-Path $AMCache)) { throw "Cache doesn't exist." }
		$SymLinkPath = Join-Path $AMCache "CurrentCache"
		$SymLinkExists = Test-Path $SymLinkPath
		if ($SymLinkExists) {
			$SymLinkCurrentTarget = Get-AMSymbolicLinkTarget -Path $SymLinkPath
			Write-Verbose "Current symlink path = $SymLinkCurrentTarget"
		}
		else {
			Write-Verbose "Symlink does not exit."
		}
			
		#region Find new cache folder
		[String[]] $excludes = @()
		$excludes += $(Split-Path -Path $SymLinkPath -Leaf)
		if ($SymLinkExists) {
			$excludes += $(Split-Path -Path $SymLinkCurrentTarget -Leaf)
		}
		$CacheFolders = Get-ChildItem -Path "$AMCache" -Exclude $excludes | Sort-Object { $_.LastWriteTime } -Descending
		$CacheFolderTable = @{}
		$NewCacheFolder = $null
		if ($CacheFolders -ne $null) { # this check is needed for PowerShell v2
			foreach ($f in $CacheFolders) {
				$statusXmlPath = Join-Path $f.FullName "status.xml"
				$status = $null
				if (Test-Path -Path $statusXmlPath -PathType Leaf) {
					try {
						$statusXml = [xml] (Get-Content -Path $statusXmlPath)
					}
					catch { $status = "Unknown" }
					if ($statusXml -ne $null) { $status = $statusXml.cache.status }
				}
				if (($NewCacheFolder -eq $null) -and ($status -eq "Updated")) 
				{
					$NewCacheFolder = $f.FullName
				}
				if ([string]::IsNullOrEmpty($status)) { $status = "Unknown" }
				$CacheFolderTable.Add($f.FullName, $status)
			}
		}
		#endregion
			
		if ([string]::IsNullOrEmpty($NewCacheFolder)) {
			Write-Verbose "Cache symlink is up to date."
		}
		else {
			#region Switch symlink to the new cache folder
			Write-Verbose "New cache folder found: `"$NewCacheFolder`"."
			if ($SymLinkExists) {
				Remove-AMSymbolicLink -Path $SymLinkPath
			}
			New-AMSymbolicLink -Link "$SymLinkPath" -Target "$NewCacheFolder" -Junction
			$StatusXmlContent = "<Cache><Status>{0}</Status></Cache>"
			[xml] $StatusXml = [string]::Format($StatusXmlContent, "Current")
			$StatusXml.Save($(Join-Path $NewCacheFolder "status.xml"))
			if ($SymLinkExists) {
				[xml] $StatusXml = [string]::Format($StatusXmlContent, "Old")
				$StatusXml.Save($(Join-Path $SymLinkCurrentTarget "status.xml"))
			}
			Write-Verbose "Cache symlink successfully changed to: `"$NewCacheFolder`"."
			#endregion
		}
			
		#region Delete non-relevant (old) cache folders
		try
		{
			if ($CacheFolders -ne $null) {
				$CacheFolders | Where-Object { ($_.FullName -ne "$NewCacheFolder") -and (($CacheFolderTable[$_.FullName] -ne "Updating") -and ($CacheFolderTable[$_.FullName] -ne "Unknown")) } | % {
					Remove-Item $_ -Recurse -Force
					Write-Verbose "Old cache folder removed: `"$($_.Name)`""
				}
			}
		}
		catch
		{
			Write-AMWarning "An error occured while trying to remove old cache folder, skipping removal of old cachefolder, will be automatically removed upon next cache update"
		}
		#endregion
			

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Displays error messages on screen and updates the dashboard.

	.Description
 	Displays error messages on screen and creates an error object in the centralshare that is read by the dashboard.
  
	.Parameter Error
 	The error message to process.

	.Example
	Write-AMError "Error Installing Adobe Reader X"
#>
function Write-AMError
{
[cmdletbinding()]
	Param
	(
		$Error
	)
	
	try 
	{
		If ($Error -is [System.Management.Automation.ErrorRecord])
		{
			$ErrorMessage = $($Error.Exception.GetBaseException().Message)
		}
		else
		{
			$ErrorMessage = $Error
		}

		Get-PSCallStack | % {Write-Verbose "Trace: $($_.Command)"}
		$UniversalTime  = $([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
		$Append = ""
		$Append += "`n`n"
        if (Test-Path Env:\am_pkg_name)
        {
            Write-Host "[" -ForegroundColor Red -NoNewline
            Write-Host "$($UniversalTime)" -NoNewline
            write-host "] PKG: $($env:am_pkg_name)" -ForegroundColor Red
			$Append += "PKG: $($env:am_pkg_name)"
			$Append += "`n"
			
        }

        if (Test-Path Env:\am_as_name)
        {
            Write-Host "[" -ForegroundColor Red -NoNewline
            Write-Host "$($UniversalTime)" -NoNewline
            write-host "] AS: $($env:am_as_name)" -ForegroundColor Red
			$Append += "AS: $($env:am_as_name)"
			$Append += "`n"
		}

        if (Test-Path Env:\am_ai_name)
        {
            Write-Host "[" -ForegroundColor Red -NoNewline
            Write-Host "$($UniversalTime)" -NoNewline
            write-host "] AI: $($env:am_ai_name)" -ForegroundColor Red
			$Append +=  "AI: $($env:am_ai_name)"
			$Append += "`n"
		}

		Write-Host "[" -ForegroundColor Red -NoNewline
		Write-Host "$($UniversalTime)" -NoNewline
		Write-Host "] ERROR: $($ErrorMessage)" -ForegroundColor Red
        
        
     

		If ($Error -is [System.Management.Automation.ErrorRecord])
		{
			$Append += "`n"
			$Append += "*** START TRACE ***"
			$Append += "`n"
			$Append += $Error.ScriptStackTrace
			$Append += "`n"		
			$Append += "*** END TRACE ***"
			
		
			# Build the hashtable with hints, if it wasn't build before
			If (!(Test-Path Variable:\AMHintsTable))
			{
				$global:AMHintsTable = New-Object System.Collections.Hashtable
				#$AMHintsTable.Add("System.Management.Automation.RuntimeException","Thrown Exception")
				$AMHintsTable.Add("System.IO.FileNotFoundException","Does the file exist, and is the system able to contact it?")
				$AMHintsTable.Add("System.Security.SecurityException", "Does $($env:username) have the appropriate rights?")
				$AMHintsTable.Add("System.UnauthorizedAccessException", "Does $($env:username) have the appropriate rights?")
				$AMHintsTable.Add("System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException", "Is $($env:username) a domain user and is $($env:computername) a member of a domain?")
				#Add win32 hints
				
    #WU_E_NO_SERVICE
    $AMHintsTable.Add("0x80240001", "Windows Update Agent was unable to provide the service")
    #WU_E_MAX_CAPACITY_REACHED
    $AMHintsTable.Add("0x80240002", "The maximum capacity of the service was exceeded")
    #WU_E_UNKNOWN_ID
    $AMHintsTable.Add("0x80240003", "An ID cannot be found")
    #WU_E_NOT_INITIALIZED
    $AMHintsTable.Add("0x80240004", "The object could not be initialized")
    #WU_E_RANGEOVERLAP
    $AMHintsTable.Add("0x80240005", "The update handler requested a byte range overlapping a previously requested range")
    #WU_E_TOOMANYRANGES
    $AMHintsTable.Add("0x80240006", "The requested number of byte ranges exceeds the maximum number")
    #WU_E_INVALIDINDEX
    $AMHintsTable.Add("0x80240007", "The index to a collection was invalid")
    #WU_E_ITEMNOTFOUND
    $AMHintsTable.Add("0x80240008", "The key for the item queried could not be found")
    #WU_E_OPERATIONINPROGRESS
    $AMHintsTable.Add("0x80240009", "Another conflicting operation was in progress. Some operations such as installation cannot be performed twice simultaneously")
    #WU_E_COULDNOTCANCEL
    $AMHintsTable.Add("0x8024000A", "Cancellation of the operation was not allowed")
    #WU_E_CALL_CANCELLED
    $AMHintsTable.Add("0x8024000B", "Operation was cancelled")
    #WU_E_NOOP
    $AMHintsTable.Add("0x8024000C", "No operation was required")
    #WU_E_XML_MISSINGDATA
    $AMHintsTable.Add("0x8024000D", "Windows Update Agent could not find required information in the update's XML data")
    #WU_E_XML_INVALID
    $AMHintsTable.Add("0x8024000E", "Windows Update Agent found invalid information in the update's XML data")
    #WU_E_CYCLE_DETECTED
    $AMHintsTable.Add("0x8024000F", "Circular update relationships were detected in the metadata")
    #WU_E_TOO_DEEP_RELATION
    $AMHintsTable.Add("0x80240010", "Update relationships too deep to evaluate were evaluated")
    #WU_E_INVALID_RELATIONSHIP
    $AMHintsTable.Add("0x80240011", "An invalid update relationship was detected")
    #WU_E_REG_VALUE_INVALID
    $AMHintsTable.Add("0x80240012", "An invalid registry value was read")
    #WU_E_DUPLICATE_ITEM
    $AMHintsTable.Add("0x80240013", "Operation tried to add a duplicate item to a list")
    #WU_E_INSTALL_NOT_ALLOWED
    $AMHintsTable.Add("0x80240016", "Operation tried to install while another installation was in progress or the system was pending a mandatory restart")
    #WU_E_NOT_APPLICABLE
    $AMHintsTable.Add("0x80240017", "Operation was not performed because there are no applicable updates")
    #WU_E_NO_USERTOKEN
    $AMHintsTable.Add("0x80240018", "Operation failed because a required user token is missing")
    #WU_E_EXCLUSIVE_INSTALL_CONFLICT
    $AMHintsTable.Add("0x80240019", "An exclusive update cannot be installed with other updates at the same time")
    #WU_E_POLICY_NOT_SET
    $AMHintsTable.Add("0x8024001A", "A policy value was not set")
    #WU_E_SELFUPDATE_IN_PROGRESS
    $AMHintsTable.Add("0x8024001B", "The operation could not be performed because the Windows Update Agent is self-updating")
    #WU_E_INVALID_UPDATE
    $AMHintsTable.Add("0x8024001D", "An update contains invalid metadata")
    #WU_E_SERVICE_STOP
    $AMHintsTable.Add("0x8024001E", "Operation did not complete because the service or system was being shut down")
    #WU_E_NO_CONNECTION
    $AMHintsTable.Add("0x8024001F", "Operation did not complete because the network connection was unavailable")
    #WU_E_NO_INTERACTIVE_USER
    $AMHintsTable.Add("0x80240020", "Operation did not complete because there is no logged-on interactive user")
    #WU_E_TIME_OUT
    $AMHintsTable.Add("0x80240021", "Operation did not complete because it timed out")
    #WU_E_ALL_UPDATES_FAILED
    $AMHintsTable.Add("0x80240022", "Operation failed for all the updates")
    #WU_E_EULAS_DECLINED
    $AMHintsTable.Add("0x80240023", "The license terms for all updates were declined")
    #WU_E_NO_UPDATE
    $AMHintsTable.Add("0x80240024", "There are no updates")
    #WU_E_USER_ACCESS_DISABLED
    $AMHintsTable.Add("0x80240025", "Group Policy settings prevented access to Windows Update")
    #WU_E_INVALID_UPDATE_TYPE
    $AMHintsTable.Add("0x80240026", "The type of update is invalid")
    #WU_E_URL_TOO_LONG
    $AMHintsTable.Add("0x80240027", "The URL exceeded the maximum length")
    #WU_E_UNINSTALL_NOT_ALLOWED
    $AMHintsTable.Add("0x80240028", "The update could not be uninstalled because the request did not originate from a WSUS server")
    #WU_E_INVALID_PRODUCT_LICENSE
    $AMHintsTable.Add("0x80240029", "Search may have missed some updates before there is an unlicensed application on the system")
    #WU_E_MISSING_HANDLER
    $AMHintsTable.Add("0x8024002A", "A component required to detect applicable updates was missing")
    #WU_E_LEGACYSERVER
    $AMHintsTable.Add("0x8024002B", "An operation did not complete because it requires a newer version of server")
    #WU_E_BIN_SOURCE_ABSENT
    $AMHintsTable.Add("0x8024002C", "A delta-compressed update could not be installed because it required the source")
    #WU_E_SOURCE_ABSENT
    $AMHintsTable.Add("0x8024002D", "A full-file update could not be installed because it required the source.")
    #WU_E_WU_DISABLED
    $AMHintsTable.Add("0x8024002E", "Access to an unmanaged server is not allowed.")
    #WU_E_CALL_CANCELLED_BY_POLICY
    $AMHintsTable.Add("0x8024002F", "Operation did not complete because the DisableWindowsUpdateAccess policy was set.")
    #WU_E_INVALID_PROXY_SERVER
    $AMHintsTable.Add("0x80240030", "The format of the proxy list was invalid.")
    #WU_E_INVALID_FILE
    $AMHintsTable.Add("0x80240031", "The file is in the wrong format.")
    #WU_E_INVALID_CRITERIA
    $AMHintsTable.Add("0x80240032", "The search criteria string was invalid.")
    #WU_E_EULA_UNAVAILABLE
    $AMHintsTable.Add("0x80240033", "License terms could not be downloaded.")
    #WU_E_DOWNLOAD_FAILED
    $AMHintsTable.Add("0x80240034", "Update failed to download.")
    #WU_E_UPDATE_NOT_PROCESSED
    $AMHintsTable.Add("0x80240035", "The update was not processed.")
    #WU_E_INVALID_OPERATION
    $AMHintsTable.Add("0x80240036", "The object's current state did not allow the operation.")
    #WU_E_NOT_SUPPORTED
    $AMHintsTable.Add("0x80240037", "The functionality for the operation is not supported.")
    #WU_E_WINHTTP_INVALID_FILE
    $AMHintsTable.Add("0x80240038", "The downloaded file has an unexpected content type.")
    #WU_E_TOO_MANY_RESYNC
    $AMHintsTable.Add("0x80240039", "Agent is asked by server to resync too many times.")
    #WU_E_NO_SERVER_CORE_SUPPORT
    $AMHintsTable.Add("0x80240040", "WUA API method does not run on Server Core installation.")
    #WU_E_SYSPREP_IN_PROGRESS
    $AMHintsTable.Add("0x80240041", "Service is not available while sysprep is running.")
    #WU_E_UNKNOWN_SERVICE
    $AMHintsTable.Add("0x80240042", "The update service is no longer registered with AU.")
    #WU_E_NO_UI_SUPPORT
    $AMHintsTable.Add("0x80240043", "There is no support for WUA UI")
    #WU_E_PER_MACHINE_UPDATE_ACCESS_DENIED
    $AMHintsTable.Add("0x80240044", "Only administrators can perform this operation on per-machine updates")
    #WU_E_UNSUPPORTED_SEARCHSCOPE
    $AMHintsTable.Add("0x80240045", "A search was attempted with a scope that is not currently supported for this type of search")
    #WU_E_BAD_FILE_URL
    $AMHintsTable.Add("0x80240046", "The URL does not point to a file")
    #WU_E_NOTSUPPORTED
    $AMHintsTable.Add("0x80240047", "The operation requested is not supported")
    #WU_E_INVALID_NOTIFICATION_INFO
    $AMHintsTable.Add("0x80240048", "The featured update notification info returned by the server is invalid")
    #WU_E_OUTOFRANGE
    $AMHintsTable.Add("0x80240049", "The data is out of range")
    #WU_E_SETUP_IN_PROGRESS
    $AMHintsTable.Add("0x8024004A", "Windows Update agent operations are not available while OS setup is running")
    #WU_E_PT_CATALOG_SYNC_REQUIRED
    $AMHintsTable.Add("0x80240436", "The server does not support category-specific search; Full catalog search has to be issued instead")
    #WU_E_PT_SECURITY_VERIFICATION_FAILURE
    $AMHintsTable.Add("0x80240437", "There was a problem authorizing with the service")
    #WU_E_PT_ENDPOINT_UNREACHABLE
    $AMHintsTable.Add("0x80240438", "There is no route or network connectivity to WindowsUpdate or the WSUS server")
    #WU_E_PT_INVALID_FORMAT
    $AMHintsTable.Add("0x80240439", "The data received does not meet the data contract expectations")
    #WU_E_PT_INVALID_URL
    $AMHintsTable.Add("0x8024043A", "The url is invalid")
    #WU_E_PT_NWS_NOT_LOADED
    $AMHintsTable.Add("0x8024043B", "Unable to load NWS runtime")
    #WU_E_PT_PROXY_AUTH_SCHEME_NOT_SUPPORTED
    $AMHintsTable.Add("0x8024043C", "The proxy auth scheme is not supported")
    #WU_E_SERVICEPROP_NOTAVAIL
    $AMHintsTable.Add("0x8024043D", "The requested service property is not available")
    #WU_E_PT_ENDPOINT_REFRESH_REQUIRED
    $AMHintsTable.Add("0x8024043E",	"The endpoint provider plugin requires online refresh")
    #WU_E_PT_ENDPOINTURL_NOTAVAIL
    $AMHintsTable.Add("0x8024043F", "A URL for the requested service endpoint is not available")
    #WU_E_PT_ENDPOINT_DISCONNECTED
    $AMHintsTable.Add("0x80240440", "The connection to the service endpoint died")
    #WU_E_PT_INVALID_OPERATION
    $AMHintsTable.Add("0x80240441", "The operation is invalid because protocol talker is in an inappropriate state")
    #WU_E_UNEXPECTED
    $AMHintsTable.Add("0x80240FFF", "An operation failed due to reasons not covered by another error code.")
    #WU_E_MSI_WRONG_VERSION
    $AMHintsTable.Add("0x80241001", "Search may have missed some updates because the Windows Installer is less than version 3.1.")
    #WU_E_MSI_NOT_CONFIGURED
    $AMHintsTable.Add("0x80241002", "Search may have missed some updates because the Windows Installer is not configured.")
    #WU_E_MSP_DISABLED
    $AMHintsTable.Add("0x80241003", "Search may have missed some updates because policy has disabled Windows Installer patching.")
    #WU_E_MSI_WRONG_APP_CONTEXT
    $AMHintsTable.Add("0x80241004", "An update could not be applied because the application is installed per-user.")
    #WU_E_MSP_UNEXPECTED
    $AMHintsTable.Add("0x80241FFF", "Search may have missed some updates because there was a failure of the Windows Installer.")
    #WU_E_UH_REMOTEUNAVAILABLE
    $AMHintsTable.Add("0x80242000", "A request for a remote update handler could not be completed because no remote process is available.")
    #WU_E_UH_LOCALONLY
    $AMHintsTable.Add("0x80242001", "A request for a remote update handler could not be completed because the handler is local only.")
    #WU_E_UH_UNKNOWNHANDLER
    $AMHintsTable.Add("0x80242002", "A request for an update handler could not be completed because the handler could not be recognized.")
    #WU_E_UH_REMOTEALREADYACTIVE
    $AMHintsTable.Add("0x80242003", "A remote update handler could not be created because one already exists.")
    #WU_E_UH_DOESNOTSUPPORTACTION
    $AMHintsTable.Add("0x80242004", "A request for the handler to install (uninstall) an update could not be completed because the update does not support install (uninstall).")
    #WU_E_UH_WRONGHANDLER
    $AMHintsTable.Add("0x80242005", "An operation did not complete because the wrong handler was specified.")
    #WU_E_UH_INVALIDMETADATA
    $AMHintsTable.Add("0x80242006", "A handler operation could not be completed because the update contains invalid metadata.")
    #WU_E_UH_INSTALLERHUNG
    $AMHintsTable.Add("0x80242007", "An operation could not be completed because the installer exceeded the time limit.")
    #WU_E_UH_OPERATIONCANCELLED
    $AMHintsTable.Add("0x80242008", "An operation being done by the update handler was cancelled.")
    #WU_E_UH_BADHANDLERXML
    $AMHintsTable.Add("0x80242009", "An operation could not be completed because the handler-specific metadata is invalid.")
    #WU_E_UH_CANREQUIREINPUT
    $AMHintsTable.Add("0x8024200A", "A request to the handler to install an update could not be completed because the update requires user input.")
    #WU_E_UH_INSTALLERFAILURE
    $AMHintsTable.Add("0x8024200B", "The installer failed to install (uninstall) one or more updates.")
    #WU_E_UH_FALLBACKTOSELFCONTAINED
    $AMHintsTable.Add("0x8024200C", "The update handler should download self-contained content rather than delta-compressed content for the update.")
    #WU_E_UH_NEEDANOTHERDOWNLOAD
    $AMHintsTable.Add("0x8024200D", "The update handler did not install the update because it needs to be downloaded again.")
    #WU_E_UH_NOTIFYFAILURE
    $AMHintsTable.Add("0x8024200E", "The update handler failed to send notification of the status of the install (uninstall) operation.")
    #WU_E_UH_INCONSISTENT_FILE_NAMES
    $AMHintsTable.Add("0x8024200F", "The file names contained in the update metadata and in the update package are inconsistent.")
    #WU_E_UH_FALLBACKERROR
    $AMHintsTable.Add("0x80242010", "The update handler failed to fall back to the self-contained content.")
    #WU_E_UH_TOOMANYDOWNLOADREQUESTS
    $AMHintsTable.Add("0x80242011", "The update handler has exceeded the maximum number of download requests.")
    #WU_E_UH_UNEXPECTEDCBSRESPONSE
    $AMHintsTable.Add("0x80242012", "The update handler has received an unexpected response from CBS.")
    #WU_E_UH_BADCBSPACKAGEID
    $AMHintsTable.Add("0x80242013", "The update metadata contains an invalid CBS package identifier.")
    #WU_E_UH_POSTREBOOTSTILLPENDING
    $AMHintsTable.Add("0x80242014", "he post-reboot operation for the update is still in progress.")
    #WU_E_UH_POSTREBOOTRESULTUNKNOWN
    $AMHintsTable.Add("0x80242015", "The result of the post-reboot operation for the update could not be determined.")
    #WU_E_UH_POSTREBOOTUNEXPECTEDSTATE
    $AMHintsTable.Add("0x80242016", "The state of the update after its post-reboot operation has completed is unexpected.")
    #WU_E_UH_NEW_SERVICING_STACK_REQUIRED
    $AMHintsTable.Add("0x80242017", "The operating system servicing stack must be updated before this update is downloaded or installed.")
    #WU_E_UH_UNEXPECTED
    $AMHintsTable.Add("0x80242FFF", "An update handler error not covered by another WU_E_UH_* code.")
    #WU_E_INSTALLATION_RESULTS_UNKNOWN_VERSION
    $AMHintsTable.Add("0x80243001", "The results of download and installation could not be read from the registry due to an unrecognized data format version.")
    #WU_E_INSTALLATION_RESULTS_INVALID_DATA
    $AMHintsTable.Add("0x80243002", "The results of download and installation could not be read from the registry due to an invalid data format.")
    #WU_E_INSTALLATION_RESULTS_NOT_FOUND
    $AMHintsTable.Add("0x80243003", "The results of download and installation are not available; the operation may have failed to start.")
    #WU_E_TRAYICON_FAILURE
    $AMHintsTable.Add("0x80243004", "A failure occurred when trying to create an icon in the taskbar notification area.")
    #WU_E_NON_UI_MODE
    $AMHintsTable.Add("0x80243FFD", "Unable to show UI when in non-UI mode; WU client UI modules may not be installed.")
    #WU_E_WUCLTUI_UNSUPPORTED_VERSION
    $AMHintsTable.Add("0x80243FFE", "Unsupported version of WU client UI exported functions.")
    #WU_E_AUCLIENT_UNEXPECTED
    $AMHintsTable.Add("0x80243FFF", "There was a user interface error not covered by another WU_E_AUCLIENT_* error code.")
    #WU_E_PT_SOAPCLIENT_BASE
    $AMHintsTable.Add("0x80244000", "WU_E_PT_SOAPCLIENT_* error codes map to the SOAPCLIENT_ERROR enum of the ATL Server Library.")
    #WU_E_PT_SOAPCLIENT_INITIALIZE
    $AMHintsTable.Add("0x80244001", "SOAPCLIENT_INITIALIZE_ERROR - initialization of the SOAP client failed, possibly because of an MSXML installation failure.")
    #WU_E_PT_SOAPCLIENT_OUTOFMEMORY
    $AMHintsTable.Add("0x80244002", "SOAPCLIENT_OUTOFMEMORY - SOAP client failed because it ran out of memory.")
    #WU_E_PT_SOAPCLIENT_GENERATE
    $AMHintsTable.Add("0x80244003", "SOAPCLIENT_GENERATE_ERROR - SOAP client failed to generate the request.")
    #WU_E_PT_SOAPCLIENT_CONNECT
    $AMHintsTable.Add("0x80244004", "SOAPCLIENT_CONNECT_ERROR - SOAP client failed to connect to the server.")
    #WU_E_PT_SOAPCLIENT_SEND
    $AMHintsTable.Add("0x80244005", "SOAPCLIENT_SEND_ERROR - SOAP client failed to send a message for reasons of WU_E_WINHTTP_* error codes.")
    #WU_E_PT_SOAPCLIENT_SERVER
    $AMHintsTable.Add("0x80244006", "SOAPCLIENT_SERVER_ERROR - SOAP client failed because there was a server error.")
    #WU_E_PT_SOAPCLIENT_SOAPFAULT
    $AMHintsTable.Add("0x80244007", "SOAPCLIENT_SOAPFAULT - SOAP client failed because there was a SOAP fault for reasons of WU_E_PT_SOAP_* error codes.")
    #WU_E_PT_SOAPCLIENT_PARSEFAULT
    $AMHintsTable.Add("0x80244008", "SOAPCLIENT_PARSEFAULT_ERROR - SOAP client failed to parse a SOAP fault.")
    #WU_E_PT_SOAPCLIENT_READ
    $AMHintsTable.Add("0x80244009", "SOAPCLIENT_READ_ERROR - SOAP client failed while reading the response from the server.")
    #WU_E_PT_SOAPCLIENT_PARSE
    $AMHintsTable.Add("0x8024400A", "SOAPCLIENT_PARSE_ERROR - SOAP client failed to parse the response from the server.")
    #WU_E_PT_SOAP_VERSION
    $AMHintsTable.Add("0x8024400B", "SOAP_E_VERSION_MISMATCH - SOAP client found an unrecognizable namespace for the SOAP envelope.")
    #WU_E_PT_SOAP_MUST_UNDERSTAND
    $AMHintsTable.Add("0x8024400C", "SOAP_E_MUST_UNDERSTAND - SOAP client was unable to understand a header.")
    #WU_E_PT_SOAP_CLIENT
    $AMHintsTable.Add("0x8024400D", "SOAP_E_CLIENT - SOAP client found the message was malformed; fix before resending.")
    #WU_E_PT_SOAP_SERVER
    $AMHintsTable.Add("0x8024400E", "SOAP_E_SERVER - The SOAP message could not be processed due to a server error; resend later.")
    #WU_E_PT_WMI_ERROR
    $AMHintsTable.Add("0x8024400F", "There was an unspecified Windows Management Instrumentation (WMI) error.")
    #WU_E_PT_EXCEEDED_MAX_SERVER_TRIPS
    $AMHintsTable.Add("0x80244010", "The number of round trips to the server exceeded the maximum limit.")
    #WU_E_PT_SUS_SERVER_NOT_SET
    $AMHintsTable.Add("0x80244011", "WUServer policy value is missing in the registry.")
    #WU_E_PT_DOUBLE_INITIALIZATION
    $AMHintsTable.Add("0x80244012", "Initialization failed because the object was already initialized.")
    #WU_E_PT_INVALID_COMPUTER_NAME
    $AMHintsTable.Add("0x80244013", "The computer name could not be determined.")
    #WU_E_PT_REFRESH_CACHE_REQUIRED
    $AMHintsTable.Add("0x80244015", "The reply from the server indicates that the server was changed or the cookie was invalid; refresh the state of the internal cache and retry.")
    #WU_E_PT_HTTP_STATUS_BAD_REQUEST
    $AMHintsTable.Add("0x80244016", "HTTP 400 - the server could not process the request due to invalid syntax.")
    #WU_E_PT_HTTP_STATUS_DENIED
    $AMHintsTable.Add("0x80244017", "HTTP 401 - the requested resource requires user authentication.")
    #WU_E_PT_HTTP_STATUS_FORBIDDEN
    $AMHintsTable.Add("0x80244018", "HTTP 403 - server understood the request, but declined to fulfill it.")
    #WU_E_PT_HTTP_STATUS_NOT_FOUND
    $AMHintsTable.Add("0x80244019", "HTTP 404 - the server cannot find the requested URI (Uniform Resource Identifier).")
    #WU_E_PT_HTTP_STATUS_BAD_METHOD
    $AMHintsTable.Add("0x8024401A", "HTTP 405 - the HTTP method is not allowed.")
    #WU_E_PT_HTTP_STATUS_PROXY_AUTH_REQ
    $AMHintsTable.Add("0x8024401B", "HTTP 407 - proxy authentication is required.")
    #WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT
    $AMHintsTable.Add("0x8024401C", "HTTP 408 - the server timed out waiting for the request.")
    #WU_E_PT_HTTP_STATUS_CONFLICT
    $AMHintsTable.Add("0x8024401D", "HTTP 409 - the request was not completed due to a conflict with the current state of the resource.")
    #WU_E_PT_HTTP_STATUS_GONE
    $AMHintsTable.Add("0x8024401E", "HTTP 410 - requested resource is no longer available at the server.")
    #WU_E_PT_HTTP_STATUS_SERVER_ERROR
    $AMHintsTable.Add("0x8024401F", "HTTP 500 - an error internal to the server prevented fulfilling the request.")
    #WU_E_PT_HTTP_STATUS_NOT_SUPPORTED
    $AMHintsTable.Add("0x80244020", "HTTP 501 - server does not support the functionality required to fulfill the request.")
    #WU_E_PT_HTTP_STATUS_BAD_GATEWAY
    $AMHintsTable.Add("0x80244021", "HTTP 502 - the server, while acting as a gateway or proxy, received an invalid response from the upstream server it accessed in attempting to fulfill the request.")
    #WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL
    $AMHintsTable.Add("0x80244022", "HTTP 503 - the service is temporarily overloaded.")
    #WU_E_PT_HTTP_STATUS_GATEWAY_TIMEOUT
    $AMHintsTable.Add("0x80244023", "HTTP 504 - the request was timed out waiting for a gateway.")
    #WU_E_PT_HTTP_STATUS_VERSION_NOT_SUP
    $AMHintsTable.Add("0x80244024", "HTTP 505 - the server does not support the HTTP protocol version used for the request.")
    #WU_E_PT_FILE_LOCATIONS_CHANGED
    $AMHintsTable.Add("0x80244025", "Operation failed due to a changed file location; refresh internal state and resend.")
    #WU_E_PT_REGISTRATION_NOT_SUPPORTED
    $AMHintsTable.Add("0x80244026", "Operation failed because Windows Update Agent does not support registration with a non-WSUS server.")
    #WU_E_PT_NO_AUTH_PLUGINS_REQUESTED
    $AMHintsTable.Add("0x80244027", "The server returned an empty authentication information list.")
    #WU_E_PT_NO_AUTH_COOKIES_CREATED
    $AMHintsTable.Add("0x80244028", "Windows Update Agent was unable to create any valid authentication cookies.")
    #WU_E_PT_INVALID_CONFIG_PROP
    $AMHintsTable.Add("0x80244029", "A configuration property value was wrong.")
    #WU_E_PT_CONFIG_PROP_MISSING
    $AMHintsTable.Add("0x8024402A", "A configuration property value was missing.")
    #WU_E_PT_HTTP_STATUS_NOT_MAPPED
    $AMHintsTable.Add("0x8024402B", "The HTTP request could not be completed and the reason did not correspond to any of the WU_E_PT_HTTP_* error codes.")
    #WU_E_PT_WINHTTP_NAME_NOT_RESOLVED
    $AMHintsTable.Add("0x8024402C", "ERROR_WINHTTP_NAME_NOT_RESOLVED - the proxy server or target server name cannot be resolved.")
    #WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS
    $AMHintsTable.Add("0x8024402F", "External cab file processing completed with some errors.")
    #WU_E_PT_ECP_INIT_FAILED
    $AMHintsTable.Add("0x80244030", "The external cab processor initialization did not complete.")
    #WU_E_PT_ECP_INVALID_FILE_FORMAT
    $AMHintsTable.Add("0x80244031", "The format of a metadata file was invalid.")
    #WU_E_PT_ECP_INVALID_METADATA
    $AMHintsTable.Add("0x80244032", "External cab processor found invalid metadata.")
    #WU_E_PT_ECP_FAILURE_TO_EXTRACT_DIGEST
    $AMHintsTable.Add("0x80244033", "The file digest could not be extracted from an external cab file.")
    #WU_E_PT_ECP_FAILURE_TO_DECOMPRESS_CAB_FILE
    $AMHintsTable.Add("0x80244034", "An external cab file could not be decompressed.")
    #WU_E_PT_ECP_FILE_LOCATION_ERROR
    $AMHintsTable.Add("0x80244035", "External cab processor was unable to get file locations.")
    #WU_E_PT_UNEXPECTED
    $AMHintsTable.Add("0x80244FFF", "A communication error not covered by another WU_E_PT_* error code")
    #WU_E_REDIRECTOR_LOAD_XML
    $AMHintsTable.Add("0x80245001", "The redirector XML document could not be loaded into the DOM class.")
    #WU_E_REDIRECTOR_S_FALSE
    $AMHintsTable.Add("0x80245002", "The redirector XML document is missing some required information.")
    #WU_E_REDIRECTOR_ID_SMALLER
    $AMHintsTable.Add("0x80245003", "The redirector ID in the downloaded redirector cab is less than in the cached cab.")
    #WU_E_PT_SAME_REDIR_ID
    $AMHintsTable.Add("0x8024502D", "Windows Update Agent failed to download a redirector cabinet file with a new redirector ID value from the server during the recovery.")
    #WU_E_PT_NO_MANAGED_RECOVER
    $AMHintsTable.Add("0x8024502E", "A redirector recovery action did not complete because the server is managed.")
    #WU_E_REDIRECTOR_UNEXPECTED
    $AMHintsTable.Add("0x80245FFF", "The redirector failed for reasons not covered by another WU_E_REDIRECTOR_* error code.")
    #WU_E_DM_URLNOTAVAILABLE
    $AMHintsTable.Add("0x80246001", "A download manager operation could not be completed because the requested file does not have a URL.")
    #WU_E_DM_INCORRECTFILEHASH
    $AMHintsTable.Add("0x80246002", "A download manager operation could not be completed because the file digest was not recognized.")
    #WU_E_DM_UNKNOWNALGORITHM
    $AMHintsTable.Add("0x80246003", "A download manager operation could not be completed because the file metadata requested an unrecognized hash algorithm.")
    #WU_E_DM_NEEDDOWNLOADREQUEST
    $AMHintsTable.Add("0x80246004", "An operation could not be completed because a download request is required from the download handler.")
    #WU_E_DM_NONETWORK
    $AMHintsTable.Add("0x80246005", "A download manager operation could not be completed because the network connection was unavailable.")
    #WU_E_DM_WRONGBITSVERSION
    $AMHintsTable.Add("0x80246006", "A download manager operation could not be completed because the version of Background Intelligent Transfer Service (BITS) is incompatible.")
    #WU_E_DM_NOTDOWNLOADED
    $AMHintsTable.Add("0x80246007", "The update has not been downloaded.")
    #WU_E_DM_FAILTOCONNECTTOBITS
    $AMHintsTable.Add("0x80246008", "A download manager operation failed because the download manager was unable to connect the Background Intelligent Transfer Service (BITS).")
    #WU_E_DM_BITSTRANSFERERROR
    $AMHintsTable.Add("0x80246009", "A download manager operation failed because there was an unspecified Background Intelligent Transfer Service (BITS) transfer error.")
    #WU_E_DM_DOWNLOADLOCATIONCHANGED
    $AMHintsTable.Add("0x8024600a", "A download must be restarted because the location of the source of the download has changed.")
    #WU_E_DM_CONTENTCHANGED
    $AMHintsTable.Add("0x8024600B", "A download must be restarted because the update content changed in a new revision.")
    #WU_E_DM_UNEXPECTED
    $AMHintsTable.Add("0x80246FFF", "There was a download manager error not covered by another WU_E_DM_* error code.")
    #WU_E_OL_INVALID_SCANFILE
    $AMHintsTable.Add("0x80247001", "An operation could not be completed because the scan package was invalid.")
    #WU_E_OL_NEWCLIENT_REQUIRED
    $AMHintsTable.Add("0x80247002", "An operation could not be completed because the scan package requires a greater version of the Windows Update Agent.")
    #WU_E_OL_UNEXPECTED
    $AMHintsTable.Add("0x80247FFF", "Search using the scan package failed.")
    #WU_E_DS_SHUTDOWN
    $AMHintsTable.Add("0x80248000", "An operation failed because Windows Update Agent is shutting down.")
    #WU_E_DS_INUSE
    $AMHintsTable.Add("0x80248001", "An operation failed because the data store was in use.")
    #WU_E_DS_INVALID
    $AMHintsTable.Add("0x80248002", "The current and expected states of the data store do not match.")
    #WU_E_DS_TABLEMISSING
    $AMHintsTable.Add("0x80248003", "The data store is missing a table.")
    #WU_E_DS_TABLEINCORRECT
    $AMHintsTable.Add("0x80248004", "The data store contains a table with unexpected columns.")
    #WU_E_DS_INVALIDTABLENAME
    $AMHintsTable.Add("0x80248005", "A table could not be opened because the table is not in the data store.")
    #WU_E_DS_BADVERSION
    $AMHintsTable.Add("0x80248006", "The current and expected versions of the data store do not match.")
    #WU_E_DS_NODATA
    $AMHintsTable.Add("0x80248007", "The information requested is not in the data store.")
    #WU_E_DS_MISSINGDATA
    $AMHintsTable.Add("0x80248008", "The data store is missing required information or has a NULL in a table column that requires a non-null value.")
    #WU_E_DS_MISSINGREF
    $AMHintsTable.Add("0x80248009", "The data store is missing required information or has a reference to missing license terms, file, localized property or linked row.")
    #WU_E_DS_UNKNOWNHANDLER
    $AMHintsTable.Add("0x8024800A", "The update was not processed because its update handler could not be recognized.")
    #WU_E_DS_CANTDELETE
    $AMHintsTable.Add("0x8024800B", "The update was not deleted because it is still referenced by one or more services.")
    #WU_E_DS_LOCKTIMEOUTEXPIRED
    $AMHintsTable.Add("0x8024800C", "The data store section could not be locked within the allotted time.")
    #WU_E_DS_NOCATEGORIES
    $AMHintsTable.Add("0x8024800D", "The category was not added because it contains no parent categories and is not a top-level category itself.")
    #WU_E_DS_ROWEXISTS
    $AMHintsTable.Add("0x8024800E", "The row was not added because an existing row has the same primary key.")
    #WU_E_DS_STOREFILELOCKED
    $AMHintsTable.Add("0x8024800F", "The data store could not be initialized because it was locked by another process.")
    #WU_E_DS_CANNOTREGISTER
    $AMHintsTable.Add("0x80248010", "The data store is not allowed to be registered with COM in the current process.")
    #WU_E_DS_UNABLETOSTART
    $AMHintsTable.Add("0x80248011", "Could not create a data store object in another process.")
    #WU_E_DS_DUPLICATEUPDATEID
    $AMHintsTable.Add("0x80248013", "The server sent the same update to the client with two different revision IDs.")
    #WU_E_DS_UNKNOWNSERVICE
    $AMHintsTable.Add("0x80248014", "An operation did not complete because the service is not in the data store.")
    #WU_E_DS_SERVICEEXPIRED
    $AMHintsTable.Add("0x80248015", "An operation did not complete because the registration of the service has expired.")
    #WU_E_DS_DECLINENOTALLOWED
    $AMHintsTable.Add("0x80248016", "A request to hide an update was declined because it is a mandatory update or because it was deployed with a deadline.")
    #WU_E_DS_TABLESESSIONMISMATCH
    $AMHintsTable.Add("0x80248017", "A table was not closed because it is not associated with the session.")
    #WU_E_DS_SESSIONLOCKMISMATCH
    $AMHintsTable.Add("0x80248018", "A table was not closed because it is not associated with the session.")
    #WU_E_DS_NEEDWINDOWSSERVICE
    $AMHintsTable.Add("0x80248019", "A request to remove the Windows Update service or to unregister it with Automatic Updates was declined because it is a built-in service and/or Automatic Updates cannot fall back to another service.")
    #WU_E_DS_INVALIDOPERATION
    $AMHintsTable.Add("0x8024801A", "A request was declined because the operation is not allowed.")
    #WU_E_DS_SCHEMAMISMATCH
    $AMHintsTable.Add("0x8024801B", "The schema of the current data store and the schema of a table in a backup XML document do not match.")
    #WU_E_DS_RESETREQUIRED
    $AMHintsTable.Add("0x8024801C", "The data store requires a session reset; release the session and retry with a new session.")
    #WU_E_DS_IMPERSONATED
    $AMHintsTable.Add("0x8024801D", "A data store operation did not complete because it was requested with an impersonated identity.")
    #WU_E_DS_UNEXPECTED
    $AMHintsTable.Add("0x80248FFF", "A data store error not covered by another WU_E_DS_* code.")
    #WU_E_INVENTORY_PARSEFAILED
    $AMHintsTable.Add("0x80249001", "Parsing of the rule file failed.")
    #WU_E_INVENTORY_GET_INVENTORY_TYPE_FAILED
    $AMHintsTable.Add("0x80249002", "Failed to get the requested inventory type from the server.")
    #WU_E_INVENTORY_RESULT_UPLOAD_FAILED
    $AMHintsTable.Add("0x80249003", "Failed to upload inventory result to the server.")
    #WU_E_INVENTORY_UNEXPECTED
    $AMHintsTable.Add("0x80249004", "There was an inventory error not covered by another error code.")
    #WU_E_INVENTORY_WMI_ERROR
    $AMHintsTable.Add("0x80249005", "A WMI error occurred when enumerating the instances for a particular class.")
    #WU_E_AU_NOSERVICE
    $AMHintsTable.Add("0x8024A000", "Automatic Updates was unable to service incoming requests.")
    #WU_E_AU_NONLEGACYSERVER
    $AMHintsTable.Add("0x8024A002", "The old version of the Automatic Updates client has stopped because the WSUS server has been upgraded.")
    #WU_E_AU_LEGACYCLIENTDISABLED
    $AMHintsTable.Add("0x8024A003", "The old version of the Automatic Updates client was disabled.")
    #WU_E_AU_PAUSED
    $AMHintsTable.Add("0x8024A004", "Automatic Updates was unable to process incoming requests because it was paused.")
    #WU_E_AU_NO_REGISTERED_SERVICE
    $AMHintsTable.Add("0x8024A005", "No unmanaged service is registered with AU.")
    #WU_E_AU_UNEXPECTED
    $AMHintsTable.Add("0x8024AFFF", "An Automatic Updates error not covered by another WU_E_AU * code.")
    #WU_E_DRV_PRUNED
    $AMHintsTable.Add("0x8024C001", "A driver was skipped.")
    #WU_E_DRV_NOPROP_OR_LEGACY
    $AMHintsTable.Add("0x8024C002", "A property for the driver could not be found. It may not conform with required specifications.")
    #WU_E_DRV_REG_MISMATCH
    $AMHintsTable.Add("0x8024C003", "The registry type read for the driver does not match the expected type.")
    #WU_E_DRV_NO_METADATA
    $AMHintsTable.Add("0x8024C004", "The driver update is missing metadata.")
    #WU_E_DRV_MISSING_ATTRIBUTE
    $AMHintsTable.Add("0x8024C005", "The driver update is missing a required attribute.")
    #WU_E_DRV_SYNC_FAILED
    $AMHintsTable.Add("0x8024C006", "Driver synchronization failed.")
    #WU_E_DRV_NO_PRINTER_CONTENT
    $AMHintsTable.Add("0x8024C007", "Information required for the synchronization of applicable printers is missing.")
    #WU_E_DRV_UNEXPECTED
    $AMHintsTable.Add("0x8024CFFF", "A driver error not covered by another WU_E_DRV_* code.")
    #WU_E_SETUP_INVALID_INFDATA
    $AMHintsTable.Add("0x8024D001", "Windows Update Agent could not be updated because an INF file contains invalid information.")
    #WU_E_SETUP_INVALID_IDENTDATA
    $AMHintsTable.Add("0x8024D002", "Windows Update Agent could not be updated because the wuident.cab file contains invalid information.")
    #WU_E_SETUP_ALREADY_INITIALIZED
    $AMHintsTable.Add("0x8024D003", "Windows Update Agent could not be updated because of an internal error that caused setup initialization to be performed twice.")
    #WU_E_SETUP_NOT_INITIALIZED
    $AMHintsTable.Add("0x8024D004", "Windows Update Agent could not be updated because setup initialization never completed successfully.")
    #WU_E_SETUP_SOURCE_VERSION_MISMATCH
    $AMHintsTable.Add("0x8024D005", "Windows Update Agent could not be updated because the versions specified in the INF do not match the actual source file versions.")
    #WU_E_SETUP_TARGET_VERSION_GREATER
    $AMHintsTable.Add("0x8024D006", "Windows Update Agent could not be updated because a WUA file on the target system is newer than the corresponding source file.")
    #WU_E_SETUP_REGISTRATION_FAILED
    $AMHintsTable.Add("0x8024D007", "Windows Update Agent could not be updated because regsvr32.exe returned an error.")
    #WU_E_SELFUPDATE_SKIP_ON_FAILURE
    $AMHintsTable.Add("0x8024D008", "An update to the Windows Update Agent was skipped because previous attempts to update have failed.")
    #WU_E_SETUP_SKIP_UPDATE
    $AMHintsTable.Add("0x8024D009", "An update to the Windows Update Agent was skipped due to a directive in the wuident.cab file.")
    #WU_E_SETUP_UNSUPPORTED_CONFIGURATION
    $AMHintsTable.Add("0x8024D00A", "Windows Update Agent could not be updated because the current system configuration is not supported.")
    #WU_E_SETUP_BLOCKED_CONFIGURATION
    $AMHintsTable.Add("0x8024D00B", "Windows Update Agent could not be updated because the system is configured to block the update.")
    #WU_E_SETUP_REBOOT_TO_FIX
    $AMHintsTable.Add("0x8024D00C", "Windows Update Agent could not be updated because a restart of the system is required.")
    #WU_E_SETUP_ALREADYRUNNING
    $AMHintsTable.Add("0x8024D00D", "Windows Update Agent setup is already running.")
    #WU_E_SETUP_REBOOTREQUIRED
    $AMHintsTable.Add("0x8024D00E", "Windows Update Agent setup package requires a reboot to complete installation.")
    #WU_E_SETUP_HANDLER_EXEC_FAILURE
    $AMHintsTable.Add("0x8024D00F", "Windows Update Agent could not be updated because the setup handler failed during execution.")
    #WU_E_SETUP_INVALID_REGISTRY_DATA
    $AMHintsTable.Add("0x8024D010", "Windows Update Agent could not be updated because the registry contains invalid information.")
    #WU_E_SELFUPDATE_REQUIRED
    $AMHintsTable.Add("0x8024D011", "Windows Update Agent must be updated before search can continue.")
    #WU_E_SELFUPDATE_REQUIRED_ADMIN
    $AMHintsTable.Add("0x8024D012", "Windows Update Agent must be updated before search can continue. An administrator is required to perform the operation.")
    #WU_E_SETUP_WRONG_SERVER_VERSION
    $AMHintsTable.Add("0x8024D013", "Windows Update Agent could not be updated because the server does not contain update information for this version.")
    #WU_E_SETUP_UNEXPECTED
    $AMHintsTable.Add("0x8024DFFF", "Windows Update Agent could not be updated because of an error not covered by another WU_E_SETUP_* error code.")
    #WU_E_EE_UNKNOWN_EXPRESSION
    $AMHintsTable.Add("0x8024E001", "An expression evaluator operation could not be completed because an expression was unrecognized.")
    #WU_E_EE_INVALID_EXPRESSION
    $AMHintsTable.Add("0x8024E002", "An expression evaluator operation could not be completed because an expression was invalid.")
    #WU_E_EE_MISSING_METADATA
    $AMHintsTable.Add("0x8024E003", "An expression evaluator operation could not be completed because an expression contains an incorrect number of metadata nodes.")
    #WU_E_EE_INVALID_VERSION
    $AMHintsTable.Add("0x8024E004", "An expression evaluator operation could not be completed because the version of the serialized expression data is invalid.")
    #WU_E_EE_NOT_INITIALIZED
    $AMHintsTable.Add("0x8024E005", "The expression evaluator could not be initialized.")
    #WU_E_EE_INVALID_ATTRIBUTEDATA
    $AMHintsTable.Add("0x8024E006", "An expression evaluator operation could not be completed because there was an invalid attribute.")
    #WU_E_EE_CLUSTER_ERROR
    $AMHintsTable.Add("0x8024E007", "An expression evaluator operation could not be completed because the cluster state of the computer could not be determined.")
    #WU_E_EE_UNEXPECTED
    $AMHintsTable.Add("0x8024EFFF", "There was an expression evaluator error not covered by another WU_E_EE_* error code.")
    #WU_E_REPORTER_EVENTCACHECORRUPT
    $AMHintsTable.Add("0x8024F001", "The event cache file was defective.")
    #WU_E_REPORTER_EVENTNAMESPACEPARSEFAILED
    $AMHintsTable.Add("0x8024F002", "The XML in the event namespace descriptor could not be parsed.")
    #WU_E_INVALID_EVENT
    $AMHintsTable.Add("0x8024F003", "The XML in the event namespace descriptor could not be parsed.")
    #WU_E_SERVER_BUSY
    $AMHintsTable.Add("0x8024F004", "The server rejected an event because the server was too busy.")
    #WU_E_REPORTER_UNEXPECTED
    $AMHintsTable.Add("0x8024FFFF", "There was a reporter error not covered by another error code.")

    # ERROR_INVALID_FUNCTION
    $AMHintsTable.Add("0x80070001", "Incorrect function.")
    #ERROR_FILE_NOT_FOUND
    $AMHintsTable.Add("0x80070002", "The system cannot find the file specified.")
    #ERROR_PATH_NOT_FOUND
    $AMHintsTable.Add("0x80070003", "The system cannot find the path specified.")
    #ERROR_TOO_MANY_OPEN_FILES
    $AMHintsTable.Add("0x80070004", "The system cannot open the file, too many open files.")
    #ERROR_ACCESS_DENIED
    $AMHintsTable.Add("0x80070005", "Access is denied.")
    #ERROR_INVALID_HANDLE
    $AMHintsTable.Add("0x80070006", "The handle is invalid.")
    #ERROR_ARENA_TRASHED
    $AMHintsTable.Add("0x80070007", "The storage control blocks were destroyed.")
    #ERROR_NOT_ENOUGH_MEMORY
    $AMHintsTable.Add("0x80070008", "Not enough storage is available to process this command.")
    #ERROR_INVALID_BLOCK
    $AMHintsTable.Add("0x80070009", "The storage control block address is invalid.")
    #ERROR_BAD_ENVIRONMENT
    $AMHintsTable.Add("0x8007000A", "The environment is incorrect.")
    #ERROR_BAD_FORMAT
    $AMHintsTable.Add("0x8007000B", "An attempt was made to load a program with an incorrect format.")
    #ERROR_INVALID_ACCESS
    $AMHintsTable.Add("0x8007000C", "The access code is invalid.")
    #ERROR_INVALID_DATA
    $AMHintsTable.Add("0x8007000D", "The data is invalid.")
    #ERROR_OUTOFMEMORY
    $AMHintsTable.Add("0x8007000E", "Not enough storage is available to complete this operation.")
    #ERROR_INVALID_DRIVE
    $AMHintsTable.Add("0x8007000F", "The system cannot find the drive specified.")
    #ERROR_CURRENT_DIRECTORY
    $AMHintsTable.Add("0x80070010", "The directory cannot be removed.")
    #ERROR_NOT_SAME_DEVICE
    $AMHintsTable.Add("0x80070011", "The system cannot move the file to a different disk drive.")
    #ERROR_NO_MORE_FILES
    $AMHintsTable.Add("0x80070012", "There are no more files.")
    #ERROR_WRITE_PROTECT
    $AMHintsTable.Add("0x80070013", "The media is write-protected.")
    #ERROR_BAD_UNIT
    $AMHintsTable.Add("0x80070014", "The system cannot find the device specified.")
    #ERROR_NOT_READY
    $AMHintsTable.Add("0x80070015", "The device is not ready.")
    #ERROR_BAD_COMMAND
    $AMHintsTable.Add("0x80070016", "The device does not recognize the command.")
    #ERROR_CRC
    $AMHintsTable.Add("0x80070017", "Data error (cyclic redundancy check).")
    #ERROR_BAD_LENGTH
    $AMHintsTable.Add("0x80070018", "The program issued a command but the command length is incorrect.")
    #ERROR_SEEK
    $AMHintsTable.Add("0x80070019", "The drive cannot locate a specific area or track on the disk.")
    #ERROR_NOT_DOS_DISK
    $AMHintsTable.Add("0x8007001A", "The specified disk cannot be accessed.")
    #ERROR_SECTOR_NOT_FOUND
    $AMHintsTable.Add("0x8007001B", "The drive cannot find the sector requested.")
    #ERROR_OUT_OF_PAPER
    $AMHintsTable.Add("0x8007001C", "The printer is out of paper.")
    #ERROR_WRITE_FAULT
    $AMHintsTable.Add("0x8007001D", "The system cannot write to the specified device.")
    #ERROR_READ_FAULT
    $AMHintsTable.Add("0x8007001E", "The system cannot read from the specified device.")
    #ERROR_GEN_FAILURE
    $AMHintsTable.Add("0x8007001F", "A device attached to the system is not functioning.")
    #ERROR_SHARING_VIOLATION
    $AMHintsTable.Add("0x80070020", "The process cannot access the file because it is being used by another process.")
    #ERROR_LOCK_VIOLATION
    $AMHintsTable.Add("0x80070021", "The process cannot access the file because another process has locked a portion of the file.")
    #ERROR_WRONG_DISK
    $AMHintsTable.Add("0x80070022", "The wrong disk is in the drive. Insert %2 (Volume Serial Number: %3) into drive %1.")
    #ERROR_SHARING_BUFFER_EXCEEDED
    $AMHintsTable.Add("0x80070024", "Too many files opened for sharing.")
    #ERROR_HANDLE_EOF
    $AMHintsTable.Add("0x80070026", "Reached the end of the file.")
    #ERROR_HANDLE_DISK_FULL
    $AMHintsTable.Add("0x80070027", "The disk is full.")
    #ERROR_NOT_SUPPORTED
    $AMHintsTable.Add("0x80070032", "The request is not supported.")
    #ERROR_REM_NOT_LIST
    $AMHintsTable.Add("0x80070033", "Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off. If Windows still cannot find the network path, contact your network administrator.")
    #ERROR_DUP_NAME
    $AMHintsTable.Add("0x80070034", "You were not connected because a duplicate name exists on the network. Go to System in Control Panel to change the computer name, and then try again.")
    #ERROR_BAD_NETPATH
    $AMHintsTable.Add("0x80070035", "The network path was not found.")
    #ERROR_NETWORK_BUSY
    $AMHintsTable.Add("0x80070036", "The network is busy.")
    #ERROR_DEV_NOT_EXIST
    $AMHintsTable.Add("0x80070037", "The specified network resource or device is no longer available.")
    #ERROR_TOO_MANY_CMDS
    $AMHintsTable.Add("0x80070038", "The network BIOS command limit has been reached.")
    #ERROR_ADAP_HDW_ERR
    $AMHintsTable.Add("0x80070039", "A network adapter hardware error occurred.")
    #ERROR_BAD_NET_RESP
    $AMHintsTable.Add("0x8007003A", "The specified server cannot perform the requested operation.")
    #ERROR_UNEXP_NET_ERR
    $AMHintsTable.Add("0x8007003B", "An unexpected network error occurred.")
    #ERROR_BAD_REM_ADAP
    $AMHintsTable.Add("0x8007003C", "The remote adapter is not compatible.")
    #ERROR_PRINTQ_FULL
    $AMHintsTable.Add("0x8007003D", "The print queue is full.")
    #ERROR_NO_SPOOL_SPACE
    $AMHintsTable.Add("0x8007003E", "Space to store the file waiting to be printed is not available on the server.")
    #ERROR_PRINT_CANCELLED
    $AMHintsTable.Add("0x8007003F", "Your file waiting to be printed was deleted.")
    #ERROR_NETNAME_DELETED
    $AMHintsTable.Add("0x80070040", "The specified network name is no longer available.")
    #ERROR_NETWORK_ACCESS_DENIED
    $AMHintsTable.Add("0x80070041", "Network access is denied.")
    #ERROR_BAD_DEV_TYPE
    $AMHintsTable.Add("0x80070042", "The network resource type is not correct.")
    #ERROR_BAD_NET_NAME
    $AMHintsTable.Add("0x80070043", "The network name cannot be found.")
    #ERROR_TOO_MANY_NAMES
    $AMHintsTable.Add("0x80070044", "The name limit for the local computer network adapter card was exceeded.")
    #ERROR_TOO_MANY_SESS
    $AMHintsTable.Add("0x80070045", "The network BIOS session limit was exceeded.")
    #ERROR_SHARING_PAUSED
    $AMHintsTable.Add("0x80070046", "The remote server has been paused or is in the process of being started.")
    #ERROR_REQ_NOT_ACCEP
    $AMHintsTable.Add("0x80070047", "No more connections can be made to this remote computer at this time because the computer has accepted the maximum number of connections.")
    #ERROR_REDIR_PAUSED
    $AMHintsTable.Add("0x80070048", "The specified printer or disk device has been paused.")
    #ERROR_FILE_EXISTS
    $AMHintsTable.Add("0x80070050", "The file exists.")
    #ERROR_CANNOT_MAKE
    $AMHintsTable.Add("0x80070052", "The directory or file cannot be created.")
    #ERROR_FAIL_I24
    $AMHintsTable.Add("0x80070053", "Fail on INT 24.")
    #ERROR_OUT_OF_STRUCTURES
    $AMHintsTable.Add("0x80070054", "Storage to process this request is not available.")
    #ERROR_ALREADY_ASSIGNED
    $AMHintsTable.Add("0x80070055", "The local device name is already in use.")
    #ERROR_INVALID_PASSWORD
    $AMHintsTable.Add("0x80070056", "The specified network password is not correct.")
    #ERROR_INVALID_PARAMETER
    $AMHintsTable.Add("0x80070057", "The parameter is incorrect.")
    #ERROR_NET_WRITE_FAULT
    $AMHintsTable.Add("0x80070058", "A write fault occurred on the network.")
    #ERROR_NO_PROC_SLOTS
    $AMHintsTable.Add("0x80070059", "The system cannot start another process at this time.")
    #ERROR_TOO_MANY_SEMAPHORES
    $AMHintsTable.Add("0x80070064", "Cannot create another system semaphore.")
    #ERROR_EXCL_SEM_ALREADY_OWNED
    $AMHintsTable.Add("0x80070065", "The exclusive semaphore is owned by another process.")
    #ERROR_SEM_IS_SET
    $AMHintsTable.Add("0x80070066", "The semaphore is set and cannot be closed.")
    #ERROR_TOO_MANY_SEM_REQUESTS
    $AMHintsTable.Add("0x80070067", "The semaphore cannot be set again.")
    #ERROR_INVALID_AT_INTERRUPT_TIME
    $AMHintsTable.Add("0x80070068", "Cannot request exclusive semaphores at interrupt time.")
    #ERROR_SEM_OWNER_DIED
    $AMHintsTable.Add("0x80070069", "The previous ownership of this semaphore has ended.")
    #ERROR_SEM_USER_LIMIT
    $AMHintsTable.Add("0x8007006A", "Insert the disk for drive %1.")
    #ERROR_DISK_CHANGE
    $AMHintsTable.Add("0x8007006B", "The program stopped because an alternate disk was not inserted.")
    #ERROR_DRIVE_LOCKED
    $AMHintsTable.Add("0x8007006C", "The disk is in use or locked by another process.")
    #ERROR_BROKEN_PIPE
    $AMHintsTable.Add("0x8007006D", "The pipe has been ended.")
    #ERROR_OPEN_FAILED
    $AMHintsTable.Add("0x8007006E", "The system cannot open the device or file specified.")
    #ERROR_BUFFER_OVERFLOW
    $AMHintsTable.Add("0x8007006F", "The file name is too long.")
    #ERROR_DISK_FULL
    $AMHintsTable.Add("0x80070070", "There is not enough space on the disk.")
    #ERROR_NO_MORE_SEARCH_HANDLES
    $AMHintsTable.Add("0x80070071", "No more internal file identifiers are available.")
    #ERROR_INVALID_TARGET_HANDLE
    $AMHintsTable.Add("0x80070072", "The target internal file identifier is incorrect.")
    #ERROR_INVALID_CATEGORY
    $AMHintsTable.Add("0x80070075", "The Input Output Control (IOCTL) call made by the application program is not correct.")
    #ERROR_INVALID_VERIFY_SWITCH
    $AMHintsTable.Add("0x80070076", "The verify-on-write switch parameter value is not correct.")
    #ERROR_BAD_DRIVER_LEVEL
    $AMHintsTable.Add("0x80070077", "The system does not support the command requested.")
    #ERROR_CALL_NOT_IMPLEMENTED
    $AMHintsTable.Add("0x80070078", "This function is not supported on this system.")
    #ERROR_SEM_TIMEOUT
    $AMHintsTable.Add("0x80070079", "The semaphore time-out period has expired.")
    #ERROR_INSUFFICIENT_BUFFER
    $AMHintsTable.Add("0x8007007A", "The data area passed to a system call is too small.")
    #ERROR_INVALID_NAME
    $AMHintsTable.Add("0x8007007B", "The file name, directory name, or volume label syntax is incorrect.")
    #ERROR_INVALID_LEVEL
    $AMHintsTable.Add("0x8007007C", "The system call level is not correct.")
    #ERROR_NO_VOLUME_LABEL
    $AMHintsTable.Add("0x8007007D", "The disk has no volume label.")
    #ERROR_MOD_NOT_FOUND
    $AMHintsTable.Add("0x8007007E", "The specified module could not be found.")
    #ERROR_PROC_NOT_FOUND
    $AMHintsTable.Add("0x8007007F", "The specified procedure could not be found.")
    #ERROR_WAIT_NO_CHILDREN
    $AMHintsTable.Add("0x80070080", "There are no child processes to wait for.")
    #ERROR_CHILD_NOT_COMPLETE
    $AMHintsTable.Add("0x80070081", "The %1 application cannot be run in Win32 mode.")
    #ERROR_DIRECT_ACCESS_HANDLE
    $AMHintsTable.Add("0x80070082", "Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O.")
    #ERROR_NEGATIVE_SEEK
    $AMHintsTable.Add("0x80070083", "An attempt was made to move the file pointer before the beginning of the file.")
    #ERROR_SEEK_ON_DEVICE
    $AMHintsTable.Add("0x80070084", "The file pointer cannot be set on the specified device or file.")
    #ERROR_IS_JOIN_TARGET
    $AMHintsTable.Add("0x80070085", "A JOIN or SUBST command cannot be used for a drive that contains previously joined drives.")
    #ERROR_IS_JOINED
    $AMHintsTable.Add("0x80070086", "An attempt was made to use a JOIN or SUBST command on a drive that has already been joined.")
    #ERROR_IS_SUBSTED
    $AMHintsTable.Add("0x80070087", "An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted.")
    #ERROR_NOT_JOINED
    $AMHintsTable.Add("0x80070088", "The system tried to delete the JOIN of a drive that is not joined.")
    #ERROR_NOT_SUBSTED
    $AMHintsTable.Add("0x80070089", "The system tried to delete the substitution of a drive that is not substituted.")
    #ERROR_JOIN_TO_JOIN
    $AMHintsTable.Add("0x8007008A", "The system tried to join a drive to a directory on a joined drive.")
    #ERROR_SUBST_TO_SUBST
    $AMHintsTable.Add("0x8007008B", "The system tried to substitute a drive to a directory on a substituted drive.")
    #ERROR_JOIN_TO_SUBST
    $AMHintsTable.Add("0x8007008C", "The system tried to join a drive to a directory on a substituted drive.")
    #ERROR_SUBST_TO_JOIN
    $AMHintsTable.Add("0x8007008D", "The system tried to SUBST a drive to a directory on a joined drive.")
    #ERROR_BUSY_DRIVE
    $AMHintsTable.Add("0x8007008E", "The system cannot perform a JOIN or SUBST at this time.")
    #ERROR_SAME_DRIVE
    $AMHintsTable.Add("0x8007008F", "The system cannot join or substitute a drive to or for a directory on the same drive.")
    #ERROR_DIR_NOT_ROOT
    $AMHintsTable.Add("0x80070090", "The directory is not a subdirectory of the root directory.")
    #ERROR_DIR_NOT_EMPTY
    $AMHintsTable.Add("0x80070091", "The directory is not empty.")
    #ERROR_IS_SUBST_PATH
    $AMHintsTable.Add("0x80070092", "The path specified is being used in a substitute.")
    #ERROR_IS_JOIN_PATH
    $AMHintsTable.Add("0x80070093", "Not enough resources are available to process this command.")
    #ERROR_PATH_BUSY
    $AMHintsTable.Add("0x80070094", "The path specified cannot be used at this time.")
    #ERROR_IS_SUBST_TARGET
    $AMHintsTable.Add("0x80070095", "An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute.")
    #ERROR_SYSTEM_TRACE
    $AMHintsTable.Add("0x80070096", "System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed.")
    #ERROR_INVALID_EVENT_COUNT
    $AMHintsTable.Add("0x80070097", "The number of specified semaphore events for DosMuxSemWait is not correct.")
    #ERROR_TOO_MANY_MUXWAITERS
    $AMHintsTable.Add("0x80070098", "DosMuxSemWait did not execute; too many semaphores are already set.")
    #ERROR_INVALID_LIST_FORMAT
    $AMHintsTable.Add("0x80070099", "The DosMuxSemWait list is not correct.")
    #ERROR_LABEL_TOO_LONG
    $AMHintsTable.Add("0x8007009A", "The volume label you entered exceeds the label character limit of the destination file system.")
    #ERROR_TOO_MANY_TCBS
    $AMHintsTable.Add("0x8007009B", "Cannot create another thread.")
    #ERROR_SIGNAL_REFUSED
    $AMHintsTable.Add("0x8007009C", "The recipient process has refused the signal.")
    #ERROR_DISCARDED
    $AMHintsTable.Add("0x8007009D", "The segment is already discarded and cannot be locked.")
    #ERROR_NOT_LOCKED
    $AMHintsTable.Add("0x8007009E", "The segment is already unlocked.")
    #ERROR_BAD_THREADID_ADDR
    $AMHintsTable.Add("0x8007009F", "The address for the thread ID is not correct.")
    #ERROR_BAD_ARGUMENTS
    $AMHintsTable.Add("0x800700A0", "One or more arguments are not correct.")
    #ERROR_BAD_PATHNAME
    $AMHintsTable.Add("0x800700A1", "The specified path is invalid.")
    #ERROR_SIGNAL_PENDING
    $AMHintsTable.Add("0x800700A2", "A signal is already pending.")
    #ERROR_MAX_THRDS_REACHED
    $AMHintsTable.Add("0x800700A4", "No more threads can be created in the system.")
    #ERROR_LOCK_FAILED
    $AMHintsTable.Add("0x800700A7", "Unable to lock a region of a file.")
    #ERROR_BUSY
    $AMHintsTable.Add("0x800700AA", "The requested resource is in use.")
    #ERROR_CANCEL_VIOLATION
    $AMHintsTable.Add("0x800700AD", "A lock request was not outstanding for the supplied cancel region.")
    #ERROR_ATOMIC_LOCKS_NOT_SUPPORTED
    $AMHintsTable.Add("0x800700AE", "The file system does not support atomic changes to the lock type.")
    #ERROR_INVALID_SEGMENT_NUMBER
    $AMHintsTable.Add("0x800700B4", "The system detected a segment number that was not correct.")
    #ERROR_INVALID_ORDINAL
    $AMHintsTable.Add("0x800700B6", "The operating system cannot run %1.")
    #ERROR_ALREADY_EXISTS
    $AMHintsTable.Add("0x800700B7", "Cannot create a file when that file already exists.")
    #ERROR_INVALID_FLAG_NUMBER
    $AMHintsTable.Add("0x800700BA", "The flag passed is not correct.")
    #ERROR_SEM_NOT_FOUND
    $AMHintsTable.Add("0x800700BB", "The specified system semaphore name was not found.")
    #ERROR_INVALID_STARTING_CODESEG
    $AMHintsTable.Add("0x800700BC", "The operating system cannot run %1.")
    #ERROR_INVALID_STACKSEG
    $AMHintsTable.Add("0x800700BD", "The operating system cannot run %1.")
    #ERROR_INVALID_MODULETYPE
    $AMHintsTable.Add("0x800700BE", "The operating system cannot run %1.")
    #ERROR_INVALID_EXE_SIGNATURE
    $AMHintsTable.Add("0x800700BF", "Cannot run %1 in Win32 mode.")
    #ERROR_EXE_MARKED_INVALID
    $AMHintsTable.Add("0x800700C0", "The operating system cannot run %1.")
    #ERROR_BAD_EXE_FORMAT
    $AMHintsTable.Add("0x800700C1", "%1 is not a valid Win32 application.")
    #ERROR_ITERATED_DATA_EXCEEDS_64k
    $AMHintsTable.Add("0x800700C2", "The operating system cannot run %1.")
    #ERROR_INVALID_MINALLOCSIZE
    $AMHintsTable.Add("0x800700C3", "The operating system cannot run %1.")
    #ERROR_DYNLINK_FROM_INVALID_RING
    $AMHintsTable.Add("0x800700C4", "The operating system cannot run this application program.")
    #ERROR_IOPL_NOT_ENABLED
    $AMHintsTable.Add("0x800700C5", "The operating system is not presently configured to run this application.")
    #ERROR_INVALID_SEGDPL
    $AMHintsTable.Add("0x800700C6", "The operating system cannot run %1.")
    #ERROR_AUTODATASEG_EXCEEDS_64k
    $AMHintsTable.Add("0x800700C7", "The operating system cannot run this application program.")
    #ERROR_RING2SEG_MUST_BE_MOVABLE
    $AMHintsTable.Add("0x800700C8", "The code segment cannot be greater than or equal to 64 KB.")
    #ERROR_RELOC_CHAIN_XEEDS_SEGLIM
    $AMHintsTable.Add("0x800700C9", "The operating system cannot run %1.")
    #ERROR_INFLOOP_IN_RELOC_CHAIN
    $AMHintsTable.Add("0x800700CA", "The operating system cannot run %1.")
    #ERROR_ENVVAR_NOT_FOUND
    $AMHintsTable.Add("0x800700CB", "The system could not find the environment option that was entered.")
    #ERROR_NO_SIGNAL_SENT
    $AMHintsTable.Add("0x800700CD", "No process in the command subtree has a signal handler.")
    #ERROR_FILENAME_EXCED_RANGE
    $AMHintsTable.Add("0x800700CE", "The file name or extension is too long.")
    #ERROR_RING2_STACK_IN_USE
    $AMHintsTable.Add("0x800700CF", "The ring 2 stack is in use.")
    #ERROR_META_EXPANSION_TOO_LONG
    $AMHintsTable.Add("0x800700D0", "The asterisk (*) or question mark (?) global file name characters are entered incorrectly, or too many global file name characters are specified.")
    #ERROR_INVALID_SIGNAL_NUMBER
    $AMHintsTable.Add("0x800700D1", "The signal being posted is not correct.")
    #ERROR_THREAD_1_INACTIVE
    $AMHintsTable.Add("0x800700D2", "The signal handler cannot be set.")
    #ERROR_LOCKED
    $AMHintsTable.Add("0x800700D4", "The segment is locked and cannot be reallocated.")
    #ERROR_TOO_MANY_MODULES
    $AMHintsTable.Add("0x800700D6", "Too many dynamic-link modules are attached to this program or dynamic-link module.")
    #ERROR_NESTING_NOT_ALLOWED
    $AMHintsTable.Add("0x800700D7", "Cannot nest calls to LoadModule.")
    #ERROR_EXE_MACHINE_TYPE_MISMATCH
    $AMHintsTable.Add("0x800700D8", "This version of %1 is not compatible with the version of Windows you're running. Check your computer's system information to see whether you need an x86 (32-bit) or x64 (64-bit) version of the program, and then contact the software publisher.")
    #ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY
    $AMHintsTable.Add("0x800700D9", "The image file %1 is signed, unable to modify.")
    #ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY
    $AMHintsTable.Add("0x800700DA", "The image file %1 is strong signed, unable to modify.")
    #ERROR_FILE_CHECKED_OUT
    $AMHintsTable.Add("0x800700DC", "This file is checked out or locked for editing by another user.")
    #ERROR_CHECKOUT_REQUIRED
    $AMHintsTable.Add("0x800700DD", "The file must be checked out before saving changes.")
    #ERROR_BAD_FILE_TYPE
    $AMHintsTable.Add("0x800700DE", "The file type being saved or retrieved has been blocked.")
    #ERROR_FILE_TOO_LARGE
    $AMHintsTable.Add("0x800700DF", "The file size exceeds the limit allowed and cannot be saved.")
    #ERROR_FORMS_AUTH_REQUIRED
    $AMHintsTable.Add("0x800700E0", "Access denied. Before opening files in this location, you must first browse to the website and select the option to sign in automatically.")
    #ERROR_VIRUS_INFECTED
    $AMHintsTable.Add("0x800700E1", "Operation did not complete successfully because the file contains a virus.")
    #ERROR_VIRUS_DELETED
    $AMHintsTable.Add("0x800700E2", "This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location.")
    #ERROR_PIPE_LOCAL
    $AMHintsTable.Add("0x800700E5", "The pipe is local.")
    #ERROR_BAD_PIPE
    $AMHintsTable.Add("0x800700E6", "The pipe state is invalid.")
    #ERROR_PIPE_BUSY
    $AMHintsTable.Add("0x800700E7", "All pipe instances are busy.")
    #ERROR_NO_DATA
    $AMHintsTable.Add("0x800700E8", "The pipe is being closed.")
    #ERROR_PIPE_NOT_CONNECTED
    $AMHintsTable.Add("0x800700E9", "No process is on the other end of the pipe.")
    #ERROR_MORE_DATA
    $AMHintsTable.Add("0x800700EA", "More data is available.")
    #ERROR_VC_DISCONNECTED
    $AMHintsTable.Add("0x800700F0", "The session was canceled.")
    #ERROR_INVALID_EA_NAME
    $AMHintsTable.Add("0x800700FE", "The specified extended attribute name was invalid.")
    #ERROR_EA_LIST_INCONSISTENT
    $AMHintsTable.Add("0x800700FF", "The extended attributes are inconsistent.")
    #WAIT_TIMEOUT
    $AMHintsTable.Add("0x80070102", "The wait operation timed out.")
    #ERROR_NO_MORE_ITEMS
    $AMHintsTable.Add("0x80070103", "No more data is available.")
    #ERROR_CANNOT_COPY
    $AMHintsTable.Add("0x8007010A", "The copy functions cannot be used.")
    #ERROR_DIRECTORY
    $AMHintsTable.Add("0x8007010B", "The directory name is invalid.")
    #ERROR_EAS_DIDNT_FIT
    $AMHintsTable.Add("0x80070113", "The extended attributes did not fit in the buffer.")
    #ERROR_EA_FILE_CORRUPT
    $AMHintsTable.Add("0x80070114", "The extended attribute file on the mounted file system is corrupt.")
    #ERROR_EA_TABLE_FULL
    $AMHintsTable.Add("0x80070115", "The extended attribute table file is full.")
    #ERROR_INVALID_EA_HANDLE
    $AMHintsTable.Add("0x80070116", "The specified extended attribute handle is invalid.")
    #ERROR_EAS_NOT_SUPPORTED
    $AMHintsTable.Add("0x8007011A", "The mounted file system does not support extended attributes.")
    #ERROR_NOT_OWNER
    $AMHintsTable.Add("0x80070120", "Attempt to release mutex not owned by caller.")
    #ERROR_TOO_MANY_POSTS
    $AMHintsTable.Add("0x8007012A", "Too many posts were made to a semaphore.")
    #ERROR_PARTIAL_COPY
    $AMHintsTable.Add("0x8007012B", "Only part of a ReadProcessMemory or WriteProcessMemory request was completed.")
    #ERROR_OPLOCK_NOT_GRANTED
    $AMHintsTable.Add("0x8007012C", "The oplock request is denied.")
    #ERROR_INVALID_OPLOCK_PROTOCOL
    $AMHintsTable.Add("0x8007012D", "An invalid oplock acknowledgment was received by the system.")
    #ERROR_DISK_TOO_FRAGMENTED
    $AMHintsTable.Add("0x8007012E", "The volume is too fragmented to complete this operation.")
    #ERROR_DELETE_PENDING
    $AMHintsTable.Add("0x8007012F", "The file cannot be opened because it is in the process of being deleted.")
    #ERROR_MR_MID_NOT_FOUND
    $AMHintsTable.Add("0x8007013D", "The system cannot find message text for message number 0x%1 in the message file for %2.")
    #ERROR_SCOPE_NOT_FOUND
    $AMHintsTable.Add("0x8007013E", "The scope specified was not found.")
    #ERROR_FAIL_NOACTION_REBOOT
    $AMHintsTable.Add("0x8007015E", "No action was taken because a system reboot is required.")
    #ERROR_FAIL_SHUTDOWN
    $AMHintsTable.Add("0x8007015F", "The shutdown operation failed.")
    #ERROR_FAIL_RESTART
    $AMHintsTable.Add("0x80070160", "The restart operation failed.")
    #ERROR_MAX_SESSIONS_REACHED
    $AMHintsTable.Add("0x80070161", "The maximum number of sessions has been reached.")
    #ERROR_THREAD_MODE_ALREADY_BACKGROUND
    $AMHintsTable.Add("0x80070190", "The thread is already in background processing mode.")
    #ERROR_THREAD_MODE_NOT_BACKGROUND
    $AMHintsTable.Add("0x80070191", "The thread is not in background processing mode.")
    #ERROR_PROCESS_MODE_ALREADY_BACKGROUND
    $AMHintsTable.Add("0x80070192", "The process is already in background processing mode.")
    #ERROR_PROCESS_MODE_NOT_BACKGROUND
    $AMHintsTable.Add("0x80070193", "The process is not in background processing mode.")
    #ERROR_INVALID_ADDRESS
    $AMHintsTable.Add("0x800701E7", "Attempt to access invalid address.")
    #ERROR_USER_PROFILE_LOAD
    $AMHintsTable.Add("0x800701F4", "User profile cannot be loaded.")
    #ERROR_ARITHMETIC_OVERFLOW
    $AMHintsTable.Add("0x80070216", "Arithmetic result exceeded 32 bits.")
    #ERROR_PIPE_CONNECTED
    $AMHintsTable.Add("0x80070217", "There is a process on the other end of the pipe.")
    #ERROR_PIPE_LISTENING
    $AMHintsTable.Add("0x80070218", "Waiting for a process to open the other end of the pipe.")
    #ERROR_VERIFIER_STOP
    $AMHintsTable.Add("0x80070219", "Application verifier has found an error in the current process.")
    #ERROR_ABIOS_ERROR
    $AMHintsTable.Add("0x8007021A", "An error occurred in the ABIOS subsystem.")
    #ERROR_WX86_WARNING
    $AMHintsTable.Add("0x8007021B", "A warning occurred in the WX86 subsystem.")
    #ERROR_WX86_ERROR
    $AMHintsTable.Add("0x8007021C", "An error occurred in the WX86 subsystem.")
    #ERROR_TIMER_NOT_CANCELED
    $AMHintsTable.Add("0x8007021D", "An attempt was made to cancel or set a timer that has an associated asynchronous procedure call (APC) and the subject thread is not the thread that originally set the timer with an associated APC routine.")
    #ERROR_UNWIND
    $AMHintsTable.Add("0x8007021E", "Unwind exception code.")
    #ERROR_BAD_STACK
    $AMHintsTable.Add("0x8007021F", "An invalid or unaligned stack was encountered during an unwind operation.")
    #ERROR_INVALID_UNWIND_TARGET
    $AMHintsTable.Add("0x80070220", "An invalid unwind target was encountered during an unwind operation.")
    #ERROR_INVALID_PORT_ATTRIBUTES
    $AMHintsTable.Add("0x80070221", "Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort.")
    #ERROR_PORT_MESSAGE_TOO_LONG
    $AMHintsTable.Add("0x80070222", "Length of message passed to NtRequestPort or NtRequestWaitReplyPort was longer than the maximum message allowed by the port.")
    #ERROR_INVALID_QUOTA_LOWER
    $AMHintsTable.Add("0x80070223", "An attempt was made to lower a quota limit below the current usage.")
    #ERROR_DEVICE_ALREADY_ATTACHED
    $AMHintsTable.Add("0x80070224", "An attempt was made to attach to a device that was already attached to another device.")
    #ERROR_INSTRUCTION_MISALIGNMENT
    $AMHintsTable.Add("0x80070225", "An attempt was made to execute an instruction at an unaligned address, and the host system does not support unaligned instruction references.")
    #ERROR_PROFILING_NOT_STARTED
    $AMHintsTable.Add("0x80070226", "Profiling not started.")
    #ERROR_PROFILING_NOT_STOPPED
    $AMHintsTable.Add("0x80070227", "Profiling not stopped.")
    #ERROR_COULD_NOT_INTERPRET
    $AMHintsTable.Add("0x80070228", "The passed ACL did not contain the minimum required information.")
    #ERROR_PROFILING_AT_LIMIT
    $AMHintsTable.Add("0x80070229", "The number of active profiling objects is at the maximum and no more may be started.")
    #ERROR_CANT_WAIT
    $AMHintsTable.Add("0x8007022A", "Used to indicate that an operation cannot continue without blocking for I/O.")
    #ERROR_CANT_TERMINATE_SELF
    $AMHintsTable.Add("0x8007022B", "Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.")
    #ERROR_UNEXPECTED_MM_CREATE_ERR
    $AMHintsTable.Add("0x8007022C", "If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.")
    #ERROR_UNEXPECTED_MM_MAP_ERROR
    $AMHintsTable.Add("0x8007022D", "If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.")
    #ERROR_UNEXPECTED_MM_EXTEND_ERR
    $AMHintsTable.Add("0x8007022E", "If an MM error is returned that is not defined in the standard FsRtl filter, it is converted to one of the following errors that is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception.")
    #ERROR_BAD_FUNCTION_TABLE
    $AMHintsTable.Add("0x8007022F", "A malformed function table was encountered during an unwind operation.")
    #ERROR_NO_GUID_TRANSLATION
    $AMHintsTable.Add("0x80070230", "Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which may cause a file creation attempt to fail.")
    #ERROR_INVALID_LDT_SIZE
    $AMHintsTable.Add("0x80070231", "Indicates that an attempt was made to grow a local domain table (LDT) by setting its size, or that the size was not an even number of selectors.")
    #ERROR_INVALID_LDT_OFFSET
    $AMHintsTable.Add("0x80070233", "Indicates that the starting value for the LDT information was not an integral multiple of the selector size.")
    #ERROR_INVALID_LDT_DESCRIPTOR
    $AMHintsTable.Add("0x80070234", "Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors.")
    #ERROR_TOO_MANY_THREADS
    $AMHintsTable.Add("0x80070235", "Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads.")
    #ERROR_THREAD_NOT_IN_PROCESS
    $AMHintsTable.Add("0x80070236", "An attempt was made to operate on a thread within a specific process, but the thread specified is not in the process specified.")
    #ERROR_PAGEFILE_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x80070237", "Page file quota was exceeded.")
    #ERROR_LOGON_SERVER_CONFLICT
    $AMHintsTable.Add("0x80070238", "The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.")
    #ERROR_SYNCHRONIZATION_REQUIRED
    $AMHintsTable.Add("0x80070239", "The Security Accounts Manager (SAM) database on a Windows Server is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required.")
    #ERROR_NET_OPEN_FAILED
    $AMHintsTable.Add("0x8007023A", "The NtCreateFile API failed. This error should never be returned to an application, it is a place holder for the Windows LAN Manager Redirector to use in its internal error mapping routines.")
    #ERROR_IO_PRIVILEGE_FAILED
    $AMHintsTable.Add("0x8007023B", "{Privilege Failed} The I/O permissions for the process could not be changed.")
    #ERROR_CONTROL_C_EXIT
    $AMHintsTable.Add("0x8007023C", "{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.")
    #ERROR_MISSING_SYSTEMFILE
    $AMHintsTable.Add("0x8007023D", "{Missing System File} The required system file %hs is bad or missing.")
    #ERROR_UNHANDLED_EXCEPTION
    $AMHintsTable.Add("0x8007023E", "{Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx.")
    #ERROR_APP_INIT_FAILURE
    $AMHintsTable.Add("0x8007023F", "{Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application.")
    #ERROR_PAGEFILE_CREATE_FAILED
    $AMHintsTable.Add("0x80070240", "{Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld.")
    #ERROR_INVALID_IMAGE_HASH
    $AMHintsTable.Add("0x80070241", "The hash for the image cannot be found in the system catalogs. The image is likely corrupt or the victim of tampering.")
    #ERROR_NO_PAGEFILE
    $AMHintsTable.Add("0x80070242", "{No Paging File Specified} No paging file was specified in the system configuration.")
    #ERROR_ILLEGAL_FLOAT_CONTEXT
    $AMHintsTable.Add("0x80070243", "{EXCEPTION} A real-mode application issued a floating-point instruction, and floating-point hardware is not present.")
    #ERROR_NO_EVENT_PAIR
    $AMHintsTable.Add("0x80070244", "An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread.")
    #ERROR_DOMAIN_CTRLR_CONFIG_ERROR
    $AMHintsTable.Add("0x80070245", "A Windows Server has an incorrect configuration.")
    #ERROR_ILLEGAL_CHARACTER
    $AMHintsTable.Add("0x80070246", "An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set, this includes the characters 0xFFFF and 0xFFFE.")
    #ERROR_UNDEFINED_CHARACTER
    $AMHintsTable.Add("0x80070247", "The Unicode character is not defined in the Unicode character set installed on the system.")
    #ERROR_FLOPPY_VOLUME
    $AMHintsTable.Add("0x80070248", "The paging file cannot be created on a floppy disk.")
    #ERROR_BIOS_FAILED_TO_CONNECT_INTERRUPT
    $AMHintsTable.Add("0x80070249", "The system bios failed to connect a system interrupt to the device or bus for which the device is connected.")
    #ERROR_BACKUP_CONTROLLER
    $AMHintsTable.Add("0x8007024A", "This operation is only allowed for the primary domain controller (PDC) of the domain.")
    #ERROR_MUTANT_LIMIT_EXCEEDED
    $AMHintsTable.Add("0x8007024B", "An attempt was made to acquire a mutant such that its maximum count would have been exceeded.")
    #ERROR_FS_DRIVER_REQUIRED
    $AMHintsTable.Add("0x8007024C", "A volume has been accessed for which a file system driver is required that has not yet been loaded.")
    #ERROR_CANNOT_LOAD_REGISTRY_FILE
    $AMHintsTable.Add("0x8007024D", "{Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable.")
    #ERROR_DEBUG_ATTACH_FAILED
    $AMHintsTable.Add("0x8007024E", "{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error.")
    #ERROR_SYSTEM_PROCESS_TERMINATED
    $AMHintsTable.Add("0x8007024F", "{Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down.")
    #ERROR_DATA_NOT_ACCEPTED
    $AMHintsTable.Add("0x80070250", "{Data Not Accepted} The transport driver interface (TDI) client could not handle the data received during an indication.")
    #ERROR_VDM_HARD_ERROR
    $AMHintsTable.Add("0x80070251", "The NT Virtual DOS Machine (NTVDM) encountered a hard error.")
    #ERROR_DRIVER_CANCEL_TIMEOUT
    $AMHintsTable.Add("0x80070252", "{Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time.")
    #ERROR_REPLY_MESSAGE_MISMATCH
    $AMHintsTable.Add("0x80070253", "{Reply Message Mismatch} An attempt was made to reply to a local procedure call (LPC) message, but the thread specified by the client ID in the message was not waiting on that message.")
    #ERROR_LOST_WRITEBEHIND_DATA
    $AMHintsTable.Add("0x80070254", "{Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost. This error may be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere.")
    #ERROR_CLIENT_SERVER_PARAMETERS_INVALID
    $AMHintsTable.Add("0x80070255", "The parameters passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window.")
    #ERROR_NOT_TINY_STREAM
    $AMHintsTable.Add("0x80070256", "The stream is not a tiny stream.")
    #ERROR_STACK_OVERFLOW_READ
    $AMHintsTable.Add("0x80070257", "The request must be handled by the stack overflow code.")
    #ERROR_CONVERT_TO_LARGE
    $AMHintsTable.Add("0x80070258", "Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing onode is moved or the extent stream is converted to a large stream.")
    #ERROR_FOUND_OUT_OF_SCOPE
    $AMHintsTable.Add("0x80070259", "The attempt to find the object found an object matching by ID on the volume but it is out of the scope of the handle used for the operation.")
    #ERROR_ALLOCATE_BUCKET
    $AMHintsTable.Add("0x8007025A", "The bucket array must be grown. Retry transaction after doing so.")
    #ERROR_MARSHALL_OVERFLOW
    $AMHintsTable.Add("0x8007025B", "The user/kernel marshaling buffer has overflowed.")
    #ERROR_INVALID_VARIANT
    $AMHintsTable.Add("0x8007025C", "The supplied variant structure contains invalid data.")
    #ERROR_BAD_COMPRESSION_BUFFER
    $AMHintsTable.Add("0x8007025D", "The specified buffer contains ill-formed data.")
    #ERROR_AUDIT_FAILED
    $AMHintsTable.Add("0x8007025E", "{Audit Failed} An attempt to generate a security audit failed.")
    #ERROR_TIMER_RESOLUTION_NOT_SET
    $AMHintsTable.Add("0x8007025F", "The timer resolution was not previously set by the current process.")
    #ERROR_INSUFFICIENT_LOGON_INFO
    $AMHintsTable.Add("0x80070260", "There is insufficient account information to log you on.")
    #ERROR_BAD_DLL_ENTRYPOINT
    $AMHintsTable.Add("0x80070261", "{Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly.")
    #ERROR_BAD_SERVICE_ENTRYPOINT
    $AMHintsTable.Add("0x80070262", "{Invalid Service Callback Entrypoint} The %hs service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly.")
    #ERROR_IP_ADDRESS_CONFLICT1
    $AMHintsTable.Add("0x80070263", "There is an IP address conflict with another system on the network.")
    #ERROR_IP_ADDRESS_CONFLICT2
    $AMHintsTable.Add("0x80070264", "There is an IP address conflict with another system on the network.")
    #ERROR_REGISTRY_QUOTA_LIMIT
    $AMHintsTable.Add("0x80070265", "{Low On Registry Space} The system has reached the maximum size allowed for the system part of the registry. Additional storage requests will be ignored.")
    #ERROR_NO_CALLBACK_ACTIVE
    $AMHintsTable.Add("0x80070266", "A callback return system service cannot be executed when no callback is active.")
    #ERROR_PWD_TOO_SHORT
    $AMHintsTable.Add("0x80070267", "The password provided is too short to meet the policy of your user account. Choose a longer password.")
    #ERROR_PWD_TOO_RECENT
    $AMHintsTable.Add("0x80070268", "The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned.")
    #ERROR_PWD_HISTORY_CONFLICT
    $AMHintsTable.Add("0x80070269", "You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used.")
    #ERROR_UNSUPPORTED_COMPRESSION
    $AMHintsTable.Add("0x8007026A", "The specified compression format is unsupported.")
    #ERROR_INVALID_HW_PROFILE
    $AMHintsTable.Add("0x8007026B", "The specified hardware profile configuration is invalid.")
    #ERROR_INVALID_PLUGPLAY_DEVICE_PATH
    $AMHintsTable.Add("0x8007026C", "The specified Plug and Play registry device path is invalid.")
    #ERROR_QUOTA_LIST_INCONSISTENT
    $AMHintsTable.Add("0x8007026D", "The specified quota list is internally inconsistent with its descriptor.")
    #ERROR_EVALUATION_EXPIRATION
    $AMHintsTable.Add("0x8007026E", "{Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shut down in 1 hour. To restore access to this installation of Windows, upgrade this installation using a licensed distribution of this product.")
    #ERROR_ILLEGAL_DLL_RELOCATION
    $AMHintsTable.Add("0x8007026F", "{Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly. The relocation occurred because the DLL %hs occupied an address range reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL.")
    #ERROR_DLL_INIT_FAILED_LOGOFF
    $AMHintsTable.Add("0x80070270", "{DLL Initialization Failed} The application failed to initialize because the window station is shutting down.")
    #ERROR_VALIDATE_CONTINUE
    $AMHintsTable.Add("0x80070271", "The validation process needs to continue on to the next step.")
    #ERROR_NO_MORE_MATCHES
    $AMHintsTable.Add("0x80070272", "There are no more matches for the current index enumeration.")
    #ERROR_RANGE_LIST_CONFLICT
    $AMHintsTable.Add("0x80070273", "The range could not be added to the range list because of a conflict.")
    #ERROR_SERVER_SID_MISMATCH
    $AMHintsTable.Add("0x80070274", "The server process is running under a SID different than that required by the client.")
    #ERROR_CANT_ENABLE_DENY_ONLY
    $AMHintsTable.Add("0x80070275", "A group marked use for deny only cannot be enabled.")
    #ERROR_FLOAT_MULTIPLE_FAULTS
    $AMHintsTable.Add("0x80070276", "{EXCEPTION} Multiple floating point faults.")
    #ERROR_FLOAT_MULTIPLE_TRAPS
    $AMHintsTable.Add("0x80070277", "{EXCEPTION} Multiple floating point traps.")
    #ERROR_NOINTERFACE
    $AMHintsTable.Add("0x80070278", "The requested interface is not supported.")
    #ERROR_DRIVER_FAILED_SLEEP
    $AMHintsTable.Add("0x80070279", "{System Standby Failed} The driver %hs does not support standby mode. Updating this driver may allow the system to go to standby mode.")
    #ERROR_CORRUPT_SYSTEM_FILE
    $AMHintsTable.Add("0x8007027A", "The system file %1 has become corrupt and has been replaced.")
    #ERROR_COMMITMENT_MINIMUM
    $AMHintsTable.Add("0x8007027B", "{Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications may be denied. For more information, see Help.")
    #ERROR_PNP_RESTART_ENUMERATION
    $AMHintsTable.Add("0x8007027C", "A device was removed so enumeration must be restarted.")
    #ERROR_SYSTEM_IMAGE_BAD_SIGNATURE
    $AMHintsTable.Add("0x8007027D", "{Fatal System Error} The system image %s is not properly signed. The file has been replaced with the signed file. The system has been shut down.")
    #ERROR_PNP_REBOOT_REQUIRED
    $AMHintsTable.Add("0x8007027E", "Device will not start without a reboot.")
    #ERROR_INSUFFICIENT_POWER
    $AMHintsTable.Add("0x8007027F", "There is not enough power to complete the requested operation.")
    #ERROR_SYSTEM_SHUTDOWN
    $AMHintsTable.Add("0x80070281", "The system is in the process of shutting down.")
    #ERROR_PORT_NOT_SET
    $AMHintsTable.Add("0x80070282", "An attempt to remove a process DebugPort was made, but a port was not already associated with the process.")
    #ERROR_DS_VERSION_CHECK_FAILURE
    $AMHintsTable.Add("0x80070283", "This version of Windows is not compatible with the behavior version of directory forest, domain, or domain controller.")
    #ERROR_RANGE_NOT_FOUND
    $AMHintsTable.Add("0x80070284", "The specified range could not be found in the range list.")
    #ERROR_NOT_SAFE_MODE_DRIVER
    $AMHintsTable.Add("0x80070286", "The driver was not loaded because the system is booting into safe mode.")
    #ERROR_FAILED_DRIVER_ENTRY
    $AMHintsTable.Add("0x80070287", "The driver was not loaded because it failed its initialization call.")
    #ERROR_DEVICE_ENUMERATION_ERROR
    $AMHintsTable.Add("0x80070288", "The device encountered an error while applying power or reading the device configuration. This may be caused by a failure of your hardware or by a poor connection.")
    #ERROR_MOUNT_POINT_NOT_RESOLVED
    $AMHintsTable.Add("0x80070289", "The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached.")
    #ERROR_INVALID_DEVICE_OBJECT_PARAMETER
    $AMHintsTable.Add("0x8007028A", "The device object parameter is either not a valid device object or is not attached to the volume specified by the file name.")
    #ERROR_MCA_OCCURED
    $AMHintsTable.Add("0x8007028B", "A machine check error has occurred. Check the system event log for additional information.")
    #ERROR_DRIVER_DATABASE_ERROR
    $AMHintsTable.Add("0x8007028C", "There was an error [%2] processing the driver database.")
    #ERROR_SYSTEM_HIVE_TOO_LARGE
    $AMHintsTable.Add("0x8007028D", "The system hive size has exceeded its limit.")
    #ERROR_DRIVER_FAILED_PRIOR_UNLOAD
    $AMHintsTable.Add("0x8007028E", "The driver could not be loaded because a previous version of the driver is still in memory.")
    #ERROR_VOLSNAP_PREPARE_HIBERNATE
    $AMHintsTable.Add("0x8007028F", "{Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.")
    #ERROR_HIBERNATION_FAILURE
    $AMHintsTable.Add("0x80070290", "The system has failed to hibernate (the error code is %hs). Hibernation will be disabled until the system is restarted.")
    #ERROR_FILE_SYSTEM_LIMITATION
    $AMHintsTable.Add("0x80070299", "The requested operation could not be completed due to a file system limitation.")
    #ERROR_ASSERTION_FAILURE
    $AMHintsTable.Add("0x8007029C", "An assertion failure has occurred.")
    #ERROR_ACPI_ERROR
    $AMHintsTable.Add("0x8007029D", "An error occurred in the Advanced Configuration and Power Interface (ACPI) subsystem.")
    #ERROR_WOW_ASSERTION
    $AMHintsTable.Add("0x8007029E", "WOW assertion error.")
    #ERROR_PNP_BAD_MPS_TABLE
    $AMHintsTable.Add("0x8007029F", "A device is missing in the system BIOS MultiProcessor Specification (MPS) table. This device will not be used. Contact your system vendor for system BIOS update.")
    #ERROR_PNP_TRANSLATION_FAILED
    $AMHintsTable.Add("0x800702A0", "A translator failed to translate resources.")
    #ERROR_PNP_IRQ_TRANSLATION_FAILED
    $AMHintsTable.Add("0x800702A1", "An interrupt request (IRQ) translator failed to translate resources.")
    #ERROR_PNP_INVALID_ID
    $AMHintsTable.Add("0x800702A2", "Driver %2 returned invalid ID for a child device (%3).")
    #ERROR_WAKE_SYSTEM_DEBUGGER
    $AMHintsTable.Add("0x800702A3", "{Kernel Debugger Awakened} the system debugger was awakened by an interrupt.")
    #ERROR_HANDLES_CLOSED
    $AMHintsTable.Add("0x800702A4", "{Handles Closed} Handles to objects have been automatically closed because of the requested operation.")
    #ERROR_EXTRANEOUS_INFORMATION
    $AMHintsTable.Add("0x800702A5", "{Too Much Information} The specified ACL contained more information than was expected.")
    #ERROR_RXACT_COMMIT_NECESSARY
    $AMHintsTable.Add("0x800702A6", "This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed, but it has not been rolled back either (so it may still be committed if desired).")
    #ERROR_MEDIA_CHECK
    $AMHintsTable.Add("0x800702A7", "{Media Changed} The media may have changed.")
    #ERROR_GUID_SUBSTITUTION_MADE
    $AMHintsTable.Add("0x800702A8", "{GUID Substitution} During the translation of a GUID to a Windows SID, no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this may provide more restrictive access than intended.")
    #ERROR_STOPPED_ON_SYMLINK
    $AMHintsTable.Add("0x800702A9", "The create operation stopped after reaching a symbolic link.")
    #ERROR_LONGJUMP
    $AMHintsTable.Add("0x800702AA", "A long jump has been executed.")
    #ERROR_PLUGPLAY_QUERY_VETOED
    $AMHintsTable.Add("0x800702AB", "The Plug and Play query operation was not successful.")
    #ERROR_UNWIND_CONSOLIDATE
    $AMHintsTable.Add("0x800702AC", "A frame consolidation has been executed.")
    #ERROR_REGISTRY_HIVE_RECOVERED
    $AMHintsTable.Add("0x800702AD", "{Registry Hive Recovered} Registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost.")
    #ERROR_DLL_MIGHT_BE_INSECURE
    $AMHintsTable.Add("0x800702AE", "The application is attempting to run executable code from the module %hs. This may be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?")
    #ERROR_DLL_MIGHT_BE_INCOMPATIBLE
    $AMHintsTable.Add("0x800702AF", "The application is loading executable code from the module %hs. This is secure, but may be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?")
    #ERROR_DBG_EXCEPTION_NOT_HANDLED
    $AMHintsTable.Add("0x800702B0", "Debugger did not handle the exception.")
    #ERROR_DBG_REPLY_LATER
    $AMHintsTable.Add("0x800702B1", "Debugger will reply later.")
    #ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE
    $AMHintsTable.Add("0x800702B2", "Debugger cannot provide handle.")
    #ERROR_DBG_TERMINATE_THREAD
    $AMHintsTable.Add("0x800702B3", "Debugger terminated thread.")
    #ERROR_DBG_TERMINATE_PROCESS
    $AMHintsTable.Add("0x800702B4", "Debugger terminated process.")
    #ERROR_DBG_CONTROL_C
    $AMHintsTable.Add("0x800702B5", "Debugger got control C.")
    #ERROR_DBG_PRINTEXCEPTION_C
    $AMHintsTable.Add("0x800702B6", "Debugger printed exception on control C.")
    #ERROR_DBG_RIPEXCEPTION
    $AMHintsTable.Add("0x800702B7", "Debugger received Routing Information Protocol (RIP) exception.")
    #ERROR_DBG_CONTROL_BREAK
    $AMHintsTable.Add("0x800702B8", "Debugger received control break.")
    #ERROR_DBG_COMMAND_EXCEPTION
    $AMHintsTable.Add("0x800702B9", "Debugger command communication exception.")
    #ERROR_OBJECT_NAME_EXISTS
    $AMHintsTable.Add("0x800702BA", "{Object Exists} An attempt was made to create an object and the object name already existed.")
    #ERROR_THREAD_WAS_SUSPENDED
    $AMHintsTable.Add("0x800702BB", "{Thread Suspended} A thread termination occurred while the thread was suspended. The thread was resumed and termination proceeded.")
    #ERROR_IMAGE_NOT_AT_BASE
    $AMHintsTable.Add("0x800702BC", "{Image Relocated} An image file could not be mapped at the address specified in the image file. Local fixes must be performed on this image.")
    #ERROR_RXACT_STATE_CREATED
    $AMHintsTable.Add("0x800702BD", "This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created.")
    #ERROR_SEGMENT_NOTIFICATION
    $AMHintsTable.Add("0x800702BE", "{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments.")
    #ERROR_BAD_CURRENT_DIRECTORY
    $AMHintsTable.Add("0x800702BF", "{Invalid Current Directory} The process cannot switch to the startup current directory %hs. Select OK to set current directory to %hs, or select CANCEL to exit.")
    #ERROR_FT_READ_RECOVERY_FROM_BACKUP
    $AMHintsTable.Add("0x800702C0", "{Redundant Read} To satisfy a read request, the NT fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume, but it was unable to reassign the failing area of the device.")
    #ERROR_FT_WRITE_RECOVERY
    $AMHintsTable.Add("0x800702C1", "{Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume, but it was not able to reassign the failing area of the device.")
    #ERROR_IMAGE_MACHINE_TYPE_MISMATCH
    $AMHintsTable.Add("0x800702C2", "{Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load.")
    #ERROR_RECEIVE_PARTIAL
    $AMHintsTable.Add("0x800702C3", "{Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.")
    #ERROR_RECEIVE_EXPEDITED
    $AMHintsTable.Add("0x800702C4", "{Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.")
    #ERROR_RECEIVE_PARTIAL_EXPEDITED
    $AMHintsTable.Add("0x800702C5", "{Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.")
    #ERROR_EVENT_DONE
    $AMHintsTable.Add("0x800702C6", "{TDI Event Done} The TDI indication has completed successfully.")
    #ERROR_EVENT_PENDING
    $AMHintsTable.Add("0x800702C7", "{TDI Event Pending} The TDI indication has entered the pending state.")
    #ERROR_CHECKING_FILE_SYSTEM
    $AMHintsTable.Add("0x800702C8", "Checking file system on %wZ.")
    #ERROR_FATAL_APP_EXIT
    $AMHintsTable.Add("0x800702C9", "{Fatal Application Exit} %hs.")
    #ERROR_PREDEFINED_HANDLE
    $AMHintsTable.Add("0x800702CA", "The specified registry key is referenced by a predefined handle.")
    #ERROR_WAS_UNLOCKED
    $AMHintsTable.Add("0x800702CB", "{Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.")
    #ERROR_WAS_LOCKED
    $AMHintsTable.Add("0x800702CD", "{Page Locked} One of the pages to lock was already locked.")
    #ERROR_ALREADY_WIN32
    $AMHintsTable.Add("0x800702CF", "The value already corresponds with a Win 32 error code.")
    #ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE
    $AMHintsTable.Add("0x800702D0", "{Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine.")
    #ERROR_NO_YIELD_PERFORMED
    $AMHintsTable.Add("0x800702D1", "A yield execution was performed and no thread was available to run.")
    #ERROR_TIMER_RESUME_IGNORED
    $AMHintsTable.Add("0x800702D2", "The resume flag to a timer API was ignored.")
    #ERROR_ARBITRATION_UNHANDLED
    $AMHintsTable.Add("0x800702D3", "The arbiter has deferred arbitration of these resources to its parent.")
    #ERROR_CARDBUS_NOT_SUPPORTED
    $AMHintsTable.Add("0x800702D4", "The inserted CardBus device cannot be started because of a configuration error on %hs `".`"")
    #ERROR_MP_PROCESSOR_MISMATCH
    $AMHintsTable.Add("0x800702D5", "The CPUs in this multiprocessor system are not all the same revision level. To use all processors the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.")
    #ERROR_HIBERNATED
    $AMHintsTable.Add("0x800702D6", "The system was put into hibernation.")
    #ERROR_RESUME_HIBERNATION
    $AMHintsTable.Add("0x800702D7", "The system was resumed from hibernation.")
    #ERROR_FIRMWARE_UPDATED
    $AMHintsTable.Add("0x800702D8", "Windows has detected that the system firmware (BIOS) was updated (previous firmware date = %2, current firmware date %3).")
    #ERROR_DRIVERS_LEAKING_LOCKED_PAGES
    $AMHintsTable.Add("0x800702D9", "A device driver is leaking locked I/O pages, causing system degradation. The system has automatically enabled a tracking code to try and catch the culprit.")
    #ERROR_WAKE_SYSTEM
    $AMHintsTable.Add("0x800702DA", "The system has awoken.")
    #ERROR_ABANDONED_WAIT_0
    $AMHintsTable.Add("0x800702DF", "The call failed because the handle associated with it was closed.")
    #ERROR_ELEVATION_REQUIRED
    $AMHintsTable.Add("0x800702E4", "The requested operation requires elevation.")
    #ERROR_REPARSE
    $AMHintsTable.Add("0x800702E5", "A reparse should be performed by the object manager because the name of the file resulted in a symbolic link.")
    #ERROR_OPLOCK_BREAK_IN_PROGRESS
    $AMHintsTable.Add("0x800702E6", "An open/create operation completed while an oplock break is underway.")
    #ERROR_VOLUME_MOUNTED
    $AMHintsTable.Add("0x800702E7", "A new volume has been mounted by a file system.")
    #ERROR_RXACT_COMMITTED
    $AMHintsTable.Add("0x800702E8", "This success level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has now been completed.")
    #ERROR_NOTIFY_CLEANUP
    $AMHintsTable.Add("0x800702E9", "This indicates that a notify change request has been completed due to closing the handle which made the notify change request.")
    #ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED
    $AMHintsTable.Add("0x800702EA", "{Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed. The computer was able to connect on a secondary transport.")
    #ERROR_PAGE_FAULT_TRANSITION
    $AMHintsTable.Add("0x800702EB", "Page fault was a transition fault.")
    #ERROR_PAGE_FAULT_DEMAND_ZERO
    $AMHintsTable.Add("0x800702EC", "Page fault was a demand zero fault.")
    #ERROR_PAGE_FAULT_COPY_ON_WRITE
    $AMHintsTable.Add("0x800702ED", "Page fault was a demand zero fault.")
    #ERROR_PAGE_FAULT_GUARD_PAGE
    $AMHintsTable.Add("0x800702EE", "Page fault was a demand zero fault.")
    #ERROR_PAGE_FAULT_PAGING_FILE
    $AMHintsTable.Add("0x800702EF", "Page fault was satisfied by reading from a secondary storage device.")
    #ERROR_CACHE_PAGE_LOCKED
    $AMHintsTable.Add("0x800702F0", "Cached page was locked during operation.")
    #ERROR_CRASH_DUMP
    $AMHintsTable.Add("0x800702F1", "Crash dump exists in paging file.")
    #ERROR_BUFFER_ALL_ZEROS
    $AMHintsTable.Add("0x800702F2", "Specified buffer contains all zeros.")
    #ERROR_REPARSE_OBJECT
    $AMHintsTable.Add("0x800702F3", "A reparse should be performed by the object manager because the name of the file resulted in a symbolic link.")
    #ERROR_RESOURCE_REQUIREMENTS_CHANGED
    $AMHintsTable.Add("0x800702F4", "The device has succeeded a query-stop and its resource requirements have changed.")
    #ERROR_TRANSLATION_COMPLETE
    $AMHintsTable.Add("0x800702F5", "The translator has translated these resources into the global space and no further translations should be performed.")
    #ERROR_NOTHING_TO_TERMINATE
    $AMHintsTable.Add("0x800702F6", "A process being terminated has no threads to terminate.")
    #ERROR_PROCESS_NOT_IN_JOB
    $AMHintsTable.Add("0x800702F7", "The specified process is not part of a job.")
    #ERROR_PROCESS_IN_JOB
    $AMHintsTable.Add("0x800702F8", "The specified process is part of a job.")
    #ERROR_VOLSNAP_HIBERNATE_READY
    $AMHintsTable.Add("0x800702F9", "{Volume Shadow Copy Service} The system is now ready for hibernation.")
    #ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY
    $AMHintsTable.Add("0x800702FA", "A file system or file system filter driver has successfully completed an FsFilter operation.")
    #ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED
    $AMHintsTable.Add("0x800702FB", "The specified interrupt vector was already connected.")
    #ERROR_INTERRUPT_STILL_CONNECTED
    $AMHintsTable.Add("0x800702FC", "The specified interrupt vector is still connected.")
    #ERROR_WAIT_FOR_OPLOCK
    $AMHintsTable.Add("0x800702FD", "An operation is blocked waiting for an oplock.")
    #ERROR_DBG_EXCEPTION_HANDLED
    $AMHintsTable.Add("0x800702FE", "Debugger handled exception.")
    #ERROR_DBG_CONTINUE
    $AMHintsTable.Add("0x800702FF", "Debugger continued.")
    #ERROR_CALLBACK_POP_STACK
    $AMHintsTable.Add("0x80070300", "An exception occurred in a user mode callback and the kernel callback frame should be removed.")
    #ERROR_COMPRESSION_DISABLED
    $AMHintsTable.Add("0x80070301", "Compression is disabled for this volume.")
    #ERROR_CANTFETCHBACKWARDS
    $AMHintsTable.Add("0x80070302", "The data provider cannot fetch backward through a result set.")
    #ERROR_CANTSCROLLBACKWARDS
    $AMHintsTable.Add("0x80070303", "The data provider cannot scroll backward through a result set.")
    #ERROR_ROWSNOTRELEASED
    $AMHintsTable.Add("0x80070304", "The data provider requires that previously fetched data is released before asking for more data.")
    #ERROR_BAD_ACCESSOR_FLAGS
    $AMHintsTable.Add("0x80070305", "The data provider was not able to interpret the flags set for a column binding in an accessor.")
    #ERROR_ERRORS_ENCOUNTERED
    $AMHintsTable.Add("0x80070306", "One or more errors occurred while processing the request.")
    #ERROR_NOT_CAPABLE
    $AMHintsTable.Add("0x80070307", "The implementation is not capable of performing the request.")
    #ERROR_REQUEST_OUT_OF_SEQUENCE
    $AMHintsTable.Add("0x80070308", "The client of a component requested an operation that is not valid given the state of the component instance.")
    #ERROR_VERSION_PARSE_ERROR
    $AMHintsTable.Add("0x80070309", "A version number could not be parsed.")
    #ERROR_BADSTARTPOSITION
    $AMHintsTable.Add("0x8007030A", "The iterator's start position is invalid.")
    #ERROR_MEMORY_HARDWARE
    $AMHintsTable.Add("0x8007030B", "The hardware has reported an uncorrectable memory error.")
    #ERROR_DISK_REPAIR_DISABLED
    $AMHintsTable.Add("0x8007030C", "The attempted operation required self-healing to be enabled.")
    #ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE
    $AMHintsTable.Add("0x8007030D", "The Desktop heap encountered an error while allocating session memory. There is more information in the system event log.")
    #ERROR_SYSTEM_POWERSTATE_TRANSITION
    $AMHintsTable.Add("0x8007030E", "The system power state is transitioning from %2 to %3.")
    #ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION
    $AMHintsTable.Add("0x8007030F", "The system power state is transitioning from %2 to %3 but could enter %4.")
    #ERROR_MCA_EXCEPTION
    $AMHintsTable.Add("0x80070310", "A thread is getting dispatched with MCA EXCEPTION because of MCA.")
    #ERROR_ACCESS_AUDIT_BY_POLICY
    $AMHintsTable.Add("0x80070311", "Access to %1 is monitored by policy rule %2.")
    #ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY
    $AMHintsTable.Add("0x80070312", "Access to %1 has been restricted by your administrator by policy rule %2.")
    #ERROR_ABANDON_HIBERFILE
    $AMHintsTable.Add("0x80070313", "A valid hibernation file has been invalidated and should be abandoned.")
    #ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED
    $AMHintsTable.Add("0x80070314", "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused by network connectivity issues. Try to save this file elsewhere.")
    #ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR
    $AMHintsTable.Add("0x80070315", "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error was returned by the server on which the file exists. Try to save this file elsewhere.")
    #ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR
    $AMHintsTable.Add("0x80070316", "{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused if the device has been removed or the media is write-protected.")
    #ERROR_EA_ACCESS_DENIED
    $AMHintsTable.Add("0x800703E2", "Access to the extended attribute was denied.")
    #ERROR_OPERATION_ABORTED
    $AMHintsTable.Add("0x800703E3", "The I/O operation has been aborted because of either a thread exit or an application request.")
    #ERROR_IO_INCOMPLETE
    $AMHintsTable.Add("0x800703E4", "Overlapped I/O event is not in a signaled state.")
    #ERROR_IO_PENDING
    $AMHintsTable.Add("0x800703E5", "Overlapped I/O operation is in progress.")
    #ERROR_NOACCESS
    $AMHintsTable.Add("0x800703E6", "Invalid access to memory location.")
    #ERROR_SWAPERROR
    $AMHintsTable.Add("0x800703E7", "Error performing in-page operation.")
    #ERROR_STACK_OVERFLOW
    $AMHintsTable.Add("0x800703E9", "Recursion too deep; the stack overflowed.")
    #ERROR_INVALID_MESSAGE
    $AMHintsTable.Add("0x800703EA", "The window cannot act on the sent message.")
    #ERROR_CAN_NOT_COMPLETE
    $AMHintsTable.Add("0x800703EB", "Cannot complete this function.")
    #ERROR_INVALID_FLAGS
    $AMHintsTable.Add("0x800703EC", "Invalid flags.")
    #ERROR_UNRECOGNIZED_VOLUME
    $AMHintsTable.Add("0x800703ED", "The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupted.")
    #ERROR_FILE_INVALID
    $AMHintsTable.Add("0x800703EE", "The volume for a file has been externally altered so that the opened file is no longer valid.")
    #ERROR_FULLSCREEN_MODE
    $AMHintsTable.Add("0x800703EF", "The requested operation cannot be performed in full-screen mode.")
    #ERROR_NO_TOKEN
    $AMHintsTable.Add("0x800703F0", "An attempt was made to reference a token that does not exist.")
    #ERROR_BADDB
    $AMHintsTable.Add("0x800703F1", "The configuration registry database is corrupt.")
    #ERROR_BADKEY
    $AMHintsTable.Add("0x800703F2", "The configuration registry key is invalid.")
    #ERROR_CANTOPEN
    $AMHintsTable.Add("0x800703F3", "The configuration registry key could not be opened.")
    #ERROR_CANTREAD
    $AMHintsTable.Add("0x800703F4", "The configuration registry key could not be read.")
    #ERROR_CANTWRITE
    $AMHintsTable.Add("0x800703F5", "The configuration registry key could not be written.")
    #ERROR_REGISTRY_RECOVERED
    $AMHintsTable.Add("0x800703F6", "One of the files in the registry database had to be recovered by use of a log or alternate copy. The recovery was successful.")
    #ERROR_REGISTRY_CORRUPT
    $AMHintsTable.Add("0x800703F7", "The registry is corrupted. The structure of one of the files containing registry data is corrupted, or the system's memory image of the file is corrupted, or the file could not be recovered because the alternate copy or log was absent or corrupted.")
    #ERROR_REGISTRY_IO_FAILED
    $AMHintsTable.Add("0x800703F8", "An I/O operation initiated by the registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry.")
    #ERROR_NOT_REGISTRY_FILE
    $AMHintsTable.Add("0x800703F9", "The system attempted to load or restore a file into the registry, but the specified file is not in a registry file format.")
    #ERROR_KEY_DELETED
    $AMHintsTable.Add("0x800703FA", "Illegal operation attempted on a registry key that has been marked for deletion.")
    #ERROR_NO_LOG_SPACE
    $AMHintsTable.Add("0x800703FB", "System could not allocate the required space in a registry log.")
    #ERROR_KEY_HAS_CHILDREN
    $AMHintsTable.Add("0x800703FC", "Cannot create a symbolic link in a registry key that already has subkeys or values.")
    #ERROR_CHILD_MUST_BE_VOLATILE
    $AMHintsTable.Add("0x800703FD", "Cannot create a stable subkey under a volatile parent key.")
    #ERROR_NOTIFY_ENUM_DIR
    $AMHintsTable.Add("0x800703FE", "A notify change request is being completed and the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.")
    #ERROR_DEPENDENT_SERVICES_RUNNING
    $AMHintsTable.Add("0x8007041B", "A stop control has been sent to a service that other running services are dependent on.")
    #ERROR_INVALID_SERVICE_CONTROL
    $AMHintsTable.Add("0x8007041C", "The requested control is not valid for this service.")
    #ERROR_SERVICE_REQUEST_TIMEOUT
    $AMHintsTable.Add("0x8007041D", "The service did not respond to the start or control request in a timely fashion.")
    #ERROR_SERVICE_NO_THREAD
    $AMHintsTable.Add("0x8007041E", "A thread could not be created for the service.")
    #ERROR_SERVICE_DATABASE_LOCKED
    $AMHintsTable.Add("0x8007041F", "The service database is locked.")
    #ERROR_SERVICE_ALREADY_RUNNING
    $AMHintsTable.Add("0x80070420", "An instance of the service is already running.")
    #ERROR_INVALID_SERVICE_ACCOUNT
    $AMHintsTable.Add("0x80070421", "The account name is invalid or does not exist, or the password is invalid for the account name specified.")
    #ERROR_SERVICE_DISABLED
    $AMHintsTable.Add("0x80070422", "The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.")
    #ERROR_CIRCULAR_DEPENDENCY
    $AMHintsTable.Add("0x80070423", "Circular service dependency was specified.")
    #ERROR_SERVICE_DOES_NOT_EXIST
    $AMHintsTable.Add("0x80070424", "The specified service does not exist as an installed service.")
    #ERROR_SERVICE_CANNOT_ACCEPT_CTRL
    $AMHintsTable.Add("0x80070425", "The service cannot accept control messages at this time.")
    #ERROR_SERVICE_NOT_ACTIVE
    $AMHintsTable.Add("0x80070426", "The service has not been started.")
    #ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
    $AMHintsTable.Add("0x80070427", "The service process could not connect to the service controller.")
    #ERROR_EXCEPTION_IN_SERVICE
    $AMHintsTable.Add("0x80070428", "An exception occurred in the service when handling the control request.")
    #ERROR_DATABASE_DOES_NOT_EXIST
    $AMHintsTable.Add("0x80070429", "The database specified does not exist.")
    #ERROR_SERVICE_SPECIFIC_ERROR
    $AMHintsTable.Add("0x8007042A", "The service has returned a service-specific error code.")
    #ERROR_PROCESS_ABORTED
    $AMHintsTable.Add("0x8007042B", "The process terminated unexpectedly.")
    #ERROR_SERVICE_DEPENDENCY_FAIL
    $AMHintsTable.Add("0x8007042C", "The dependency service or group failed to start.")
    #ERROR_SERVICE_LOGON_FAILED
    $AMHintsTable.Add("0x8007042D", "The service did not start due to a logon failure.")
    #ERROR_SERVICE_START_HANG
    $AMHintsTable.Add("0x8007042E", "After starting, the service hung in a start-pending state.")
    #ERROR_INVALID_SERVICE_LOCK
    $AMHintsTable.Add("0x8007042F", "The specified service database lock is invalid.")
    #ERROR_SERVICE_MARKED_FOR_DELETE
    $AMHintsTable.Add("0x80070430", "The specified service has been marked for deletion.")
    #ERROR_SERVICE_EXISTS
    $AMHintsTable.Add("0x80070431", "The specified service already exists.")
    #ERROR_ALREADY_RUNNING_LKG
    $AMHintsTable.Add("0x80070432", "The system is currently running with the last-known-good configuration.")
    #ERROR_SERVICE_DEPENDENCY_DELETED
    $AMHintsTable.Add("0x80070433", "The dependency service does not exist or has been marked for deletion.")
    #ERROR_BOOT_ALREADY_ACCEPTED
    $AMHintsTable.Add("0x80070434", "The current boot has already been accepted for use as the last-known-good control set.")
    #ERROR_SERVICE_NEVER_STARTED
    $AMHintsTable.Add("0x80070435", "No attempts to start the service have been made since the last boot.")
    #ERROR_DUPLICATE_SERVICE_NAME
    $AMHintsTable.Add("0x80070436", "The name is already in use as either a service name or a service display name.")
    #ERROR_DIFFERENT_SERVICE_ACCOUNT
    $AMHintsTable.Add("0x80070437", "The account specified for this service is different from the account specified for other services running in the same process.")
    #ERROR_CANNOT_DETECT_DRIVER_FAILURE
    $AMHintsTable.Add("0x80070438", "Failure actions can only be set for Win32 services, not for drivers.")
    #ERROR_CANNOT_DETECT_PROCESS_ABORT
    $AMHintsTable.Add("0x80070439", "This service runs in the same process as the service control manager. Therefore, the service control manager cannot take action if this service's process terminates unexpectedly.")
    #ERROR_NO_RECOVERY_PROGRAM
    $AMHintsTable.Add("0x8007043A", "No recovery program has been configured for this service.")
    #ERROR_SERVICE_NOT_IN_EXE
    $AMHintsTable.Add("0x8007043B", "The executable program that this service is configured to run in does not implement the service.")
    #ERROR_NOT_SAFEBOOT_SERVICE
    $AMHintsTable.Add("0x8007043C", "This service cannot be started in Safe Mode.")
    #ERROR_END_OF_MEDIA
    $AMHintsTable.Add("0x8007044C", "The physical end of the tape has been reached.")
    #ERROR_FILEMARK_DETECTED
    $AMHintsTable.Add("0x8007044D", "A tape access reached a filemark.")
    #ERROR_BEGINNING_OF_MEDIA
    $AMHintsTable.Add("0x8007044E", "The beginning of the tape or a partition was encountered.")
    #ERROR_SETMARK_DETECTED
    $AMHintsTable.Add("0x8007044F", "A tape access reached the end of a set of files.")
    #ERROR_NO_DATA_DETECTED
    $AMHintsTable.Add("0x80070450", "No more data is on the tape.")
    #ERROR_PARTITION_FAILURE
    $AMHintsTable.Add("0x80070451", "Tape could not be partitioned.")
    #ERROR_INVALID_BLOCK_LENGTH
    $AMHintsTable.Add("0x80070452", "When accessing a new tape of a multivolume partition, the current block size is incorrect.")
    #ERROR_DEVICE_NOT_PARTITIONED
    $AMHintsTable.Add("0x80070453", "Tape partition information could not be found when loading a tape.")
    #ERROR_UNABLE_TO_LOCK_MEDIA
    $AMHintsTable.Add("0x80070454", "Unable to lock the media eject mechanism.")
    #ERROR_UNABLE_TO_UNLOAD_MEDIA
    $AMHintsTable.Add("0x80070455", "Unable to unload the media.")
    #ERROR_MEDIA_CHANGED
    $AMHintsTable.Add("0x80070456", "The media in the drive may have changed.")
    #ERROR_BUS_RESET
    $AMHintsTable.Add("0x80070457", "The I/O bus was reset.")
    #ERROR_NO_MEDIA_IN_DRIVE
    $AMHintsTable.Add("0x80070458", "No media in drive.")
    #ERROR_NO_UNICODE_TRANSLATION
    $AMHintsTable.Add("0x80070459", "No mapping for the Unicode character exists in the target multibyte code page.")
    #ERROR_DLL_INIT_FAILED
    $AMHintsTable.Add("0x8007045A", "A DLL initialization routine failed.")
    #ERROR_SHUTDOWN_IN_PROGRESS
    $AMHintsTable.Add("0x8007045B", "A system shutdown is in progress.")
    #ERROR_NO_SHUTDOWN_IN_PROGRESS
    $AMHintsTable.Add("0x8007045C", "Unable to abort the system shutdown because no shutdown was in progress.")
    #ERROR_IO_DEVICE
    $AMHintsTable.Add("0x8007045D", "The request could not be performed because of an I/O device error.")
    #ERROR_SERIAL_NO_DEVICE
    $AMHintsTable.Add("0x8007045E", "No serial device was successfully initialized. The serial driver will unload.")
    #ERROR_IRQ_BUSY
    $AMHintsTable.Add("0x8007045F", "Unable to open a device that was sharing an IRQ with other devices. At least one other device that uses that IRQ was already opened.")
    #ERROR_MORE_WRITES
    $AMHintsTable.Add("0x80070460", "A serial I/O operation was completed by another write to the serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)")
    #ERROR_COUNTER_TIMEOUT
    $AMHintsTable.Add("0x80070461", "A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER did not reach zero.)")
    #ERROR_FLOPPY_ID_MARK_NOT_FOUND
    $AMHintsTable.Add("0x80070462", "No ID address mark was found on the floppy disk.")
    #ERROR_FLOPPY_WRONG_CYLINDER
    $AMHintsTable.Add("0x80070463", "Mismatch between the floppy disk sector ID field and the floppy disk controller track address.")
    #ERROR_FLOPPY_UNKNOWN_ERROR
    $AMHintsTable.Add("0x80070464", "The floppy disk controller reported an error that is not recognized by the floppy disk driver.")
    #ERROR_FLOPPY_BAD_REGISTERS
    $AMHintsTable.Add("0x80070465", "The floppy disk controller returned inconsistent results in its registers.")
    #ERROR_DISK_RECALIBRATE_FAILED
    $AMHintsTable.Add("0x80070466", "While accessing the hard disk, a recalibrate operation failed, even after retries.")
    #ERROR_DISK_OPERATION_FAILED
    $AMHintsTable.Add("0x80070467", "While accessing the hard disk, a disk operation failed even after retries.")
    #ERROR_DISK_RESET_FAILED
    $AMHintsTable.Add("0x80070468", "While accessing the hard disk, a disk controller reset was needed, but that also failed.")
    #ERROR_EOM_OVERFLOW
    $AMHintsTable.Add("0x80070469", "Physical end of tape encountered.")
    #ERROR_NOT_ENOUGH_SERVER_MEMORY
    $AMHintsTable.Add("0x8007046A", "Not enough server storage is available to process this command.")
    #ERROR_POSSIBLE_DEADLOCK
    $AMHintsTable.Add("0x8007046B", "A potential deadlock condition has been detected.")
    #ERROR_MAPPED_ALIGNMENT
    $AMHintsTable.Add("0x8007046C", "The base address or the file offset specified does not have the proper alignment.")
    #ERROR_SET_POWER_STATE_VETOED
    $AMHintsTable.Add("0x80070474", "An attempt to change the system power state was vetoed by another application or driver.")
    #ERROR_SET_POWER_STATE_FAILED
    $AMHintsTable.Add("0x80070475", "The system BIOS failed an attempt to change the system power state.")
    #ERROR_TOO_MANY_LINKS
    $AMHintsTable.Add("0x80070476", "An attempt was made to create more links on a file than the file system supports.")
    #ERROR_OLD_WIN_VERSION
    $AMHintsTable.Add("0x8007047E", "The specified program requires a newer version of Windows.")
    #ERROR_APP_WRONG_OS
    $AMHintsTable.Add("0x8007047F", "The specified program is not a Windows or MS-DOS program.")
    #ERROR_SINGLE_INSTANCE_APP
    $AMHintsTable.Add("0x80070480", "Cannot start more than one instance of the specified program.")
    #ERROR_RMODE_APP
    $AMHintsTable.Add("0x80070481", "The specified program was written for an earlier version of Windows.")
    #ERROR_INVALID_DLL
    $AMHintsTable.Add("0x80070482", "One of the library files needed to run this application is damaged.")
    #ERROR_NO_ASSOCIATION
    $AMHintsTable.Add("0x80070483", "No application is associated with the specified file for this operation.")
    #ERROR_DDE_FAIL
    $AMHintsTable.Add("0x80070484", "An error occurred in sending the command to the application.")
    #ERROR_DLL_NOT_FOUND
    $AMHintsTable.Add("0x80070485", "One of the library files needed to run this application cannot be found.")
    #ERROR_NO_MORE_USER_HANDLES
    $AMHintsTable.Add("0x80070486", "The current process has used all of its system allowance of handles for Windows manager objects.")
    #ERROR_MESSAGE_SYNC_ONLY
    $AMHintsTable.Add("0x80070487", "The message can be used only with synchronous operations.")
    #ERROR_SOURCE_ELEMENT_EMPTY
    $AMHintsTable.Add("0x80070488", "The indicated source element has no media.")
    #ERROR_DESTINATION_ELEMENT_FULL
    $AMHintsTable.Add("0x80070489", "The indicated destination element already contains media.")
    #ERROR_ILLEGAL_ELEMENT_ADDRESS
    $AMHintsTable.Add("0x8007048A", "The indicated element does not exist.")
    #ERROR_MAGAZINE_NOT_PRESENT
    $AMHintsTable.Add("0x8007048B", "The indicated element is part of a magazine that is not present.")
    #ERROR_DEVICE_REINITIALIZATION_NEEDED
    $AMHintsTable.Add("0x8007048C", "The indicated device requires re-initialization due to hardware errors.")
    #ERROR_DEVICE_REQUIRES_CLEANING
    $AMHintsTable.Add("0x8007048D", "The device has indicated that cleaning is required before further operations are attempted.")
    #ERROR_DEVICE_DOOR_OPEN
    $AMHintsTable.Add("0x8007048E", "The device has indicated that its door is open.")
    #ERROR_DEVICE_NOT_CONNECTED
    $AMHintsTable.Add("0x8007048F", "The device is not connected.")
    #ERROR_NOT_FOUND
    $AMHintsTable.Add("0x80070490", "Element not found.")
    #ERROR_NO_MATCH
    $AMHintsTable.Add("0x80070491", "There was no match for the specified key in the index.")
    #ERROR_SET_NOT_FOUND
    $AMHintsTable.Add("0x80070492", "The property set specified does not exist on the object.")
    #ERROR_POINT_NOT_FOUND
    $AMHintsTable.Add("0x80070493", "The point passed to GetMouseMovePoints is not in the buffer.")
    #ERROR_NO_TRACKING_SERVICE
    $AMHintsTable.Add("0x80070494", "The tracking (workstation) service is not running.")
    #ERROR_NO_VOLUME_ID
    $AMHintsTable.Add("0x80070495", "The volume ID could not be found.")
    #ERROR_UNABLE_TO_REMOVE_REPLACED
    $AMHintsTable.Add("0x80070497", "Unable to remove the file to be replaced.")
    #ERROR_UNABLE_TO_MOVE_REPLACEMENT
    $AMHintsTable.Add("0x80070498", "Unable to move the replacement file to the file to be replaced. The file to be replaced has retained its original name.")
    #ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
    $AMHintsTable.Add("0x80070499", "Unable to move the replacement file to the file to be replaced. The file to be replaced has been renamed using the backup name.")
    #ERROR_JOURNAL_DELETE_IN_PROGRESS
    $AMHintsTable.Add("0x8007049A", "The volume change journal is being deleted.")
    #ERROR_JOURNAL_NOT_ACTIVE
    $AMHintsTable.Add("0x8007049B", "The volume change journal is not active.")
    #ERROR_POTENTIAL_FILE_FOUND
    $AMHintsTable.Add("0x8007049C", "A file was found, but it may not be the correct file.")
    #ERROR_JOURNAL_ENTRY_DELETED
    $AMHintsTable.Add("0x8007049D", "The journal entry has been deleted from the journal.")
    #ERROR_SHUTDOWN_IS_SCHEDULED
    $AMHintsTable.Add("0x800704A6", "A system shutdown has already been scheduled.")
    #ERROR_SHUTDOWN_USERS_LOGGED_ON
    $AMHintsTable.Add("0x800704A7", "The system shutdown cannot be initiated because there are other users logged on to the computer.")
    #ERROR_BAD_DEVICE
    $AMHintsTable.Add("0x800704B0", "The specified device name is invalid.")
    #ERROR_CONNECTION_UNAVAIL
    $AMHintsTable.Add("0x800704B1", "The device is not currently connected but it is a remembered connection.")
    #ERROR_DEVICE_ALREADY_REMEMBERED
    $AMHintsTable.Add("0x800704B2", "The local device name has a remembered connection to another network resource.")
    #ERROR_NO_NET_OR_BAD_PATH
    $AMHintsTable.Add("0x800704B3", "The network path was either typed incorrectly, does not exist, or the network provider is not currently available. Try retyping the path or contact your network administrator.")
    #ERROR_BAD_PROVIDER
    $AMHintsTable.Add("0x800704B4", "The specified network provider name is invalid.")
    #ERROR_CANNOT_OPEN_PROFILE
    $AMHintsTable.Add("0x800704B5", "Unable to open the network connection profile.")
    #ERROR_BAD_PROFILE
    $AMHintsTable.Add("0x800704B6", "The network connection profile is corrupted.")
    #ERROR_NOT_CONTAINER
    $AMHintsTable.Add("0x800704B7", "Cannot enumerate a noncontainer.")
    #ERROR_EXTENDED_ERROR
    $AMHintsTable.Add("0x800704B8", "An extended error has occurred.")
    #ERROR_INVALID_GROUPNAME
    $AMHintsTable.Add("0x800704B9", "The format of the specified group name is invalid.")
    #ERROR_INVALID_COMPUTERNAME
    $AMHintsTable.Add("0x800704BA", "The format of the specified computer name is invalid.")
    #ERROR_INVALID_EVENTNAME
    $AMHintsTable.Add("0x800704BB", "The format of the specified event name is invalid.")
    #ERROR_INVALID_DOMAINNAME
    $AMHintsTable.Add("0x800704BC", "The format of the specified domain name is invalid.")
    #ERROR_INVALID_SERVICENAME
    $AMHintsTable.Add("0x800704BD", "The format of the specified service name is invalid.")
    #ERROR_INVALID_NETNAME
    $AMHintsTable.Add("0x800704BE", "The format of the specified network name is invalid.")
    #ERROR_INVALID_SHARENAME
    $AMHintsTable.Add("0x800704BF", "The format of the specified share name is invalid.")
    #ERROR_INVALID_PASSWORDNAME
    $AMHintsTable.Add("0x800704C0", "The format of the specified password is invalid.")
    #ERROR_INVALID_MESSAGENAME
    $AMHintsTable.Add("0x800704C1", "The format of the specified message name is invalid.")
    #ERROR_INVALID_MESSAGEDEST
    $AMHintsTable.Add("0x800704C2", "The format of the specified message destination is invalid.")
    #ERROR_SESSION_CREDENTIAL_CONFLICT
    $AMHintsTable.Add("0x800704C3", "Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again.")
    #ERROR_REMOTE_SESSION_LIMIT_EXCEEDED
    $AMHintsTable.Add("0x800704C4", "An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.")
    #ERROR_DUP_DOMAINNAME
    $AMHintsTable.Add("0x800704C5", "The workgroup or domain name is already in use by another computer on the network.")
    #ERROR_NO_NETWORK
    $AMHintsTable.Add("0x800704C6", "The network is not present or not started.")
    #ERROR_CANCELLED
    $AMHintsTable.Add("0x800704C7", "The operation was canceled by the user.")
    #ERROR_USER_MAPPED_FILE
    $AMHintsTable.Add("0x800704C8", "The requested operation cannot be performed on a file with a user-mapped section open.")
    #ERROR_CONNECTION_REFUSED
    $AMHintsTable.Add("0x800704C9", "The remote system refused the network connection.")
    #ERROR_GRACEFUL_DISCONNECT
    $AMHintsTable.Add("0x800704CA", "The network connection was gracefully closed.")
    #ERROR_ADDRESS_ALREADY_ASSOCIATED
    $AMHintsTable.Add("0x800704CB", "The network transport endpoint already has an address associated with it.")
    #ERROR_ADDRESS_NOT_ASSOCIATED
    $AMHintsTable.Add("0x800704CC", "An address has not yet been associated with the network endpoint.")
    #ERROR_CONNECTION_INVALID
    $AMHintsTable.Add("0x800704CD", "An operation was attempted on a nonexistent network connection.")
    #ERROR_CONNECTION_ACTIVE
    $AMHintsTable.Add("0x800704CE", "An invalid operation was attempted on an active network connection.")
    #ERROR_NETWORK_UNREACHABLE
    $AMHintsTable.Add("0x800704CF", "The network location cannot be reached. For information about network troubleshooting, see Windows Help.")
    #ERROR_HOST_UNREACHABLE
    $AMHintsTable.Add("0x800704D0", "The network location cannot be reached. For information about network troubleshooting, see Windows Help.")
    #ERROR_PROTOCOL_UNREACHABLE
    $AMHintsTable.Add("0x800704D1", "The network location cannot be reached. For information about network troubleshooting, see Windows Help.")
    #ERROR_PORT_UNREACHABLE
    $AMHintsTable.Add("0x800704D2", "No service is operating at the destination network endpoint on the remote system.")
    #ERROR_REQUEST_ABORTED
    $AMHintsTable.Add("0x800704D3", "The request was aborted.")
    #ERROR_CONNECTION_ABORTED
    $AMHintsTable.Add("0x800704D4", "The network connection was aborted by the local system.")
    #ERROR_RETRY
    $AMHintsTable.Add("0x800704D5", "The operation could not be completed. A retry should be performed.")
    #ERROR_CONNECTION_COUNT_LIMIT
    $AMHintsTable.Add("0x800704D6", "A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.")
    #ERROR_LOGIN_TIME_RESTRICTION
    $AMHintsTable.Add("0x800704D7", "Attempting to log on during an unauthorized time of day for this account.")
    #ERROR_LOGIN_WKSTA_RESTRICTION
    $AMHintsTable.Add("0x800704D8", "The account is not authorized to log on from this station.")
    #ERROR_INCORRECT_ADDRESS
    $AMHintsTable.Add("0x800704D9", "The network address could not be used for the operation requested.")
    #ERROR_ALREADY_REGISTERED
    $AMHintsTable.Add("0x800704DA", "The service is already registered.")
    #ERROR_SERVICE_NOT_FOUND
    $AMHintsTable.Add("0x800704DB", "The specified service does not exist.")
    #ERROR_NOT_AUTHENTICATED
    $AMHintsTable.Add("0x800704DC", "The operation being requested was not performed because the user has not been authenticated.")
    #ERROR_NOT_LOGGED_ON
    $AMHintsTable.Add("0x800704DD", "The operation being requested was not performed because the user has not logged on to the network. The specified service does not exist.")
    #ERROR_CONTINUE
    $AMHintsTable.Add("0x800704DE", "Continue with work in progress.")
    #ERROR_ALREADY_INITIALIZED
    $AMHintsTable.Add("0x800704DF", "An attempt was made to perform an initialization operation when initialization has already been completed.")
    #ERROR_NO_MORE_DEVICES
    $AMHintsTable.Add("0x800704E0", "No more local devices.")
    #ERROR_NO_SUCH_SITE
    $AMHintsTable.Add("0x800704E1", "The specified site does not exist.")
    #ERROR_DOMAIN_CONTROLLER_EXISTS
    $AMHintsTable.Add("0x800704E2", "A domain controller with the specified name already exists.")
    #ERROR_ONLY_IF_CONNECTED
    $AMHintsTable.Add("0x800704E3", "This operation is supported only when you are connected to the server.")
    #ERROR_OVERRIDE_NOCHANGES
    $AMHintsTable.Add("0x800704E4", "The group policy framework should call the extension even if there are no changes.")
    #ERROR_BAD_USER_PROFILE
    $AMHintsTable.Add("0x800704E5", "The specified user does not have a valid profile.")
    #ERROR_NOT_SUPPORTED_ON_SBS
    $AMHintsTable.Add("0x800704E6", "This operation is not supported on a computer running Windows Server 2003 for Small Business Server.")
    #ERROR_SERVER_SHUTDOWN_IN_PROGRESS
    $AMHintsTable.Add("0x800704E7", "The server machine is shutting down.")
    #ERROR_HOST_DOWN
    $AMHintsTable.Add("0x800704E8", "The remote system is not available. For information about network troubleshooting, see Windows Help.")
    #ERROR_NON_ACCOUNT_SID
    $AMHintsTable.Add("0x800704E9", "The security identifier provided is not from an account domain.")
    #ERROR_NON_DOMAIN_SID
    $AMHintsTable.Add("0x800704EA", "The security identifier provided does not have a domain component.")
    #ERROR_APPHELP_BLOCK
    $AMHintsTable.Add("0x800704EB", "AppHelp dialog canceled, thus preventing the application from starting.")
    #ERROR_ACCESS_DISABLED_BY_POLICY
    $AMHintsTable.Add("0x800704EC", "This program is blocked by Group Policy. For more information, contact your system administrator.")
    #ERROR_REG_NAT_CONSUMPTION
    $AMHintsTable.Add("0x800704ED", "A program attempt to use an invalid register value. Normally caused by an uninitialized register. This error is Itanium specific.")
    #ERROR_CSCSHARE_OFFLINE
    $AMHintsTable.Add("0x800704EE", "The share is currently offline or does not exist.")
    #ERROR_PKINIT_FAILURE
    $AMHintsTable.Add("0x800704EF", "The Kerberos protocol encountered an error while validating the KDC certificate during smartcard logon. There is more information in the system event log.")
    #ERROR_SMARTCARD_SUBSYSTEM_FAILURE
    $AMHintsTable.Add("0x800704F0", "The Kerberos protocol encountered an error while attempting to utilize the smartcard subsystem.")
    #ERROR_DOWNGRADE_DETECTED
    $AMHintsTable.Add("0x800704F1", "The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.")
    #ERROR_MACHINE_LOCKED
    $AMHintsTable.Add("0x800704F7", "The machine is locked and cannot be shut down without the force option.")
    #ERROR_CALLBACK_SUPPLIED_INVALID_DATA
    $AMHintsTable.Add("0x800704F9", "An application-defined callback gave invalid data when called.")
    #ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED
    $AMHintsTable.Add("0x800704FA", "The Group Policy framework should call the extension in the synchronous foreground policy refresh.")
    #ERROR_DRIVER_BLOCKED
    $AMHintsTable.Add("0x800704FB", "This driver has been blocked from loading.")
    #ERROR_INVALID_IMPORT_OF_NON_DLL
    $AMHintsTable.Add("0x800704FC", "A DLL referenced a module that was neither a DLL nor the process's executable image.")
    #ERROR_ACCESS_DISABLED_WEBBLADE
    $AMHintsTable.Add("0x800704FD", "Windows cannot open this program because it has been disabled.")
    #ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER
    $AMHintsTable.Add("0x800704FE", "Windows cannot open this program because the license enforcement system has been tampered with or become corrupted.")
    #ERROR_RECOVERY_FAILURE
    $AMHintsTable.Add("0x800704FF", "A transaction recover failed.")
    #ERROR_ALREADY_FIBER
    $AMHintsTable.Add("0x80070500", "The current thread has already been converted to a fiber.")
    #ERROR_ALREADY_THREAD
    $AMHintsTable.Add("0x80070501", "The current thread has already been converted from a fiber.")
    #ERROR_STACK_BUFFER_OVERRUN
    $AMHintsTable.Add("0x80070502", "The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application.")
    #ERROR_PARAMETER_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x80070503", "Data present in one of the parameters is more than the function can operate on.")
    #ERROR_DEBUGGER_INACTIVE
    $AMHintsTable.Add("0x80070504", "An attempt to perform an operation on a debug object failed because the object is in the process of being deleted.")
    #ERROR_DELAY_LOAD_FAILED
    $AMHintsTable.Add("0x80070505", "An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.")
    #ERROR_VDM_DISALLOWED
    $AMHintsTable.Add("0x80070506", "%1 is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator.")
    #ERROR_UNIDENTIFIED_ERROR
    $AMHintsTable.Add("0x80070507", "Insufficient information exists to identify the cause of failure.")
    #ERROR_INVALID_CRUNTIME_PARAMETER
    $AMHintsTable.Add("0x80070508", "The parameter passed to a C runtime function is incorrect.")
    #ERROR_BEYOND_VDL
    $AMHintsTable.Add("0x80070509", "The operation occurred beyond the valid data length of the file.")
    #ERROR_INCOMPATIBLE_SERVICE_SID_TYPE
    $AMHintsTable.Add("0x8007050A", "The service start failed because one or more services in the same process have an incompatible service SID type setting. A service with a restricted service SID type can only coexist in the same process with other services with a restricted SID type.")
    #ERROR_DRIVER_PROCESS_TERMINATED
    $AMHintsTable.Add("0x8007050B", "The process hosting the driver for this device has been terminated.")
    #ERROR_IMPLEMENTATION_LIMIT
    $AMHintsTable.Add("0x8007050C", "An operation attempted to exceed an implementation-defined limit.")
    #ERROR_PROCESS_IS_PROTECTED
    $AMHintsTable.Add("0x8007050D", "Either the target process, or the target thread's containing process, is a protected process.")
    #ERROR_SERVICE_NOTIFY_CLIENT_LAGGING
    $AMHintsTable.Add("0x8007050E", "The service notification client is lagging too far behind the current state of services in the machine.")
    #ERROR_DISK_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x8007050F", "An operation failed because the storage quota was exceeded.")
    #ERROR_CONTENT_BLOCKED
    $AMHintsTable.Add("0x80070510", "An operation failed because the content was blocked.")
    #ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE
    $AMHintsTable.Add("0x80070511", "A privilege that the service requires to function properly does not exist in the service account configuration. You may use the Services Microsoft Management Console (MMC) snap-in (Services.msc) and the Local Security Settings MMC snap-in (Secpol.msc) to view the service configuration and the account configuration.")
    #ERROR_INVALID_LABEL
    $AMHintsTable.Add("0x80070513", "Indicates a particular SID may not be assigned as the label of an object.")
    #ERROR_NOT_ALL_ASSIGNED
    $AMHintsTable.Add("0x80070514", "Not all privileges or groups referenced are assigned to the caller.")
    #ERROR_SOME_NOT_MAPPED
    $AMHintsTable.Add("0x80070515", "Some mapping between account names and SIDs was not done.")
    #ERROR_NO_QUOTAS_FOR_ACCOUNT
    $AMHintsTable.Add("0x80070516", "No system quota limits are specifically set for this account.")
    #ERROR_LOCAL_USER_SESSION_KEY
    $AMHintsTable.Add("0x80070517", "No encryption key is available. A well-known encryption key was returned.")
    #ERROR_NULL_LM_PASSWORD
    $AMHintsTable.Add("0x80070518", "The password is too complex to be converted to a LAN Manager password. The LAN Manager password returned is a null string.")
    #ERROR_UNKNOWN_REVISION
    $AMHintsTable.Add("0x80070519", "The revision level is unknown.")
    #ERROR_REVISION_MISMATCH
    $AMHintsTable.Add("0x8007051A", "Indicates two revision levels are incompatible.")
    #ERROR_INVALID_OWNER
    $AMHintsTable.Add("0x8007051B", "This SID may not be assigned as the owner of this object.")
    #ERROR_INVALID_PRIMARY_GROUP
    $AMHintsTable.Add("0x8007051C", "This SID may not be assigned as the primary group of an object.")
    #ERROR_NO_IMPERSONATION_TOKEN
    $AMHintsTable.Add("0x8007051D", "An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.")
    #ERROR_CANT_DISABLE_MANDATORY
    $AMHintsTable.Add("0x8007051E", "The group may not be disabled.")
    #ERROR_NO_LOGON_SERVERS
    $AMHintsTable.Add("0x8007051F", "There are currently no logon servers available to service the logon request.")
    #ERROR_NO_SUCH_LOGON_SESSION
    $AMHintsTable.Add("0x80070520", "A specified logon session does not exist. It may already have been terminated.")
    #ERROR_NO_SUCH_PRIVILEGE
    $AMHintsTable.Add("0x80070521", "A specified privilege does not exist.")
    #ERROR_PRIVILEGE_NOT_HELD
    $AMHintsTable.Add("0x80070522", "A required privilege is not held by the client.")
    #ERROR_INVALID_ACCOUNT_NAME
    $AMHintsTable.Add("0x80070523", "The name provided is not a properly formed account name.")
    #ERROR_USER_EXISTS
    $AMHintsTable.Add("0x80070524", "The specified account already exists.")
    #ERROR_NO_SUCH_USER
    $AMHintsTable.Add("0x80070525", "The specified account does not exist.")
    #ERROR_GROUP_EXISTS
    $AMHintsTable.Add("0x80070526", "The specified group already exists.")
    #ERROR_NO_SUCH_GROUP
    $AMHintsTable.Add("0x80070527", "The specified group does not exist.")
    #ERROR_MEMBER_IN_GROUP
    $AMHintsTable.Add("0x80070528", "Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member.")
    #ERROR_MEMBER_NOT_IN_GROUP
    $AMHintsTable.Add("0x80070529", "The specified user account is not a member of the specified group account.")
    #ERROR_LAST_ADMIN
    $AMHintsTable.Add("0x8007052A", "The last remaining administration account cannot be disabled or deleted.")
    #ERROR_WRONG_PASSWORD
    $AMHintsTable.Add("0x8007052B", "Unable to update the password. The value provided as the current password is incorrect.")
    #ERROR_ILL_FORMED_PASSWORD
    $AMHintsTable.Add("0x8007052C", "Unable to update the password. The value provided for the new password contains values that are not allowed in passwords.")
    #ERROR_PASSWORD_RESTRICTION
    $AMHintsTable.Add("0x8007052D", "Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.")
    #ERROR_LOGON_FAILURE
    $AMHintsTable.Add("0x8007052E", "Logon failure: Unknown user name or bad password.")
    #ERROR_ACCOUNT_RESTRICTION
    $AMHintsTable.Add("0x8007052F", "Logon failure: User account restriction. Possible reasons are blank passwords not allowed, logon hour restrictions, or a policy restriction has been enforced.")
    #ERROR_INVALID_LOGON_HOURS
    $AMHintsTable.Add("0x80070530", "Logon failure: Account logon time restriction violation.")
    #ERROR_INVALID_WORKSTATION
    $AMHintsTable.Add("0x80070531", "Logon failure: User not allowed to log on to this computer.")
    #ERROR_PASSWORD_EXPIRED
    $AMHintsTable.Add("0x80070532", "Logon failure: The specified account password has expired.")
    #ERROR_ACCOUNT_DISABLED
    $AMHintsTable.Add("0x80070533", "Logon failure: Account currently disabled.")
    #ERROR_NONE_MAPPED
    $AMHintsTable.Add("0x80070534", "No mapping between account names and SIDs was done.")
    #ERROR_TOO_MANY_LUIDS_REQUESTED
    $AMHintsTable.Add("0x80070535", "Too many local user identifiers (LUIDs) were requested at one time.")
    #ERROR_LUIDS_EXHAUSTED
    $AMHintsTable.Add("0x80070536", "No more LUIDs are available.")
    #ERROR_INVALID_SUB_AUTHORITY
    $AMHintsTable.Add("0x80070537", "The sub-authority part of an SID is invalid for this particular use.")
    #ERROR_INVALID_ACL
    $AMHintsTable.Add("0x80070538", "The ACL structure is invalid.")
    #ERROR_INVALID_SID
    $AMHintsTable.Add("0x80070539", "The SID structure is invalid.")
    #ERROR_INVALID_SECURITY_DESCR
    $AMHintsTable.Add("0x8007053A", "The security descriptor structure is invalid.")
    #ERROR_BAD_INHERITANCE_ACL
    $AMHintsTable.Add("0x8007053C", "The inherited ACL or ACE could not be built.")
    #ERROR_SERVER_DISABLED
    $AMHintsTable.Add("0x8007053D", "The server is currently disabled.")
    #ERROR_SERVER_NOT_DISABLED
    $AMHintsTable.Add("0x8007053E", "The server is currently enabled.")
    #ERROR_INVALID_ID_AUTHORITY
    $AMHintsTable.Add("0x8007053F", "The value provided was an invalid value for an identifier authority.")
    #ERROR_ALLOTTED_SPACE_EXCEEDED
    $AMHintsTable.Add("0x80070540", "No more memory is available for security information updates.")
    #ERROR_INVALID_GROUP_ATTRIBUTES
    $AMHintsTable.Add("0x80070541", "The specified attributes are invalid, or incompatible with the attributes for the group as a whole.")
    #ERROR_BAD_IMPERSONATION_LEVEL
    $AMHintsTable.Add("0x80070542", "Either a required impersonation level was not provided, or the provided impersonation level is invalid.")
    #ERROR_CANT_OPEN_ANONYMOUS
    $AMHintsTable.Add("0x80070543", "Cannot open an anonymous level security token.")
    #ERROR_BAD_VALIDATION_CLASS
    $AMHintsTable.Add("0x80070544", "The validation information class requested was invalid.")
    #ERROR_BAD_TOKEN_TYPE
    $AMHintsTable.Add("0x80070545", "The type of the token is inappropriate for its attempted use.")
    #ERROR_NO_SECURITY_ON_OBJECT
    $AMHintsTable.Add("0x80070546", "Unable to perform a security operation on an object that has no associated security.")
    #ERROR_CANT_ACCESS_DOMAIN_INFO
    $AMHintsTable.Add("0x80070547", "Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.")
    #ERROR_INVALID_SERVER_STATE
    $AMHintsTable.Add("0x80070548", "The SAM or local security authority (LSA) server was in the wrong state to perform the security operation.")
    #ERROR_INVALID_DOMAIN_STATE
    $AMHintsTable.Add("0x80070549", "The domain was in the wrong state to perform the security operation.")
    #ERROR_INVALID_DOMAIN_ROLE
    $AMHintsTable.Add("0x8007054A", "This operation is only allowed for the PDC of the domain.")
    #ERROR_NO_SUCH_DOMAIN
    $AMHintsTable.Add("0x8007054B", "The specified domain either does not exist or could not be contacted.")
    #ERROR_DOMAIN_EXISTS
    $AMHintsTable.Add("0x8007054C", "The specified domain already exists.")
    #ERROR_DOMAIN_LIMIT_EXCEEDED
    $AMHintsTable.Add("0x8007054D", "An attempt was made to exceed the limit on the number of domains per server.")
    #ERROR_INTERNAL_DB_CORRUPTION
    $AMHintsTable.Add("0x8007054E", "Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk.")
    #ERROR_INTERNAL_ERROR
    $AMHintsTable.Add("0x8007054F", "An internal error occurred.")
    #ERROR_GENERIC_NOT_MAPPED
    $AMHintsTable.Add("0x80070550", "Generic access types were contained in an access mask that should already be mapped to nongeneric types.")
    #ERROR_BAD_DESCRIPTOR_FORMAT
    $AMHintsTable.Add("0x80070551", "A security descriptor is not in the right format (absolute or self-relative).")
    #ERROR_NOT_LOGON_PROCESS
    $AMHintsTable.Add("0x80070552", "The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.")
    #ERROR_LOGON_SESSION_EXISTS
    $AMHintsTable.Add("0x80070553", "Cannot start a new logon session with an ID that is already in use.")
    #ERROR_NO_SUCH_PACKAGE
    $AMHintsTable.Add("0x80070554", "A specified authentication package is unknown.")
    #ERROR_BAD_LOGON_SESSION_STATE
    $AMHintsTable.Add("0x80070555", "The logon session is not in a state that is consistent with the requested operation.")
    #ERROR_LOGON_SESSION_COLLISION
    $AMHintsTable.Add("0x80070556", "The logon session ID is already in use.")
    #ERROR_INVALID_LOGON_TYPE
    $AMHintsTable.Add("0x80070557", "A logon request contained an invalid logon type value.")
    #ERROR_CANNOT_IMPERSONATE
    $AMHintsTable.Add("0x80070558", "Unable to impersonate using a named pipe until data has been read from that pipe.")
    #ERROR_RXACT_INVALID_STATE
    $AMHintsTable.Add("0x80070559", "The transaction state of a registry subtree is incompatible with the requested operation.")
    #ERROR_RXACT_COMMIT_FAILURE
    $AMHintsTable.Add("0x8007055A", "An internal security database corruption has been encountered.")
    #ERROR_SPECIAL_ACCOUNT
    $AMHintsTable.Add("0x8007055B", "Cannot perform this operation on built-in accounts.")
    #ERROR_SPECIAL_GROUP
    $AMHintsTable.Add("0x8007055C", "Cannot perform this operation on this built-in special group.")
    #ERROR_SPECIAL_USER
    $AMHintsTable.Add("0x8007055D", "Cannot perform this operation on this built-in special user.")
    #ERROR_MEMBERS_PRIMARY_GROUP
    $AMHintsTable.Add("0x8007055E", "The user cannot be removed from a group because the group is currently the user's primary group.")
    #ERROR_TOKEN_ALREADY_IN_USE
    $AMHintsTable.Add("0x8007055F", "The token is already in use as a primary token.")
    #ERROR_NO_SUCH_ALIAS
    $AMHintsTable.Add("0x80070560", "The specified local group does not exist.")
    #ERROR_MEMBER_NOT_IN_ALIAS
    $AMHintsTable.Add("0x80070561", "The specified account name is not a member of the group.")
    #ERROR_MEMBER_IN_ALIAS
    $AMHintsTable.Add("0x80070562", "The specified account name is already a member of the group.")
    #ERROR_ALIAS_EXISTS
    $AMHintsTable.Add("0x80070563", "The specified local group already exists.")
    #ERROR_LOGON_NOT_GRANTED
    $AMHintsTable.Add("0x80070564", "Logon failure: The user has not been granted the requested logon type at this computer.")
    #ERROR_TOO_MANY_SECRETS
    $AMHintsTable.Add("0x80070565", "The maximum number of secrets that may be stored in a single system has been exceeded.")
    #ERROR_SECRET_TOO_LONG
    $AMHintsTable.Add("0x80070566", "The length of a secret exceeds the maximum length allowed.")
    #ERROR_INTERNAL_DB_ERROR
    $AMHintsTable.Add("0x80070567", "The local security authority database contains an internal inconsistency.")
    #ERROR_TOO_MANY_CONTEXT_IDS
    $AMHintsTable.Add("0x80070568", "During a logon attempt, the user's security context accumulated too many SIDs.")
    #ERROR_LOGON_TYPE_NOT_GRANTED
    $AMHintsTable.Add("0x80070569", "Logon failure: The user has not been granted the requested logon type at this computer.")
    #ERROR_NT_CROSS_ENCRYPTION_REQUIRED
    $AMHintsTable.Add("0x8007056A", "A cross-encrypted password is necessary to change a user password.")
    #ERROR_NO_SUCH_MEMBER
    $AMHintsTable.Add("0x8007056B", "A member could not be added to or removed from the local group because the member does not exist.")
    #ERROR_INVALID_MEMBER
    $AMHintsTable.Add("0x8007056C", "A new member could not be added to a local group because the member has the wrong account type.")
    #ERROR_TOO_MANY_SIDS
    $AMHintsTable.Add("0x8007056D", "Too many SIDs have been specified.")
    #ERROR_LM_CROSS_ENCRYPTION_REQUIRED
    $AMHintsTable.Add("0x8007056E", "A cross-encrypted password is necessary to change this user password.")
    #ERROR_NO_INHERITANCE
    $AMHintsTable.Add("0x8007056F", "Indicates an ACL contains no inheritable components.")
    #ERROR_FILE_CORRUPT
    $AMHintsTable.Add("0x80070570", "The file or directory is corrupted and unreadable.")
    #ERROR_DISK_CORRUPT
    $AMHintsTable.Add("0x80070571", "The disk structure is corrupted and unreadable.")
    #ERROR_NO_USER_SESSION_KEY
    $AMHintsTable.Add("0x80070572", "There is no user session key for the specified logon session.")
    #ERROR_LICENSE_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x80070573", "The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has accepted the maximum number of connections.")
    #ERROR_WRONG_TARGET_NAME
    $AMHintsTable.Add("0x80070574", "Logon failure: The target account name is incorrect.")
    #ERROR_MUTUAL_AUTH_FAILED
    $AMHintsTable.Add("0x80070575", "Mutual authentication failed. The server's password is out of date at the domain controller.")
    #ERROR_TIME_SKEW
    $AMHintsTable.Add("0x80070576", "There is a time and/or date difference between the client and server.")
    #ERROR_CURRENT_DOMAIN_NOT_ALLOWED
    $AMHintsTable.Add("0x80070577", "This operation cannot be performed on the current domain.")
    #ERROR_INVALID_WINDOW_HANDLE
    $AMHintsTable.Add("0x80070578", "Invalid window handle.")
    #ERROR_INVALID_MENU_HANDLE
    $AMHintsTable.Add("0x80070579", "Invalid menu handle.")
    #ERROR_INVALID_CURSOR_HANDLE
    $AMHintsTable.Add("0x8007057A", "Invalid cursor handle.")
    #ERROR_INVALID_ACCEL_HANDLE
    $AMHintsTable.Add("0x8007057B", "Invalid accelerator table handle.")
    #ERROR_INVALID_HOOK_HANDLE
    $AMHintsTable.Add("0x8007057C", "Invalid hook handle.")
    #ERROR_INVALID_DWP_HANDLE
    $AMHintsTable.Add("0x8007057D", "Invalid handle to a multiple-window position structure.")
    #ERROR_TLW_WITH_WSCHILD
    $AMHintsTable.Add("0x8007057E", "Cannot create a top-level child window.")
    #ERROR_CANNOT_FIND_WND_CLASS
    $AMHintsTable.Add("0x8007057F", "Cannot find window class.")
    #ERROR_WINDOW_OF_OTHER_THREAD
    $AMHintsTable.Add("0x80070580", "Invalid window; it belongs to other thread.")
    #ERROR_HOTKEY_ALREADY_REGISTERED
    $AMHintsTable.Add("0x80070581", "Hot key is already registered.")
    #ERROR_CLASS_ALREADY_EXISTS
    $AMHintsTable.Add("0x80070582", "Class already exists.")
    #ERROR_CLASS_DOES_NOT_EXIST
    $AMHintsTable.Add("0x80070583", "Class does not exist.")
    #ERROR_CLASS_HAS_WINDOWS
    $AMHintsTable.Add("0x80070584", "Class still has open windows.")
    #ERROR_INVALID_INDEX
    $AMHintsTable.Add("0x80070585", "Invalid index.")
    #ERROR_INVALID_ICON_HANDLE
    $AMHintsTable.Add("0x80070586", "Invalid icon handle.")
    #ERROR_PRIVATE_DIALOG_INDEX
    $AMHintsTable.Add("0x80070587", "Using private DIALOG window words.")
    #ERROR_LISTBOX_ID_NOT_FOUND
    $AMHintsTable.Add("0x80070588", "The list box identifier was not found.")
    #ERROR_NO_WILDCARD_CHARACTERS
    $AMHintsTable.Add("0x80070589", "No wildcards were found.")
    #ERROR_CLIPBOARD_NOT_OPEN
    $AMHintsTable.Add("0x8007058A", "Thread does not have a clipboard open.")
    #ERROR_HOTKEY_NOT_REGISTERED
    $AMHintsTable.Add("0x8007058B", "Hot key is not registered.")
    #ERROR_WINDOW_NOT_DIALOG
    $AMHintsTable.Add("0x8007058C", "The window is not a valid dialog window.")
    #ERROR_CONTROL_ID_NOT_FOUND
    $AMHintsTable.Add("0x8007058D", "Control ID not found.")
    #ERROR_INVALID_COMBOBOX_MESSAGE
    $AMHintsTable.Add("0x8007058E", "Invalid message for a combo box because it does not have an edit control.")
    #ERROR_WINDOW_NOT_COMBOBOX
    $AMHintsTable.Add("0x8007058F", "The window is not a combo box.")
    #ERROR_INVALID_EDIT_HEIGHT
    $AMHintsTable.Add("0x80070590", "Height must be less than 256.")
    #ERROR_DC_NOT_FOUND
    $AMHintsTable.Add("0x80070591", "Invalid device context (DC) handle.")
    #ERROR_INVALID_HOOK_FILTER
    $AMHintsTable.Add("0x80070592", "Invalid hook procedure type.")
    #ERROR_INVALID_FILTER_PROC
    $AMHintsTable.Add("0x80070593", "Invalid hook procedure.")
    #ERROR_HOOK_NEEDS_HMOD
    $AMHintsTable.Add("0x80070594", "Cannot set nonlocal hook without a module handle.")
    #ERROR_GLOBAL_ONLY_HOOK
    $AMHintsTable.Add("0x80070595", "This hook procedure can only be set globally.")
    #ERROR_JOURNAL_HOOK_SET
    $AMHintsTable.Add("0x80070596", "The journal hook procedure is already installed.")
    #ERROR_HOOK_NOT_INSTALLED
    $AMHintsTable.Add("0x80070597", "The hook procedure is not installed.")
    #ERROR_INVALID_LB_MESSAGE
    $AMHintsTable.Add("0x80070598", "Invalid message for single-selection list box.")
    #ERROR_SETCOUNT_ON_BAD_LB
    $AMHintsTable.Add("0x80070599", "LB_SETCOUNT sent to non-lazy list box.")
    #ERROR_LB_WITHOUT_TABSTOPS
    $AMHintsTable.Add("0x8007059A", "This list box does not support tab stops.")
    #ERROR_DESTROY_OBJECT_OF_OTHER_THREAD
    $AMHintsTable.Add("0x8007059B", "Cannot destroy object created by another thread.")
    #ERROR_CHILD_WINDOW_MENU
    $AMHintsTable.Add("0x8007059C", "Child windows cannot have menus.")
    #ERROR_NO_SYSTEM_MENU
    $AMHintsTable.Add("0x8007059D", "The window does not have a system menu.")
    #ERROR_INVALID_MSGBOX_STYLE
    $AMHintsTable.Add("0x8007059E", "Invalid message box style.")
    #ERROR_INVALID_SPI_VALUE
    $AMHintsTable.Add("0x8007059F", "Invalid system-wide (SPI_*) parameter.")
    #ERROR_SCREEN_ALREADY_LOCKED
    $AMHintsTable.Add("0x800705A0", "Screen already locked.")
    #ERROR_HWNDS_HAVE_DIFF_PARENT
    $AMHintsTable.Add("0x800705A1", "All handles to windows in a multiple-window position structure must have the same parent.")
    #ERROR_NOT_CHILD_WINDOW
    $AMHintsTable.Add("0x800705A2", "The window is not a child window.")
    #ERROR_INVALID_GW_COMMAND
    $AMHintsTable.Add("0x800705A3", "Invalid GW_* command.")
    #ERROR_INVALID_THREAD_ID
    $AMHintsTable.Add("0x800705A4", "Invalid thread identifier.")
    #ERROR_NON_MDICHILD_WINDOW
    $AMHintsTable.Add("0x800705A5", "Cannot process a message from a window that is not a multiple document interface (MDI) window.")
    #ERROR_POPUP_ALREADY_ACTIVE
    $AMHintsTable.Add("0x800705A6", "Pop-up menu already active.")
    #ERROR_NO_SCROLLBARS
    $AMHintsTable.Add("0x800705A7", "The window does not have scroll bars.")
    #ERROR_INVALID_SCROLLBAR_RANGE
    $AMHintsTable.Add("0x800705A8", "Scroll bar range cannot be greater than MAXLONG.")
    #ERROR_INVALID_SHOWWIN_COMMAND
    $AMHintsTable.Add("0x800705A9", "Cannot show or remove the window in the way specified.")
    #ERROR_NO_SYSTEM_RESOURCES
    $AMHintsTable.Add("0x800705AA", "Insufficient system resources exist to complete the requested service.")
    #ERROR_NONPAGED_SYSTEM_RESOURCES
    $AMHintsTable.Add("0x800705AB", "Insufficient system resources exist to complete the requested service.")
    #ERROR_PAGED_SYSTEM_RESOURCES
    $AMHintsTable.Add("0x800705AC", "Insufficient system resources exist to complete the requested service.")
    #ERROR_WORKING_SET_QUOTA
    $AMHintsTable.Add("0x800705AD", "Insufficient quota to complete the requested service.")
    #ERROR_PAGEFILE_QUOTA
    $AMHintsTable.Add("0x800705AE", "Insufficient quota to complete the requested service.")
    #ERROR_COMMITMENT_LIMIT
    $AMHintsTable.Add("0x800705AF", "The paging file is too small for this operation to complete.")
    #ERROR_MENU_ITEM_NOT_FOUND
    $AMHintsTable.Add("0x800705B0", "A menu item was not found.")
    #ERROR_INVALID_KEYBOARD_HANDLE
    $AMHintsTable.Add("0x800705B1", "Invalid keyboard layout handle.")
    #ERROR_HOOK_TYPE_NOT_ALLOWED
    $AMHintsTable.Add("0x800705B2", "Hook type not allowed.")
    #ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION
    $AMHintsTable.Add("0x800705B3", "This operation requires an interactive window station.")
    #ERROR_TIMEOUT
    $AMHintsTable.Add("0x800705B4", "This operation returned because the time-out period expired.")
    #ERROR_INVALID_MONITOR_HANDLE
    $AMHintsTable.Add("0x800705B5", "Invalid monitor handle.")
    #ERROR_INCORRECT_SIZE
    $AMHintsTable.Add("0x800705B6", "Incorrect size argument.")
    #ERROR_SYMLINK_CLASS_DISABLED
    $AMHintsTable.Add("0x800705B7", "The symbolic link cannot be followed because its type is disabled.")
    #ERROR_SYMLINK_NOT_SUPPORTED
    $AMHintsTable.Add("0x800705B8", "This application does not support the current operation on symbolic links.")
    #ERROR_EVENTLOG_FILE_CORRUPT
    $AMHintsTable.Add("0x800705DC", "The event log file is corrupted.")
    #ERROR_EVENTLOG_CANT_START
    $AMHintsTable.Add("0x800705DD", "No event log file could be opened, so the event logging service did not start.")
    #ERROR_LOG_FILE_FULL
    $AMHintsTable.Add("0x800705DE", "The event log file is full.")
    #ERROR_EVENTLOG_FILE_CHANGED
    $AMHintsTable.Add("0x800705DF", "The event log file has changed between read operations.")
    #ERROR_INVALID_TASK_NAME
    $AMHintsTable.Add("0x8007060E", "The specified task name is invalid.")
    #ERROR_INVALID_TASK_INDEX
    $AMHintsTable.Add("0x8007060F", "The specified task index is invalid.")
    #ERROR_THREAD_ALREADY_IN_TASK
    $AMHintsTable.Add("0x80070610", "The specified thread is already joining a task.")
    #ERROR_INSTALL_SERVICE_FAILURE
    $AMHintsTable.Add("0x80070641", "The Windows Installer service could not be accessed. This can occur if the Windows Installer is not correctly installed. Contact your support personnel for assistance.")
    #ERROR_INSTALL_USEREXIT
    $AMHintsTable.Add("0x80070642", "User canceled installation.")
    #ERROR_INSTALL_FAILURE
    $AMHintsTable.Add("0x80070643", "Fatal error during installation.")
    #ERROR_INSTALL_SUSPEND
    $AMHintsTable.Add("0x80070644", "Installation suspended, incomplete.")
    #ERROR_UNKNOWN_PRODUCT
    $AMHintsTable.Add("0x80070645", "This action is valid only for products that are currently installed.")
    #ERROR_UNKNOWN_FEATURE
    $AMHintsTable.Add("0x80070646", "Feature ID not registered.")
    #ERROR_UNKNOWN_COMPONENT
    $AMHintsTable.Add("0x80070647", "Component ID not registered.")
    #ERROR_UNKNOWN_PROPERTY
    $AMHintsTable.Add("0x80070648", "Unknown property.")
    #ERROR_INVALID_HANDLE_STATE
    $AMHintsTable.Add("0x80070649", "Handle is in an invalid state.")
    #ERROR_BAD_CONFIGURATION
    $AMHintsTable.Add("0x8007064A", "The configuration data for this product is corrupt. Contact your support personnel.")
    #ERROR_INDEX_ABSENT
    $AMHintsTable.Add("0x8007064B", "Component qualifier not present.")
    #ERROR_INSTALL_SOURCE_ABSENT
    $AMHintsTable.Add("0x8007064C", "The installation source for this product is not available. Verify that the source exists and that you can access it.")
    #ERROR_INSTALL_PACKAGE_VERSION
    $AMHintsTable.Add("0x8007064D", "This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.")
    #ERROR_PRODUCT_UNINSTALLED
    $AMHintsTable.Add("0x8007064E", "Product is uninstalled.")
    #ERROR_BAD_QUERY_SYNTAX
    $AMHintsTable.Add("0x8007064F", "SQL query syntax invalid or unsupported.")
    #ERROR_INVALID_FIELD
    $AMHintsTable.Add("0x80070650", "Record field does not exist.")
    #ERROR_DEVICE_REMOVED
    $AMHintsTable.Add("0x80070651", "The device has been removed.")
    #ERROR_INSTALL_ALREADY_RUNNING
    $AMHintsTable.Add("0x80070652", "Another installation is already in progress. Complete that installation before proceeding with this install.")
    #ERROR_INSTALL_PACKAGE_OPEN_FAILED
    $AMHintsTable.Add("0x80070653", "This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package.")
    #ERROR_INSTALL_PACKAGE_INVALID
    $AMHintsTable.Add("0x80070654", "This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package.")
    #ERROR_INSTALL_UI_FAILURE
    $AMHintsTable.Add("0x80070655", "There was an error starting the Windows Installer service user interface. Contact your support personnel.")
    #ERROR_INSTALL_LOG_FAILURE
    $AMHintsTable.Add("0x80070656", "Error opening installation log file. Verify that the specified log file location exists and that you can write to it.")
    #ERROR_INSTALL_LANGUAGE_UNSUPPORTED
    $AMHintsTable.Add("0x80070657", "The language of this installation package is not supported by your system.")
    #ERROR_INSTALL_TRANSFORM_FAILURE
    $AMHintsTable.Add("0x80070658", "Error applying transforms. Verify that the specified transform paths are valid.")
    #ERROR_INSTALL_PACKAGE_REJECTED
    $AMHintsTable.Add("0x80070659", "This installation is forbidden by system policy. Contact your system administrator.")
    #ERROR_FUNCTION_NOT_CALLED
    $AMHintsTable.Add("0x8007065A", "Function could not be executed.")
    #ERROR_FUNCTION_FAILED
    $AMHintsTable.Add("0x8007065B", "Function failed during execution.")
    #ERROR_INVALID_TABLE
    $AMHintsTable.Add("0x8007065C", "Invalid or unknown table specified.")
    #ERROR_DATATYPE_MISMATCH
    $AMHintsTable.Add("0x8007065D", "Data supplied is of wrong type.")
    #ERROR_UNSUPPORTED_TYPE
    $AMHintsTable.Add("0x8007065E", "Data of this type is not supported.")
    #ERROR_CREATE_FAILED
    $AMHintsTable.Add("0x8007065F", "The Windows Installer service failed to start. Contact your support personnel.")
    #ERROR_INSTALL_TEMP_UNWRITABLE
    $AMHintsTable.Add("0x80070660", "The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder.")
    #ERROR_INSTALL_PLATFORM_UNSUPPORTED
    $AMHintsTable.Add("0x80070661", "This installation package is not supported by this processor type. Contact your product vendor.")
    #ERROR_INSTALL_NOTUSED
    $AMHintsTable.Add("0x80070662", "Component not used on this computer.")
    #ERROR_PATCH_PACKAGE_OPEN_FAILED
    $AMHintsTable.Add("0x80070663", "This update package could not be opened. Verify that the update package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer update package.")
    #ERROR_PATCH_PACKAGE_INVALID
    $AMHintsTable.Add("0x80070664", "This update package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer update package.")
    #ERROR_PATCH_PACKAGE_UNSUPPORTED
    $AMHintsTable.Add("0x80070665", "This update package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service.")
    #ERROR_PRODUCT_VERSION
    $AMHintsTable.Add("0x80070666", "Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs in Control Panel.")
    #ERROR_INVALID_COMMAND_LINE
    $AMHintsTable.Add("0x80070667", "Invalid command-line argument. Consult the Windows Installer SDK for detailed command line help.")
    #ERROR_INSTALL_REMOTE_DISALLOWED
    $AMHintsTable.Add("0x80070668", "Only administrators have permission to add, remove, or configure server software during a Terminal Services remote session. If you want to install or configure software on the server, contact your network administrator.")
    #ERROR_SUCCESS_REBOOT_INITIATED
    $AMHintsTable.Add("0x80070669", "The requested operation completed successfully. The system will be restarted so the changes can take effect.")
    #ERROR_PATCH_TARGET_NOT_FOUND
    $AMHintsTable.Add("0x8007066A", "The upgrade cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade may update a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade.")
    #ERROR_PATCH_PACKAGE_REJECTED
    $AMHintsTable.Add("0x8007066B", "The update package is not permitted by a software restriction policy.")
    #ERROR_INSTALL_TRANSFORM_REJECTED
    $AMHintsTable.Add("0x8007066C", "One or more customizations are not permitted by a software restriction policy.")
    #ERROR_INSTALL_REMOTE_PROHIBITED
    $AMHintsTable.Add("0x8007066D", "The Windows Installer does not permit installation from a Remote Desktop Connection.")
    #ERROR_PATCH_REMOVAL_UNSUPPORTED
    $AMHintsTable.Add("0x8007066E", "Uninstallation of the update package is not supported.")
    #ERROR_UNKNOWN_PATCH
    $AMHintsTable.Add("0x8007066F", "The update is not applied to this product.")
    #ERROR_PATCH_NO_SEQUENCE
    $AMHintsTable.Add("0x80070670", "No valid sequence could be found for the set of updates.")
    #ERROR_PATCH_REMOVAL_DISALLOWED
    $AMHintsTable.Add("0x80070671", "Update removal was disallowed by policy.")
    #ERROR_INVALID_PATCH_XML
    $AMHintsTable.Add("0x80070672", "The XML update data is invalid.")
    #ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT
    $AMHintsTable.Add("0x80070673", "Windows Installer does not permit updating of managed advertised products. At least one feature of the product must be installed before applying the update.")
    #ERROR_INSTALL_SERVICE_SAFEBOOT
    $AMHintsTable.Add("0x80070674", "The Windows Installer service is not accessible in Safe Mode. Try again when your computer is not in Safe Mode or you can use System Restore to return your machine to a previous good state.")
    #RPC_S_INVALID_STRING_BINDING
    $AMHintsTable.Add("0x800706A4", "The string binding is invalid.")
    #RPC_S_WRONG_KIND_OF_BINDING
    $AMHintsTable.Add("0x800706A5", "The binding handle is not the correct type.")
    #RPC_S_INVALID_BINDING
    $AMHintsTable.Add("0x800706A6", "The binding handle is invalid.")
    #RPC_S_PROTSEQ_NOT_SUPPORTED
    $AMHintsTable.Add("0x800706A7", "The RPC protocol sequence is not supported.")
    #RPC_S_INVALID_RPC_PROTSEQ
    $AMHintsTable.Add("0x800706A8", "The RPC protocol sequence is invalid.")
    #RPC_S_INVALID_STRING_UUID
    $AMHintsTable.Add("0x800706A9", "The string UUID is invalid.")
    #RPC_S_INVALID_ENDPOINT_FORMAT
    $AMHintsTable.Add("0x800706AA", "The endpoint format is invalid.")
    #RPC_S_INVALID_NET_ADDR
    $AMHintsTable.Add("0x800706AB", "The network address is invalid.")
    #RPC_S_NO_ENDPOINT_FOUND
    $AMHintsTable.Add("0x800706AC", "No endpoint was found.")
    #RPC_S_INVALID_TIMEOUT
    $AMHintsTable.Add("0x800706AD", "The time-out value is invalid.")
    #RPC_S_OBJECT_NOT_FOUND
    $AMHintsTable.Add("0x800706AE", "The object UUID) was not found.")
    #RPC_S_ALREADY_REGISTERED
    $AMHintsTable.Add("0x800706AF", "The object UUID) has already been registered.")
    #RPC_S_TYPE_ALREADY_REGISTERED
    $AMHintsTable.Add("0x800706B0", "The type UUID has already been registered.")
    #RPC_S_ALREADY_LISTENING
    $AMHintsTable.Add("0x800706B1", "The RPC server is already listening.")
    #RPC_S_NO_PROTSEQS_REGISTERED
    $AMHintsTable.Add("0x800706B2", "No protocol sequences have been registered.")
    #RPC_S_NOT_LISTENING
    $AMHintsTable.Add("0x800706B3", "The RPC server is not listening.")
    #RPC_S_UNKNOWN_MGR_TYPE
    $AMHintsTable.Add("0x800706B4", "The manager type is unknown.")
    #RPC_S_UNKNOWN_IF
    $AMHintsTable.Add("0x800706B5", "The interface is unknown.")
    #RPC_S_NO_BINDINGS
    $AMHintsTable.Add("0x800706B6", "There are no bindings.")
    #RPC_S_NO_PROTSEQS
    $AMHintsTable.Add("0x800706B7", "There are no protocol sequences.")
    #RPC_S_CANT_CREATE_ENDPOINT
    $AMHintsTable.Add("0x800706B8", "The endpoint cannot be created.")
    #RPC_S_OUT_OF_RESOURCES
    $AMHintsTable.Add("0x800706B9", "Not enough resources are available to complete this operation.")
    #RPC_S_SERVER_UNAVAILABLE
    $AMHintsTable.Add("0x800706BA", "Make sure that the target computer is on and the connection not blocked by a firewall.")
    #RPC_S_SERVER_TOO_BUSY
    $AMHintsTable.Add("0x800706BB", "The RPC server is too busy to complete this operation.")
    #RPC_S_INVALID_NETWORK_OPTIONS
    $AMHintsTable.Add("0x800706BC", "The network options are invalid.")
    #RPC_S_NO_CALL_ACTIVE
    $AMHintsTable.Add("0x800706BD", "There are no RPCs active on this thread.")
    #RPC_S_CALL_FAILED
    $AMHintsTable.Add("0x800706BE", "The RPC failed.")
    #RPC_S_CALL_FAILED_DNE
    $AMHintsTable.Add("0x800706BF", "The RPC failed and did not execute.")
    #RPC_S_PROTOCOL_ERROR
    $AMHintsTable.Add("0x800706C0", "An RPC protocol error occurred.")
    #RPC_S_PROXY_ACCESS_DENIED
    $AMHintsTable.Add("0x800706C1", "Access to the HTTP proxy is denied.")
    #RPC_S_UNSUPPORTED_TRANS_SYN
    $AMHintsTable.Add("0x800706C2", "The transfer syntax is not supported by the RPC server.")
    #RPC_S_UNSUPPORTED_TYPE
    $AMHintsTable.Add("0x800706C4", "The UUID type is not supported.")
    #RPC_S_INVALID_TAG
    $AMHintsTable.Add("0x800706C5", "The tag is invalid.")
    #RPC_S_INVALID_BOUND
    $AMHintsTable.Add("0x800706C6", "The array bounds are invalid.")
    #RPC_S_NO_ENTRY_NAME
    $AMHintsTable.Add("0x800706C7", "The binding does not contain an entry name.")
    #RPC_S_INVALID_NAME_SYNTAX
    $AMHintsTable.Add("0x800706C8", "The name syntax is invalid.")
    #RPC_S_UNSUPPORTED_NAME_SYNTAX
    $AMHintsTable.Add("0x800706C9", "The name syntax is not supported.")
    #RPC_S_UUID_NO_ADDRESS
    $AMHintsTable.Add("0x800706CB", "No network address is available to use to construct a UUID.")
    #RPC_S_DUPLICATE_ENDPOINT
    $AMHintsTable.Add("0x800706CC", "The endpoint is a duplicate.")
    #RPC_S_UNKNOWN_AUTHN_TYPE
    $AMHintsTable.Add("0x800706CD", "The authentication type is unknown.")
    #RPC_S_MAX_CALLS_TOO_SMALL
    $AMHintsTable.Add("0x800706CE", "The maximum number of calls is too small.")
    #RPC_S_STRING_TOO_LONG
    $AMHintsTable.Add("0x800706CF", "The string is too long.")
    #RPC_S_PROTSEQ_NOT_FOUND
    $AMHintsTable.Add("0x800706D0", "The RPC protocol sequence was not found.")
    #RPC_S_PROCNUM_OUT_OF_RANGE
    $AMHintsTable.Add("0x800706D1", "The procedure number is out of range.")
    #RPC_S_BINDING_HAS_NO_AUTH
    $AMHintsTable.Add("0x800706D2", "The binding does not contain any authentication information.")
    #RPC_S_UNKNOWN_AUTHN_SERVICE
    $AMHintsTable.Add("0x800706D3", "The authentication service is unknown.")
    #RPC_S_UNKNOWN_AUTHN_LEVEL
    $AMHintsTable.Add("0x800706D4", "The authentication level is unknown.")
    #RPC_S_INVALID_AUTH_IDENTITY
    $AMHintsTable.Add("0x800706D5", "The security context is invalid.")
    #RPC_S_UNKNOWN_AUTHZ_SERVICE
    $AMHintsTable.Add("0x800706D6", "The authorization service is unknown.")
    #EPT_S_INVALID_ENTRY
    $AMHintsTable.Add("0x800706D7", "The entry is invalid.")
    #EPT_S_CANT_PERFORM_OP
    $AMHintsTable.Add("0x800706D8", "The server endpoint cannot perform the operation.")
    #EPT_S_NOT_REGISTERED
    $AMHintsTable.Add("0x800706D9", "There are no more endpoints available from the endpoint mapper.")
    #RPC_S_NOTHING_TO_EXPORT
    $AMHintsTable.Add("0x800706DA", "No interfaces have been exported.")
    #RPC_S_INCOMPLETE_NAME
    $AMHintsTable.Add("0x800706DB", "The entry name is incomplete.")
    #RPC_S_INVALID_VERS_OPTION
    $AMHintsTable.Add("0x800706DC", "The version option is invalid.")
    #RPC_S_NO_MORE_MEMBERS
    $AMHintsTable.Add("0x800706DD", "There are no more members.")
    #RPC_S_NOT_ALL_OBJS_UNEXPORTED
    $AMHintsTable.Add("0x800706DE", "There is nothing to unexport.")
    #RPC_S_INTERFACE_NOT_FOUND
    $AMHintsTable.Add("0x800706DF", "The interface was not found.")
    #RPC_S_ENTRY_ALREADY_EXISTS
    $AMHintsTable.Add("0x800706E0", "The entry already exists.")
    #RPC_S_ENTRY_NOT_FOUND
    $AMHintsTable.Add("0x800706E1", "The entry is not found.")
    #RPC_S_NAME_SERVICE_UNAVAILABLE
    $AMHintsTable.Add("0x800706E2", "The name service is unavailable.")
    #RPC_S_INVALID_NAF_ID
    $AMHintsTable.Add("0x800706E3", "The network address family is invalid.")
    #RPC_S_CANNOT_SUPPORT
    $AMHintsTable.Add("0x800706E4", "The requested operation is not supported.")
    #RPC_S_NO_CONTEXT_AVAILABLE
    $AMHintsTable.Add("0x800706E5", "No security context is available to allow impersonation.")
    #RPC_S_INTERNAL_ERROR
    $AMHintsTable.Add("0x800706E6", "An internal error occurred in an RPC.")
    #RPC_S_ZERO_DIVIDE
    $AMHintsTable.Add("0x800706E7", "The RPC server attempted an integer division by zero.")
    #RPC_S_ADDRESS_ERROR
    $AMHintsTable.Add("0x800706E8", "An addressing error occurred in the RPC server.")
    #RPC_S_FP_DIV_ZERO
    $AMHintsTable.Add("0x800706E9", "A floating-point operation at the RPC server caused a division by zero.")
    #RPC_S_FP_UNDERFLOW
    $AMHintsTable.Add("0x800706EA", "A floating-point underflow occurred at the RPC server.")
    #RPC_S_FP_OVERFLOW
    $AMHintsTable.Add("0x800706EB", "A floating-point overflow occurred at the RPC server.")
    #RPC_X_NO_MORE_ENTRIES
    $AMHintsTable.Add("0x800706EC", "The list of RPC servers available for the binding of auto handles has been exhausted.")
    #RPC_X_SS_CHAR_TRANS_OPEN_FAIL
    $AMHintsTable.Add("0x800706ED", "Unable to open the character translation table file.")
    #RPC_X_SS_CHAR_TRANS_SHORT_FILE
    $AMHintsTable.Add("0x800706EE", "The file containing the character translation table has fewer than 512 bytes.")
    #RPC_X_SS_IN_NULL_CONTEXT
    $AMHintsTable.Add("0x800706EF", "A null context handle was passed from the client to the host during an RPC.")
    #RPC_X_SS_CONTEXT_DAMAGED
    $AMHintsTable.Add("0x800706F1", "The context handle changed during an RPC.")
    #RPC_X_SS_HANDLES_MISMATCH
    $AMHintsTable.Add("0x800706F2", "The binding handles passed to an RPC do not match.")
    #RPC_X_SS_CANNOT_GET_CALL_HANDLE
    $AMHintsTable.Add("0x800706F3", "The stub is unable to get the RPC handle.")
    #RPC_X_NULL_REF_POINTER
    $AMHintsTable.Add("0x800706F4", "A null reference pointer was passed to the stub.")
    #RPC_X_ENUM_VALUE_OUT_OF_RANGE
    $AMHintsTable.Add("0x800706F5", "The enumeration value is out of range.")
    #RPC_X_BYTE_COUNT_TOO_SMALL
    $AMHintsTable.Add("0x800706F6", "The byte count is too small.")
    #RPC_X_BAD_STUB_DATA
    $AMHintsTable.Add("0x800706F7", "The stub received bad data.")
    #ERROR_INVALID_USER_BUFFER
    $AMHintsTable.Add("0x800706F8", "The supplied user buffer is not valid for the requested operation.")
    #ERROR_UNRECOGNIZED_MEDIA
    $AMHintsTable.Add("0x800706F9", "The disk media is not recognized. It may not be formatted.")
    #ERROR_NO_TRUST_LSA_SECRET
    $AMHintsTable.Add("0x800706FA", "The workstation does not have a trust secret.")
    #ERROR_NO_TRUST_SAM_ACCOUNT
    $AMHintsTable.Add("0x800706FB", "The security database on the server does not have a computer account for this workstation trust relationship.")
    #ERROR_TRUSTED_DOMAIN_FAILURE
    $AMHintsTable.Add("0x800706FC", "The trust relationship between the primary domain and the trusted domain failed.")
    #ERROR_TRUSTED_RELATIONSHIP_FAILURE
    $AMHintsTable.Add("0x800706FD", "The trust relationship between this workstation and the primary domain failed.")
    #ERROR_TRUST_FAILURE
    $AMHintsTable.Add("0x800706FE", "The network logon failed.")
    #RPC_S_CALL_IN_PROGRESS
    $AMHintsTable.Add("0x800706FF", "An RPC is already in progress for this thread.")
    #ERROR_NETLOGON_NOT_STARTED
    $AMHintsTable.Add("0x80070700", "An attempt was made to log on, but the network logon service was not started.")
    #ERROR_ACCOUNT_EXPIRED
    $AMHintsTable.Add("0x80070701", "The user's account has expired.")
    #ERROR_REDIRECTOR_HAS_OPEN_HANDLES
    $AMHintsTable.Add("0x80070702", "The redirector is in use and cannot be unloaded.")
    #ERROR_PRINTER_DRIVER_ALREADY_INSTALLED
    $AMHintsTable.Add("0x80070703", "The specified printer driver is already installed.")
    #ERROR_UNKNOWN_PORT
    $AMHintsTable.Add("0x80070704", "The specified port is unknown.")
    #ERROR_UNKNOWN_PRINTER_DRIVER
    $AMHintsTable.Add("0x80070705", "The printer driver is unknown.")
    #ERROR_UNKNOWN_PRINTPROCESSOR
    $AMHintsTable.Add("0x80070706", "The print processor is unknown.")
    #ERROR_INVALID_SEPARATOR_FILE
    $AMHintsTable.Add("0x80070707", "The specified separator file is invalid.")
    #ERROR_INVALID_PRIORITY
    $AMHintsTable.Add("0x80070708", "The specified priority is invalid.")
    #ERROR_INVALID_PRINTER_NAME
    $AMHintsTable.Add("0x80070709", "The printer name is invalid.")
    #ERROR_PRINTER_ALREADY_EXISTS
    $AMHintsTable.Add("0x8007070A", "The printer already exists.")
    #ERROR_INVALID_PRINTER_COMMAND
    $AMHintsTable.Add("0x8007070B", "The printer command is invalid.")
    #ERROR_INVALID_DATATYPE
    $AMHintsTable.Add("0x8007070C", "The specified data type is invalid.")
    #ERROR_INVALID_ENVIRONMENT
    $AMHintsTable.Add("0x8007070D", "The environment specified is invalid.")
    #RPC_S_NO_MORE_BINDINGS
    $AMHintsTable.Add("0x8007070E", "There are no more bindings.")
    #ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT
    $AMHintsTable.Add("0x8007070F", "The account used is an interdomain trust account. Use your global user account or local user account to access this server.")
    #ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT
    $AMHintsTable.Add("0x80070710", "The account used is a computer account. Use your global user account or local user account to access this server.")
    #ERROR_NOLOGON_SERVER_TRUST_ACCOUNT
    $AMHintsTable.Add("0x80070711", "The account used is a server trust account. Use your global user account or local user account to access this server.")
    #ERROR_DOMAIN_TRUST_INCONSISTENT
    $AMHintsTable.Add("0x80070712", "The name or SID of the domain specified is inconsistent with the trust information for that domain.")
    #ERROR_SERVER_HAS_OPEN_HANDLES
    $AMHintsTable.Add("0x80070713", "The server is in use and cannot be unloaded.")
    #ERROR_RESOURCE_DATA_NOT_FOUND
    $AMHintsTable.Add("0x80070714", "The specified image file did not contain a resource section.")
    #ERROR_RESOURCE_TYPE_NOT_FOUND
    $AMHintsTable.Add("0x80070715", "The specified resource type cannot be found in the image file.")
    #ERROR_RESOURCE_NAME_NOT_FOUND
    $AMHintsTable.Add("0x80070716", "The specified resource name cannot be found in the image file.")
    #ERROR_RESOURCE_LANG_NOT_FOUND
    $AMHintsTable.Add("0x80070717", "The specified resource language ID cannot be found in the image file.")
    #ERROR_NOT_ENOUGH_QUOTA
    $AMHintsTable.Add("0x80070718", "Not enough quota is available to process this command.")
    #RPC_S_NO_INTERFACES
    $AMHintsTable.Add("0x80070719", "No interfaces have been registered.")
    #RPC_S_CALL_CANCELLED
    $AMHintsTable.Add("0x8007071A", "The RPC was canceled.")
    #RPC_S_BINDING_INCOMPLETE
    $AMHintsTable.Add("0x8007071B", "The binding handle does not contain all the required information.")
    #RPC_S_COMM_FAILURE
    $AMHintsTable.Add("0x8007071C", "A communications failure occurred during an RPC.")
    #RPC_S_UNSUPPORTED_AUTHN_LEVEL
    $AMHintsTable.Add("0x8007071D", "The requested authentication level is not supported.")
    #RPC_S_NO_PRINC_NAME
    $AMHintsTable.Add("0x8007071E", "No principal name is registered.")
    #RPC_S_NOT_RPC_ERROR
    $AMHintsTable.Add("0x8007071F", "The error specified is not a valid Windows RPC error code.")
    #RPC_S_UUID_LOCAL_ONLY
    $AMHintsTable.Add("0x80070720", "A UUID that is valid only on this computer has been allocated.")
    #RPC_S_SEC_PKG_ERROR
    $AMHintsTable.Add("0x80070721", "A security package-specific error occurred.")
    #RPC_S_NOT_CANCELLED
    $AMHintsTable.Add("0x80070722", "The thread is not canceled.")
    #RPC_X_INVALID_ES_ACTION
    $AMHintsTable.Add("0x80070723", "Invalid operation on the encoding/decoding handle.")
    #RPC_X_WRONG_ES_VERSION
    $AMHintsTable.Add("0x80070724", "Incompatible version of the serializing package.")
    #RPC_X_WRONG_STUB_VERSION
    $AMHintsTable.Add("0x80070725", "Incompatible version of the RPC stub.")
    #RPC_X_INVALID_PIPE_OBJECT
    $AMHintsTable.Add("0x80070726", "The RPC pipe object is invalid or corrupted.")
    #RPC_X_WRONG_PIPE_ORDER
    $AMHintsTable.Add("0x80070727", "An invalid operation was attempted on an RPC pipe object.")
    #RPC_X_WRONG_PIPE_VERSION
    $AMHintsTable.Add("0x80070728", "Unsupported RPC pipe version.")
    #RPC_S_GROUP_MEMBER_NOT_FOUND
    $AMHintsTable.Add("0x8007076A", "The group member was not found.")
    #EPT_S_CANT_CREATE
    $AMHintsTable.Add("0x8007076B", "The endpoint mapper database entry could not be created.")
    #RPC_S_INVALID_OBJECT
    $AMHintsTable.Add("0x8007076C", "The object UUID is the nil UUID.")
    #ERROR_INVALID_TIME
    $AMHintsTable.Add("0x8007076D", "The specified time is invalid.")
    #ERROR_INVALID_FORM_NAME
    $AMHintsTable.Add("0x8007076E", "The specified form name is invalid.")
    #ERROR_INVALID_FORM_SIZE
    $AMHintsTable.Add("0x8007076F", "The specified form size is invalid.")
    #ERROR_ALREADY_WAITING
    $AMHintsTable.Add("0x80070770", "The specified printer handle is already being waited on.")
    #ERROR_PRINTER_DELETED
    $AMHintsTable.Add("0x80070771", "The specified printer has been deleted.")
    #ERROR_INVALID_PRINTER_STATE
    $AMHintsTable.Add("0x80070772", "The state of the printer is invalid.")
    #ERROR_PASSWORD_MUST_CHANGE
    $AMHintsTable.Add("0x80070773", "The user's password must be changed before logging on the first time.")
    #ERROR_DOMAIN_CONTROLLER_NOT_FOUND
    $AMHintsTable.Add("0x80070774", "Could not find the domain controller for this domain.")
    #ERROR_ACCOUNT_LOCKED_OUT
    $AMHintsTable.Add("0x80070775", "The referenced account is currently locked out and may not be logged on to.")
    #OR_INVALID_OXID
    $AMHintsTable.Add("0x80070776", "The object exporter specified was not found.")
    #OR_INVALID_OID
    $AMHintsTable.Add("0x80070777", "The object specified was not found.")
    #OR_INVALID_SET
    $AMHintsTable.Add("0x80070778", "The object set specified was not found.")
    #RPC_S_SEND_INCOMPLETE
    $AMHintsTable.Add("0x80070779", "Some data remains to be sent in the request buffer.")
    #RPC_S_INVALID_ASYNC_HANDLE
    $AMHintsTable.Add("0x8007077A", "Invalid asynchronous RPC handle.")
    #RPC_S_INVALID_ASYNC_CALL
    $AMHintsTable.Add("0x8007077B", "Invalid asynchronous RPC call handle for this operation.")
    #RPC_X_PIPE_CLOSED
    $AMHintsTable.Add("0x8007077C", "The RPC pipe object has already been closed.")
    #RPC_X_PIPE_DISCIPLINE_ERROR
    $AMHintsTable.Add("0x8007077D", "The RPC call completed before all pipes were processed.")
    #RPC_X_PIPE_EMPTY
    $AMHintsTable.Add("0x8007077E", "No more data is available from the RPC pipe.")
    #ERROR_NO_SITENAME
    $AMHintsTable.Add("0x8007077F", "No site name is available for this machine.")
    #ERROR_CANT_ACCESS_FILE
    $AMHintsTable.Add("0x80070780", "The file cannot be accessed by the system.")
    #ERROR_CANT_RESOLVE_FILENAME
    $AMHintsTable.Add("0x80070781", "The name of the file cannot be resolved by the system.")
    #RPC_S_ENTRY_TYPE_MISMATCH
    $AMHintsTable.Add("0x80070782", "The entry is not of the expected type.")
    #RPC_S_NOT_ALL_OBJS_EXPORTED
    $AMHintsTable.Add("0x80070783", "Not all object UUIDs could be exported to the specified entry.")
    #RPC_S_INTERFACE_NOT_EXPORTED
    $AMHintsTable.Add("0x80070784", "The interface could not be exported to the specified entry.")
    #RPC_S_PROFILE_NOT_ADDED
    $AMHintsTable.Add("0x80070785", "The specified profile entry could not be added.")
    #RPC_S_PRF_ELT_NOT_ADDED
    $AMHintsTable.Add("0x80070786", "The specified profile element could not be added.")
    #RPC_S_PRF_ELT_NOT_REMOVED
    $AMHintsTable.Add("0x80070787", "The specified profile element could not be removed.")
    #RPC_S_GRP_ELT_NOT_ADDED
    $AMHintsTable.Add("0x80070788", "The group element could not be added.")
    #RPC_S_GRP_ELT_NOT_REMOVED
    $AMHintsTable.Add("0x80070789", "The group element could not be removed.")
    #ERROR_KM_DRIVER_BLOCKED
    $AMHintsTable.Add("0x8007078A", "The printer driver is not compatible with a policy enabled on your computer that blocks Windows NT 4.0 drivers.")
    #ERROR_CONTEXT_EXPIRED
    $AMHintsTable.Add("0x8007078B", "The context has expired and can no longer be used.")
    #ERROR_PER_USER_TRUST_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x8007078C", "The current user's delegated trust creation quota has been exceeded.")
    #ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x8007078D", "The total delegated trust creation quota has been exceeded.")
    #ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x8007078E", "The current user's delegated trust deletion quota has been exceeded.")
    #ERROR_AUTHENTICATION_FIREWALL_FAILED
    $AMHintsTable.Add("0x8007078F", "Logon failure: The machine you are logging on to is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.")
    #ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED
    $AMHintsTable.Add("0x80070790", "Remote connections to the Print Spooler are blocked by a policy set on your machine.")
    #ERROR_INVALID_PIXEL_FORMAT
    $AMHintsTable.Add("0x800707D0", "The pixel format is invalid.")
    #ERROR_BAD_DRIVER
    $AMHintsTable.Add("0x800707D1", "The specified driver is invalid.")
    #ERROR_INVALID_WINDOW_STYLE
    $AMHintsTable.Add("0x800707D2", "The window style or class attribute is invalid for this operation.")
    #ERROR_METAFILE_NOT_SUPPORTED
    $AMHintsTable.Add("0x800707D3", "The requested metafile operation is not supported.")
    #ERROR_TRANSFORM_NOT_SUPPORTED
    $AMHintsTable.Add("0x800707D4", "The requested transformation operation is not supported.")
    #ERROR_CLIPPING_NOT_SUPPORTED
    $AMHintsTable.Add("0x800707D5", "The requested clipping operation is not supported.")
    #ERROR_INVALID_CMM
    $AMHintsTable.Add("0x800707DA", "The specified color management module is invalid.")
    #ERROR_INVALID_PROFILE
    $AMHintsTable.Add("0x800707DB", "The specified color profile is invalid.")
    #ERROR_TAG_NOT_FOUND
    $AMHintsTable.Add("0x800707DC", "The specified tag was not found.")
    #ERROR_TAG_NOT_PRESENT
    $AMHintsTable.Add("0x800707DD", "A required tag is not present.")
    #ERROR_DUPLICATE_TAG
    $AMHintsTable.Add("0x800707DE", "The specified tag is already present.")
    #ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE
    $AMHintsTable.Add("0x800707DF", "The specified color profile is not associated with any device.")
    #ERROR_PROFILE_NOT_FOUND
    $AMHintsTable.Add("0x800707E0", "The specified color profile was not found.")
    #ERROR_INVALID_COLORSPACE
    $AMHintsTable.Add("0x800707E1", "The specified color space is invalid.")
    #ERROR_ICM_NOT_ENABLED
    $AMHintsTable.Add("0x800707E2", "Image Color Management is not enabled.")
    #ERROR_DELETING_ICM_XFORM
    $AMHintsTable.Add("0x800707E3", "There was an error while deleting the color transform.")
    #ERROR_INVALID_TRANSFORM
    $AMHintsTable.Add("0x800707E4", "The specified color transform is invalid.")
    #ERROR_COLORSPACE_MISMATCH
    $AMHintsTable.Add("0x800707E5", "The specified transform does not match the bitmap's color space.")
    #ERROR_INVALID_COLORINDEX
    $AMHintsTable.Add("0x800707E6", "The specified named color index is not present in the profile.")
    #ERROR_PROFILE_DOES_NOT_MATCH_DEVICE
    $AMHintsTable.Add("0x800707E7", "The specified profile is intended for a device of a different type than the specified device.")
    #NERR_NetNotStarted
    $AMHintsTable.Add("0x80070836", "The workstation driver is not installed.")
    #NERR_UnknownServer
    $AMHintsTable.Add("0x80070837", "The server could not be located.")
    #NERR_ShareMem
    $AMHintsTable.Add("0x80070838", "An internal error occurred. The network cannot access a shared memory segment.")
    #NERR_NoNetworkResource
    $AMHintsTable.Add("0x80070839", "A network resource shortage occurred.")
    #NERR_RemoteOnly
    $AMHintsTable.Add("0x8007083A", "This operation is not supported on workstations.")
    #NERR_DevNotRedirected
    $AMHintsTable.Add("0x8007083B", "The device is not connected.")
    #ERROR_CONNECTED_OTHER_PASSWORD
    $AMHintsTable.Add("0x8007083C", "The network connection was made successfully, but the user had to be prompted for a password other than the one originally specified.")
    #ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT
    $AMHintsTable.Add("0x8007083D", "The network connection was made successfully using default credentials.")
    #NERR_ServerNotStarted
    $AMHintsTable.Add("0x80070842", "The Server service is not started.")
    #NERR_ItemNotFound
    $AMHintsTable.Add("0x80070843", "The queue is empty.")
    #NERR_UnknownDevDir
    $AMHintsTable.Add("0x80070844", "The device or directory does not exist.")
    #NERR_RedirectedPath
    $AMHintsTable.Add("0x80070845", "The operation is invalid on a redirected resource.")
    #NERR_DuplicateShare
    $AMHintsTable.Add("0x80070846", "The name has already been shared.")
    #NERR_NoRoom
    $AMHintsTable.Add("0x80070847", "The server is currently out of the requested resource.")
    #NERR_TooManyItems
    $AMHintsTable.Add("0x80070849", "Requested addition of items exceeds the maximum allowed.")
    #NERR_InvalidMaxUsers
    $AMHintsTable.Add("0x8007084A", "The Peer service supports only two simultaneous users.")
    #NERR_BufTooSmall
    $AMHintsTable.Add("0x8007084B", "The API return buffer is too small.")
    #NERR_RemoteErr
    $AMHintsTable.Add("0x8007084F", "A remote API error occurred.")
    #NERR_LanmanIniError
    $AMHintsTable.Add("0x80070853", "An error occurred when opening or reading the configuration file.")
    #NERR_NetworkError
    $AMHintsTable.Add("0x80070858", "A general network error occurred.")
    #NERR_WkstaInconsistentState
    $AMHintsTable.Add("0x80070859", "The Workstation service is in an inconsistent state. Restart the computer before restarting the Workstation service.")
    #NERR_WkstaNotStarted
    $AMHintsTable.Add("0x8007085A", "The Workstation service has not been started.")
    #NERR_BrowserNotStarted
    $AMHintsTable.Add("0x8007085B", "The requested information is not available.")
    #NERR_InternalError
    $AMHintsTable.Add("0x8007085C", "An internal error occurred.")
    #NERR_BadTransactConfig
    $AMHintsTable.Add("0x8007085D", "The server is not configured for transactions.")
    #NERR_InvalidAPI
    $AMHintsTable.Add("0x8007085E", "The requested API is not supported on the remote server.")
    #NERR_BadEventName
    $AMHintsTable.Add("0x8007085F", "The event name is invalid.")
    #NERR_DupNameReboot
    $AMHintsTable.Add("0x80070860", "The computer name already exists on the network. Change it and reboot the computer.")
    #NERR_CfgCompNotFound
    $AMHintsTable.Add("0x80070862", "The specified component could not be found in the configuration information.")
    #NERR_CfgParamNotFound
    $AMHintsTable.Add("0x80070863", "The specified parameter could not be found in the configuration information.")
    #NERR_LineTooLong
    $AMHintsTable.Add("0x80070865", "A line in the configuration file is too long.")
    #NERR_QNotFound
    $AMHintsTable.Add("0x80070866", "The printer does not exist.")
    #NERR_JobNotFound
    $AMHintsTable.Add("0x80070867", "The print job does not exist.")
    #NERR_DestNotFound
    $AMHintsTable.Add("0x80070868", "The printer destination cannot be found.")
    #NERR_DestExists
    $AMHintsTable.Add("0x80070869", "The printer destination already exists.")
    #NERR_QExists
    $AMHintsTable.Add("0x8007086A", "The print queue already exists.")
    #NERR_QNoRoom
    $AMHintsTable.Add("0x8007086B", "No more printers can be added.")
    #NERR_JobNoRoom
    $AMHintsTable.Add("0x8007086C", "No more print jobs can be added.")
    #NERR_DestNoRoom
    $AMHintsTable.Add("0x8007086D", "No more printer destinations can be added.")
    #NERR_DestIdle
    $AMHintsTable.Add("0x8007086E", "This printer destination is idle and cannot accept control operations.")
    #NERR_DestInvalidOp
    $AMHintsTable.Add("0x8007086F", "This printer destination request contains an invalid control function.")
    #NERR_ProcNoRespond
    $AMHintsTable.Add("0x80070870", "The print processor is not responding.")
    #NERR_SpoolerNotLoaded
    $AMHintsTable.Add("0x80070871", "The spooler is not running.")
    #NERR_DestInvalidState
    $AMHintsTable.Add("0x80070872", "This operation cannot be performed on the print destination in its current state.")
    #NERR_QinvalidState
    $AMHintsTable.Add("0x80070873", "This operation cannot be performed on the print queue in its current state.")
    #NERR_JobInvalidState
    $AMHintsTable.Add("0x80070874", "This operation cannot be performed on the print job in its current state.")
    #NERR_SpoolNoMemory
    $AMHintsTable.Add("0x80070875", "A spooler memory allocation failure occurred.")
    #NERR_DriverNotFound
    $AMHintsTable.Add("0x80070876", "The device driver does not exist.")
    #NERR_DataTypeInvalid
    $AMHintsTable.Add("0x80070877", "The data type is not supported by the print processor.")
    #NERR_ProcNotFound
    $AMHintsTable.Add("0x80070878", "The print processor is not installed.")
    #NERR_ServiceTableLocked
    $AMHintsTable.Add("0x80070884", "The service database is locked.")
    #NERR_ServiceTableFull
    $AMHintsTable.Add("0x80070885", "The service table is full.")
    #NERR_ServiceInstalled
    $AMHintsTable.Add("0x80070886", "The requested service has already been started.")
    #NERR_ServiceEntryLocked
    $AMHintsTable.Add("0x80070887", "The service does not respond to control actions.")
    #NERR_ServiceNotInstalled
    $AMHintsTable.Add("0x80070888", "The service has not been started.")
    #NERR_BadServiceName
    $AMHintsTable.Add("0x80070889", "The service name is invalid.")
    #NERR_ServiceCtlTimeout
    $AMHintsTable.Add("0x8007088A", "The service is not responding to the control function.")
    #NERR_ServiceCtlBusy
    $AMHintsTable.Add("0x8007088B", "The service control is busy.")
    #NERR_BadServiceProgName
    $AMHintsTable.Add("0x8007088C", "The configuration file contains an invalid service program name.")
    #NERR_ServiceNotCtrl
    $AMHintsTable.Add("0x8007088D", "The service could not be controlled in its present state.")
    #NERR_ServiceKillProc
    $AMHintsTable.Add("0x8007088E", "The service ended abnormally.")
    #NERR_ServiceCtlNotValid
    $AMHintsTable.Add("0x8007088F", "The requested pause or stop is not valid for this service.")
    #NERR_NotInDispatchTbl
    $AMHintsTable.Add("0x80070890", "The service control dispatcher could not find the service name in the dispatch table.")
    #NERR_BadControlRecv
    $AMHintsTable.Add("0x80070891", "The service control dispatcher pipe read failed.")
    #NERR_ServiceNotStarting
    $AMHintsTable.Add("0x80070892", "A thread for the new service could not be created.")
    #NERR_AlreadyLoggedOn
    $AMHintsTable.Add("0x80070898", "This workstation is already logged on to the LAN.")
    #NERR_NotLoggedOn
    $AMHintsTable.Add("0x80070899", "The workstation is not logged on to the LAN.")
    #NERR_BadUsername
    $AMHintsTable.Add("0x8007089A", "The user name or group name parameter is invalid.")
    #NERR_BadPassword
    $AMHintsTable.Add("0x8007089B", "The password parameter is invalid.")
    #NERR_UnableToAddName_W
    $AMHintsTable.Add("0x8007089C", "The logon processor did not add the message alias.")
    #NERR_UnableToAddName_F
    $AMHintsTable.Add("0x8007089D", "The logon processor did not add the message alias.")
    #NERR_UnableToDelName_W
    $AMHintsTable.Add("0x8007089E", "@W The logoff processor did not delete the message alias.")
    #NERR_UnableToDelName_F
    $AMHintsTable.Add("0x8007089F", "The logoff processor did not delete the message alias.")
    #NERR_LogonsPaused
    $AMHintsTable.Add("0x800708A1", "Network logons are paused.")
    #NERR_LogonServerConflict
    $AMHintsTable.Add("0x800708A2", "A centralized logon server conflict occurred.")
    #NERR_LogonNoUserPath
    $AMHintsTable.Add("0x800708A3", "The server is configured without a valid user path.")
    #NERR_LogonScriptError
    $AMHintsTable.Add("0x800708A4", "An error occurred while loading or running the logon script.")
    #NERR_StandaloneLogon
    $AMHintsTable.Add("0x800708A6", "The logon server was not specified. The computer will be logged on as STANDALONE.")
    #NERR_LogonServerNotFound
    $AMHintsTable.Add("0x800708A7", "The logon server could not be found.")
    #NERR_LogonDomainExists
    $AMHintsTable.Add("0x800708A8", "There is already a logon domain for this computer.")
    #NERR_NonValidatedLogon
    $AMHintsTable.Add("0x800708A9", "The logon server could not validate the logon.")
    #NERR_ACFNotFound
    $AMHintsTable.Add("0x800708AB", "The security database could not be found.")
    #NERR_GroupNotFound
    $AMHintsTable.Add("0x800708AC", "The group name could not be found.")
    #NERR_UserNotFound
    $AMHintsTable.Add("0x800708AD", "The user name could not be found.")
    #NERR_ResourceNotFound
    $AMHintsTable.Add("0x800708AE", "The resource name could not be found.")
    #NERR_GroupExists
    $AMHintsTable.Add("0x800708AF", "The group already exists.")
    #NERR_UserExists
    $AMHintsTable.Add("0x800708B0", "The user account already exists.")
    #NERR_ResourceExists
    $AMHintsTable.Add("0x800708B1", "The resource permission list already exists.")
    #NERR_NotPrimary
    $AMHintsTable.Add("0x800708B2", "This operation is allowed only on the PDC of the domain.")
    #NERR_ACFNotLoaded
    $AMHintsTable.Add("0x800708B3", "The security database has not been started.")
    #NERR_ACFNoRoom
    $AMHintsTable.Add("0x800708B4", "There are too many names in the user accounts database.")
    #NERR_ACFFileIOFail
    $AMHintsTable.Add("0x800708B5", "A disk I/O failure occurred.")
    #NERR_ACFTooManyLists
    $AMHintsTable.Add("0x800708B6", "The limit of 64 entries per resource was exceeded.")
    #NERR_UserLogon
    $AMHintsTable.Add("0x800708B7", "Deleting a user with a session is not allowed.")
    #NERR_ACFNoParent
    $AMHintsTable.Add("0x800708B8", "The parent directory could not be located.")
    #NERR_CanNotGrowSegment
    $AMHintsTable.Add("0x800708B9", "Unable to add to the security database session cache segment.")
    #NERR_SpeGroupOp
    $AMHintsTable.Add("0x800708BA", "This operation is not allowed on this special group.")
    #NERR_NotInCache
    $AMHintsTable.Add("0x800708BB", "This user is not cached in the user accounts database session cache.")
    #NERR_UserInGroup
    $AMHintsTable.Add("0x800708BC", "The user already belongs to this group.")
    #NERR_UserNotInGroup
    $AMHintsTable.Add("0x800708BD", "The user does not belong to this group.")
    #NERR_AccountUndefined
    $AMHintsTable.Add("0x800708BE", "This user account is undefined.")
    #NERR_AccountExpired
    $AMHintsTable.Add("0x800708BF", "This user account has expired.")
    #NERR_InvalidWorkstation
    $AMHintsTable.Add("0x800708C0", "The user is not allowed to log on from this workstation.")
    #NERR_InvalidLogonHours
    $AMHintsTable.Add("0x800708C1", "The user is not allowed to log on at this time.")
    #NERR_PasswordExpired
    $AMHintsTable.Add("0x800708C2", "The password of this user has expired.")
    #NERR_PasswordCantChange
    $AMHintsTable.Add("0x800708C3", "The password of this user cannot change.")
    #NERR_PasswordHistConflict
    $AMHintsTable.Add("0x800708C4", "This password cannot be used now.")
    #NERR_PasswordTooShort
    $AMHintsTable.Add("0x800708C5", "The password does not meet the password policy requirements. Check the minimum password length, password complexity, and password history requirements.")
    #NERR_PasswordTooRecent
    $AMHintsTable.Add("0x800708C6", "The password of this user is too recent to change.")
    #NERR_InvalidDatabase
    $AMHintsTable.Add("0x800708C7", "The security database is corrupted.")
    #NERR_DatabaseUpToDate
    $AMHintsTable.Add("0x800708C8", "No updates are necessary to this replicant network or local security database.")
    #NERR_SyncRequired
    $AMHintsTable.Add("0x800708C9", "This replicant database is outdated; synchronization is required.")
    #NERR_UseNotFound
    $AMHintsTable.Add("0x800708CA", "The network connection could not be found.")
    #NERR_BadAsgType
    $AMHintsTable.Add("0x800708CB", "This asg_type is invalid.")
    #NERR_DeviceIsShared
    $AMHintsTable.Add("0x800708CC", "This device is currently being shared.")
    #NERR_NoComputerName
    $AMHintsTable.Add("0x800708DE", "The computer name could not be added as a message alias. The name may already exist on the network.")
    #NERR_MsgAlreadyStarted
    $AMHintsTable.Add("0x800708DF", "The Messenger service is already started.")
    #NERR_MsgInitFailed
    $AMHintsTable.Add("0x800708E0", "The Messenger service failed to start.")
    #NERR_NameNotFound
    $AMHintsTable.Add("0x800708E1", "The message alias could not be found on the network.")
    #NERR_AlreadyForwarded
    $AMHintsTable.Add("0x800708E2", "This message alias has already been forwarded.")
    #NERR_AddForwarded
    $AMHintsTable.Add("0x800708E3", "This message alias has been added but is still forwarded.")
    #NERR_AlreadyExists
    $AMHintsTable.Add("0x800708E4", "This message alias already exists locally.")
    #NERR_TooManyNames
    $AMHintsTable.Add("0x800708E5", "The maximum number of added message aliases has been exceeded.")
    #NERR_DelComputerName
    $AMHintsTable.Add("0x800708E6", "The computer name could not be deleted.")
    #NERR_LocalForward
    $AMHintsTable.Add("0x800708E7", "Messages cannot be forwarded back to the same workstation.")
    #NERR_GrpMsgProcessor
    $AMHintsTable.Add("0x800708E8", "An error occurred in the domain message processor.")
    #NERR_PausedRemote
    $AMHintsTable.Add("0x800708E9", "The message was sent, but the recipient has paused the Messenger service.")
    #NERR_BadReceive
    $AMHintsTable.Add("0x800708EA", "The message was sent but not received.")
    #NERR_NameInUse
    $AMHintsTable.Add("0x800708EB", "The message alias is currently in use. Try again later.")
    #NERR_MsgNotStarted
    $AMHintsTable.Add("0x800708EC", "The Messenger service has not been started.")
    #NERR_NotLocalName
    $AMHintsTable.Add("0x800708ED", "The name is not on the local computer.")
    #NERR_NoForwardName
    $AMHintsTable.Add("0x800708EE", "The forwarded message alias could not be found on the network.")
    #NERR_RemoteFull
    $AMHintsTable.Add("0x800708EF", "The message alias table on the remote station is full.")
    #NERR_NameNotForwarded
    $AMHintsTable.Add("0x800708F0", "Messages for this alias are not currently being forwarded.")
    #NERR_TruncatedBroadcast
    $AMHintsTable.Add("0x800708F1", "The broadcast message was truncated.")
    #NERR_InvalidDevice
    $AMHintsTable.Add("0x800708F6", "This is an invalid device name.")
    #NERR_WriteFault
    $AMHintsTable.Add("0x800708F7", "A write fault occurred.")
    #NERR_DuplicateName
    $AMHintsTable.Add("0x800708F9", "A duplicate message alias exists on the network.")
    #NERR_DeleteLater
    $AMHintsTable.Add("0x800708FA", "This message alias will be deleted later.")
    #NERR_IncompleteDel
    $AMHintsTable.Add("0x800708FB", "The message alias was not successfully deleted from all networks.")
    #NERR_MultipleNets
    $AMHintsTable.Add("0x800708FC", "This operation is not supported on computers with multiple networks.")
    #NERR_NetNameNotFound
    $AMHintsTable.Add("0x80070906", "This shared resource does not exist.")
    #NERR_DeviceNotShared
    $AMHintsTable.Add("0x80070907", "This device is not shared.")
    #NERR_ClientNameNotFound
    $AMHintsTable.Add("0x80070908", "A session does not exist with that computer name.")
    #NERR_FileIdNotFound
    $AMHintsTable.Add("0x8007090A", "There is not an open file with that identification number.")
    #NERR_ExecFailure
    $AMHintsTable.Add("0x8007090B", "A failure occurred when executing a remote administration command.")
    #NERR_TmpFile
    $AMHintsTable.Add("0x8007090C", "A failure occurred when opening a remote temporary file.")
    #NERR_TooMuchData
    $AMHintsTable.Add("0x8007090D", "The data returned from a remote administration command has been truncated to 64 KB.")
    #NERR_DeviceShareConflict
    $AMHintsTable.Add("0x8007090E", "This device cannot be shared as both a spooled and a nonspooled resource.")
    #NERR_BrowserTableIncomplete
    $AMHintsTable.Add("0x8007090F", "The information in the list of servers may be incorrect.")
    #NERR_NotLocalDomain
    $AMHintsTable.Add("0x80070910", "The computer is not active in this domain.")
    #NERR_IsDfsShare
    $AMHintsTable.Add("0x80070911", "The share must be removed from the Distributed File System (DFS) before it can be deleted.")
    #NERR_DevInvalidOpCode
    $AMHintsTable.Add("0x8007091B", "The operation is invalid for this device.")
    #NERR_DevNotFound
    $AMHintsTable.Add("0x8007091C", "This device cannot be shared.")
    #NERR_DevNotOpen
    $AMHintsTable.Add("0x8007091D", "This device was not open.")
    #NERR_BadQueueDevString
    $AMHintsTable.Add("0x8007091E", "This device name list is invalid.")
    #NERR_BadQueuePriority
    $AMHintsTable.Add("0x8007091F", "The queue priority is invalid.")
    #NERR_NoCommDevs
    $AMHintsTable.Add("0x80070921", "There are no shared communication devices.")
    #NERR_QueueNotFound
    $AMHintsTable.Add("0x80070922", "The queue you specified does not exist.")
    #NERR_BadDevString
    $AMHintsTable.Add("0x80070924", "This list of devices is invalid.")
    #NERR_BadDev
    $AMHintsTable.Add("0x80070925", "The requested device is invalid.")
    #NERR_InUseBySpooler
    $AMHintsTable.Add("0x80070926", "This device is already in use by the spooler.")
    #NERR_CommDevInUse
    $AMHintsTable.Add("0x80070927", "This device is already in use as a communication device.")
    #NERR_InvalidComputer
    $AMHintsTable.Add("0x8007092F", "This computer name is invalid.")
    #NERR_MaxLenExceeded
    $AMHintsTable.Add("0x80070932", "The string and prefix specified are too long.")
    #NERR_BadComponent
    $AMHintsTable.Add("0x80070934", "This path component is invalid.")
    #NERR_CantType
    $AMHintsTable.Add("0x80070935", "Could not determine the type of input.")
    #NERR_TooManyEntries
    $AMHintsTable.Add("0x8007093A", "The buffer for types is not big enough.")
    #NERR_ProfileFileTooBig
    $AMHintsTable.Add("0x80070942", "Profile files cannot exceed 64 KB.")
    #NERR_ProfileOffset
    $AMHintsTable.Add("0x80070943", "The start offset is out of range.")
    #NERR_ProfileCleanup
    $AMHintsTable.Add("0x80070944", "The system cannot delete current connections to network resources.")
    #NERR_ProfileUnknownCmd
    $AMHintsTable.Add("0x80070945", "The system was unable to parse the command line in this file.")
    #NERR_ProfileLoadErr
    $AMHintsTable.Add("0x80070946", "An error occurred while loading the profile file.")
    #NERR_ProfileSaveErr
    $AMHintsTable.Add("0x80070947", "Errors occurred while saving the profile file. The profile was partially saved.")
    #NERR_LogOverflow
    $AMHintsTable.Add("0x80070949", "Log file %1 is full.")
    #NERR_LogFileChanged
    $AMHintsTable.Add("0x8007094A", "This log file has changed between reads.")
    #NERR_LogFileCorrupt
    $AMHintsTable.Add("0x8007094B", "Log file %1 is corrupt.")
    #NERR_SourceIsDir
    $AMHintsTable.Add("0x8007094C", "The source path cannot be a directory.")
    #NERR_BadSource
    $AMHintsTable.Add("0x8007094D", "The source path is illegal.")
    #NERR_BadDest
    $AMHintsTable.Add("0x8007094E", "The destination path is illegal.")
    #NERR_DifferentServers
    $AMHintsTable.Add("0x8007094F", "The source and destination paths are on different servers.")
    #NERR_RunSrvPaused
    $AMHintsTable.Add("0x80070951", "The Run server you requested is paused.")
    #NERR_ErrCommRunSrv
    $AMHintsTable.Add("0x80070955", "An error occurred when communicating with a Run server.")
    #NERR_ErrorExecingGhost
    $AMHintsTable.Add("0x80070957", "An error occurred when starting a background process.")
    #NERR_ShareNotFound
    $AMHintsTable.Add("0x80070958", "The shared resource you are connected to could not be found.")
    #NERR_InvalidLana
    $AMHintsTable.Add("0x80070960", "The LAN adapter number is invalid.")
    #NERR_OpenFiles
    $AMHintsTable.Add("0x80070961", "There are open files on the connection.")
    #NERR_ActiveConns
    $AMHintsTable.Add("0x80070962", "Active connections still exist.")
    #NERR_BadPasswordCore
    $AMHintsTable.Add("0x80070963", "This share name or password is invalid.")
    #NERR_DevInUse
    $AMHintsTable.Add("0x80070964", "The device is being accessed by an active process.")
    #NERR_LocalDrive
    $AMHintsTable.Add("0x80070965", "The drive letter is in use locally.")
    #NERR_AlertExists
    $AMHintsTable.Add("0x8007097E", "The specified client is already registered for the specified event.")
    #NERR_TooManyAlerts
    $AMHintsTable.Add("0x8007097F", "The alert table is full.")
    #NERR_NoSuchAlert
    $AMHintsTable.Add("0x80070980", "An invalid or nonexistent alert name was raised.")
    #NERR_BadRecipient
    $AMHintsTable.Add("0x80070981", "The alert recipient is invalid.")
    #NERR_AcctLimitExceeded
    $AMHintsTable.Add("0x80070982", "A user's session with this server has been deleted.")
    #NERR_InvalidLogSeek
    $AMHintsTable.Add("0x80070988", "The log file does not contain the requested record number.")
    #NERR_BadUasConfig
    $AMHintsTable.Add("0x80070992", "The user accounts database is not configured correctly.")
    #NERR_InvalidUASOp
    $AMHintsTable.Add("0x80070993", "This operation is not permitted when the Net Logon service is running.")
    #NERR_LastAdmin
    $AMHintsTable.Add("0x80070994", "This operation is not allowed on the last administrative account.")
    #NERR_DCNotFound
    $AMHintsTable.Add("0x80070995", "Could not find the domain controller for this domain.")
    #NERR_LogonTrackingError
    $AMHintsTable.Add("0x80070996", "Could not set logon information for this user.")
    #NERR_NetlogonNotStarted
    $AMHintsTable.Add("0x80070997", "The Net Logon service has not been started.")
    #NERR_CanNotGrowUASFile
    $AMHintsTable.Add("0x80070998", "Unable to add to the user accounts database.")
    #NERR_TimeDiffAtDC
    $AMHintsTable.Add("0x80070999", "This server's clock is not synchronized with the PDC's clock.")
    #NERR_PasswordMismatch
    $AMHintsTable.Add("0x8007099A", "A password mismatch has been detected.")
    #NERR_NoSuchServer
    $AMHintsTable.Add("0x8007099C", "The server identification does not specify a valid server.")
    #NERR_NoSuchSession
    $AMHintsTable.Add("0x8007099D", "The session identification does not specify a valid session.")
    #NERR_NoSuchConnection
    $AMHintsTable.Add("0x8007099E", "The connection identification does not specify a valid connection.")
    #NERR_TooManyServers
    $AMHintsTable.Add("0x8007099F", "There is no space for another entry in the table of available servers.")
    #NERR_TooManySessions
    $AMHintsTable.Add("0x800709A0", "The server has reached the maximum number of sessions it supports.")
    #NERR_TooManyConnections
    $AMHintsTable.Add("0x800709A1", "The server has reached the maximum number of connections it supports.")
    #NERR_TooManyFiles
    $AMHintsTable.Add("0x800709A2", "The server cannot open more files because it has reached its maximum number.")
    #NERR_NoAlternateServers
    $AMHintsTable.Add("0x800709A3", "There are no alternate servers registered on this server.")
    #NERR_TryDownLevel
    $AMHintsTable.Add("0x800709A6", "Try the down-level (remote admin protocol) version of API instead.")
    #NERR_UPSDriverNotStarted
    $AMHintsTable.Add("0x800709B0", "The uninterruptible power supply (UPS) driver could not be accessed by the UPS service.")
    #NERR_UPSInvalidConfig
    $AMHintsTable.Add("0x800709B1", "The UPS service is not configured correctly.")
    #NERR_UPSInvalidCommPort
    $AMHintsTable.Add("0x800709B2", "The UPS service could not access the specified Comm Port.")
    #NERR_UPSSignalAsserted
    $AMHintsTable.Add("0x800709B3", "The UPS indicated a line fail or low battery situation. Service not started.")
    #NERR_UPSShutdownFailed
    $AMHintsTable.Add("0x800709B4", "The UPS service failed to perform a system shut down.")
    #NERR_BadDosRetCode
    $AMHintsTable.Add("0x800709C4", "The program below returned an MS-DOS error code.")
    #NERR_ProgNeedsExtraMem
    $AMHintsTable.Add("0x800709C5", "The program below needs more memory.")
    #NERR_BadDosFunction
    $AMHintsTable.Add("0x800709C6", "The program below called an unsupported MS-DOS function.")
    #NERR_RemoteBootFailed
    $AMHintsTable.Add("0x800709C7", "The workstation failed to boot.")
    #NERR_BadFileCheckSum
    $AMHintsTable.Add("0x800709C8", "The file below is corrupt.")
    #NERR_NoRplBootSystem
    $AMHintsTable.Add("0x800709C9", "No loader is specified in the boot-block definition file.")
    #NERR_RplLoadrNetBiosErr
    $AMHintsTable.Add("0x800709CA", "NetBIOS returned an error: The network control blocks (NCBs) and Server Message Block (SMB) are dumped above.")
    #NERR_RplLoadrDiskErr
    $AMHintsTable.Add("0x800709CB", "A disk I/O error occurred.")
    #NERR_ImageParamErr
    $AMHintsTable.Add("0x800709CC", "Image parameter substitution failed.")
    #NERR_TooManyImageParams
    $AMHintsTable.Add("0x800709CD", "Too many image parameters cross disk sector boundaries.")
    #NERR_NonDosFloppyUsed
    $AMHintsTable.Add("0x800709CE", "The image was not generated from an MS-DOS disk formatted with /S.")
    #NERR_RplBootRestart
    $AMHintsTable.Add("0x800709CF", "Remote boot will be restarted later.")
    #NERR_RplSrvrCallFailed
    $AMHintsTable.Add("0x800709D0", "The call to the Remoteboot server failed.")
    #NERR_CantConnectRplSrvr
    $AMHintsTable.Add("0x800709D1", "Cannot connect to the Remoteboot server.")
    #NERR_CantOpenImageFile
    $AMHintsTable.Add("0x800709D2", "Cannot open image file on the Remoteboot server.")
    #NERR_CallingRplSrvr
    $AMHintsTable.Add("0x800709D3", "Connecting to the Remoteboot server.")
    #NERR_StartingRplBoot
    $AMHintsTable.Add("0x800709D4", "Connecting to the Remoteboot server.")
    #NERR_RplBootServiceTerm
    $AMHintsTable.Add("0x800709D5", "Remote boot service was stopped, check the error log for the cause of the problem.")
    #NERR_RplBootStartFailed
    $AMHintsTable.Add("0x800709D6", "Remote boot startup failed; check the error log for the cause of the problem.")
    #NERR_RPL_CONNECTED
    $AMHintsTable.Add("0x800709D7", "A second connection to a Remoteboot resource is not allowed.")
    #NERR_BrowserConfiguredToNotRun
    $AMHintsTable.Add("0x800709F6", "The browser service was configured with MaintainServerList=No.")
    #NERR_RplNoAdaptersStarted
    $AMHintsTable.Add("0x80070A32", "Service failed to start because none of the network adapters started with this service.")
    #NERR_RplBadRegistry
    $AMHintsTable.Add("0x80070A33", "Service failed to start due to bad startup information in the registry.")
    #NERR_RplBadDatabase
    $AMHintsTable.Add("0x80070A34", "Service failed to start because its database is absent or corrupt.")
    #NERR_RplRplfilesShare
    $AMHintsTable.Add("0x80070A35", "Service failed to start because the RPLFILES share is absent.")
    #NERR_RplNotRplServer
    $AMHintsTable.Add("0x80070A36", "Service failed to start because the RPLUSER group is absent.")
    #NERR_RplCannotEnum
    $AMHintsTable.Add("0x80070A37", "Cannot enumerate service records.")
    #NERR_RplWkstaInfoCorrupted
    $AMHintsTable.Add("0x80070A38", "Workstation record information has been corrupted.")
    #NERR_RplWkstaNotFound
    $AMHintsTable.Add("0x80070A39", "Workstation record was not found.")
    #NERR_RplWkstaNameUnavailable
    $AMHintsTable.Add("0x80070A3A", "Workstation name is in use by some other workstation.")
    #NERR_RplProfileInfoCorrupted
    $AMHintsTable.Add("0x80070A3B", "Profile record information has been corrupted.")
    #NERR_RplProfileNotFound
    $AMHintsTable.Add("0x80070A3C", "Profile record was not found.")
    #NERR_RplProfileNameUnavailable
    $AMHintsTable.Add("0x80070A3D", "Profile name is in use by some other profile.")
    #NERR_RplProfileNotEmpty
    $AMHintsTable.Add("0x80070A3E", "There are workstations using this profile.")
    #NERR_RplConfigInfoCorrupted
    $AMHintsTable.Add("0x80070A3F", "Configuration record information has been corrupted.")
    #NERR_RplConfigNotFound
    $AMHintsTable.Add("0x80070A40", "Configuration record was not found.")
    #NERR_RplAdapterInfoCorrupted
    $AMHintsTable.Add("0x80070A41", "Adapter ID record information has been corrupted.")
    #NERR_RplInternal
    $AMHintsTable.Add("0x80070A42", "An internal service error has occurred.")
    #NERR_RplVendorInfoCorrupted
    $AMHintsTable.Add("0x80070A43", "Vendor ID record information has been corrupted.")
    #NERR_RplBootInfoCorrupted
    $AMHintsTable.Add("0x80070A44", "Boot block record information has been corrupted.")
    #NERR_RplWkstaNeedsUserAcct
    $AMHintsTable.Add("0x80070A45", "The user account for this workstation record is missing.")
    #NERR_RplNeedsRPLUSERAcct
    $AMHintsTable.Add("0x80070A46", "The RPLUSER local group could not be found.")
    #NERR_RplBootNotFound
    $AMHintsTable.Add("0x80070A47", "Boot block record was not found.")
    #NERR_RplIncompatibleProfile
    $AMHintsTable.Add("0x80070A48", "Chosen profile is incompatible with this workstation.")
    #NERR_RplAdapterNameUnavailable
    $AMHintsTable.Add("0x80070A49", "Chosen network adapter ID is in use by some other workstation.")
    #NERR_RplConfigNotEmpty
    $AMHintsTable.Add("0x80070A4A", "There are profiles using this configuration.")
    #NERR_RplBootInUse
    $AMHintsTable.Add("0x80070A4B", "There are workstations, profiles, or configurations using this boot block.")
    #NERR_RplBackupDatabase
    $AMHintsTable.Add("0x80070A4C", "Service failed to back up the Remoteboot database.")
    #NERR_RplAdapterNotFound
    $AMHintsTable.Add("0x80070A4D", "Adapter record was not found.")
    #NERR_RplVendorNotFound
    $AMHintsTable.Add("0x80070A4E", "Vendor record was not found.")
    #NERR_RplVendorNameUnavailable
    $AMHintsTable.Add("0x80070A4F", "Vendor name is in use by some other vendor record.")
    #NERR_RplBootNameUnavailable
    $AMHintsTable.Add("0x80070A50", "The boot name or vendor ID is in use by some other boot block record.")
    #NERR_RplConfigNameUnavailable
    $AMHintsTable.Add("0x80070A51", "The configuration name is in use by some other configuration.")
    #NERR_DfsInternalCorruption
    $AMHintsTable.Add("0x80070A64", "The internal database maintained by the DFS service is corrupt.")
    #NERR_DfsVolumeDataCorrupt
    $AMHintsTable.Add("0x80070A65", "One of the records in the internal DFS database is corrupt.")
    #NERR_DfsNoSuchVolume
    $AMHintsTable.Add("0x80070A66", "There is no DFS name whose entry path matches the input entry path.")
    #NERR_DfsVolumeAlreadyExists
    $AMHintsTable.Add("0x80070A67", "A root or link with the given name already exists.")
    #NERR_DfsAlreadyShared
    $AMHintsTable.Add("0x80070A68", "The server share specified is already shared in the DFS.")
    #NERR_DfsNoSuchShare
    $AMHintsTable.Add("0x80070A69", "The indicated server share does not support the indicated DFS namespace.")
    #NERR_DfsNotALeafVolume
    $AMHintsTable.Add("0x80070A6A", "The operation is not valid in this portion of the namespace.")
    #NERR_DfsLeafVolume
    $AMHintsTable.Add("0x80070A6B", "The operation is not valid in this portion of the namespace.")
    #NERR_DfsVolumeHasMultipleServers
    $AMHintsTable.Add("0x80070A6C", "The operation is ambiguous because the link has multiple servers.")
    #NERR_DfsCantCreateJunctionPoint
    $AMHintsTable.Add("0x80070A6D", "Unable to create a link.")
    #NERR_DfsServerNotDfsAware
    $AMHintsTable.Add("0x80070A6E", "The server is not DFS-aware.")
    #NERR_DfsBadRenamePath
    $AMHintsTable.Add("0x80070A6F", "The specified rename target path is invalid.")
    #NERR_DfsVolumeIsOffline
    $AMHintsTable.Add("0x80070A70", "The specified DFS link is offline.")
    #NERR_DfsNoSuchServer
    $AMHintsTable.Add("0x80070A71", "The specified server is not a server for this link.")
    #NERR_DfsCyclicalName
    $AMHintsTable.Add("0x80070A72", "A cycle in the DFS name was detected.")
    #NERR_DfsNotSupportedInServerDfs
    $AMHintsTable.Add("0x80070A73", "The operation is not supported on a server-based DFS.")
    #NERR_DfsDuplicateService
    $AMHintsTable.Add("0x80070A74", "This link is already supported by the specified server share.")
    #NERR_DfsCantRemoveLastServerShare
    $AMHintsTable.Add("0x80070A75", "Cannot remove the last server share supporting this root or link.")
    #NERR_DfsVolumeIsInterDfs
    $AMHintsTable.Add("0x80070A76", "The operation is not supported for an inter-DFS link.")
    #NERR_DfsInconsistent
    $AMHintsTable.Add("0x80070A77", "The internal state of the DFS Service has become inconsistent.")
    #NERR_DfsServerUpgraded
    $AMHintsTable.Add("0x80070A78", "The DFS Service has been installed on the specified server.")
    #NERR_DfsDataIsIdentical
    $AMHintsTable.Add("0x80070A79", "The DFS data being reconciled is identical.")
    #NERR_DfsCantRemoveDfsRoot
    $AMHintsTable.Add("0x80070A7A", "The DFS root cannot be deleted. Uninstall DFS if required.")
    #NERR_DfsChildOrParentInDfs
    $AMHintsTable.Add("0x80070A7B", "A child or parent directory of the share is already in a DFS.")
    #NERR_DfsInternalError
    $AMHintsTable.Add("0x80070A82", "DFS internal error.")
    #NERR_SetupAlreadyJoined
    $AMHintsTable.Add("0x80070A83", "This machine is already joined to a domain.")
    #NERR_SetupNotJoined
    $AMHintsTable.Add("0x80070A84", "This machine is not currently joined to a domain.")
    #NERR_SetupDomainController
    $AMHintsTable.Add("0x80070A85", "This machine is a domain controller and cannot be unjoined from a domain.")
    #NERR_DefaultJoinRequired
    $AMHintsTable.Add("0x80070A86", "The destination domain controller does not support creating machine accounts in organizational units (OUs).")
    #NERR_InvalidWorkgroupName
    $AMHintsTable.Add("0x80070A87", "The specified workgroup name is invalid.")
    #NERR_NameUsesIncompatibleCodePage
    $AMHintsTable.Add("0x80070A88", "The specified computer name is incompatible with the default language used on the domain controller.")
    #NERR_ComputerAccountNotFound
    $AMHintsTable.Add("0x80070A89", "The specified computer account could not be found.")
    #NERR_PersonalSku
    $AMHintsTable.Add("0x80070A8A", "This version of Windows cannot be joined to a domain.")
    #NERR_PasswordMustChange
    $AMHintsTable.Add("0x80070A8D", "The password must change at the next logon.")
    #NERR_AccountLockedOut
    $AMHintsTable.Add("0x80070A8E", "The account is locked out.")
    #NERR_PasswordTooLong
    $AMHintsTable.Add("0x80070A8F", "The password is too long.")
    #NERR_PasswordNotComplexEnough
    $AMHintsTable.Add("0x80070A90", "The password does not meet the complexity policy.")
    #NERR_PasswordFilterError
    $AMHintsTable.Add("0x80070A91", "The password does not meet the requirements of the password filter DLLs.")
    #ERROR_UNKNOWN_PRINT_MONITOR
    $AMHintsTable.Add("0x80070BB8", "The specified print monitor is unknown.")
    #ERROR_PRINTER_DRIVER_IN_USE
    $AMHintsTable.Add("0x80070BB9", "The specified printer driver is currently in use.")
    #ERROR_SPOOL_FILE_NOT_FOUND
    $AMHintsTable.Add("0x80070BBA", "The spool file was not found.")
    #ERROR_SPL_NO_STARTDOC
    $AMHintsTable.Add("0x80070BBB", "A StartDocPrinter call was not issued.")
    #ERROR_SPL_NO_ADDJOB
    $AMHintsTable.Add("0x80070BBC", "An AddJob call was not issued.")
    #ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED
    $AMHintsTable.Add("0x80070BBD", "The specified print processor has already been installed.")
    #ERROR_PRINT_MONITOR_ALREADY_INSTALLED
    $AMHintsTable.Add("0x80070BBE", "The specified print monitor has already been installed.")
    #ERROR_INVALID_PRINT_MONITOR
    $AMHintsTable.Add("0x80070BBF", "The specified print monitor does not have the required functions.")
    #ERROR_PRINT_MONITOR_IN_USE
    $AMHintsTable.Add("0x80070BC0", "The specified print monitor is currently in use.")
    #ERROR_PRINTER_HAS_JOBS_QUEUED
    $AMHintsTable.Add("0x80070BC1", "The requested operation is not allowed when there are jobs queued to the printer.")
    #ERROR_SUCCESS_REBOOT_REQUIRED
    $AMHintsTable.Add("0x80070BC2", "The requested operation is successful. Changes will not be effective until the system is rebooted.")
    #ERROR_SUCCESS_RESTART_REQUIRED
    $AMHintsTable.Add("0x80070BC3", "The requested operation is successful. Changes will not be effective until the service is restarted.")
    #ERROR_PRINTER_NOT_FOUND
    $AMHintsTable.Add("0x80070BC4", "No printers were found.")
    #ERROR_PRINTER_DRIVER_WARNED
    $AMHintsTable.Add("0x80070BC5", "The printer driver is known to be unreliable.")
    #ERROR_PRINTER_DRIVER_BLOCKED
    $AMHintsTable.Add("0x80070BC6", "The printer driver is known to harm the system.")
    #ERROR_PRINTER_DRIVER_PACKAGE_IN_USE
    $AMHintsTable.Add("0x80070BC7", "The specified printer driver package is currently in use.")
    #ERROR_CORE_DRIVER_PACKAGE_NOT_FOUND
    $AMHintsTable.Add("0x80070BC8", "Unable to find a core driver package that is required by the printer driver package.")
    #ERROR_FAIL_REBOOT_REQUIRED
    $AMHintsTable.Add("0x80070BC9", "The requested operation failed. A system reboot is required to roll back changes made.")
    #ERROR_FAIL_REBOOT_INITIATED
    $AMHintsTable.Add("0x80070BCA", "The requested operation failed. A system reboot has been initiated to roll back changes made.")
    #ERROR_IO_REISSUE_AS_CACHED
    $AMHintsTable.Add("0x80070F6E", "Reissue the given operation as a cached I/O operation.")
    #ERROR_WINS_INTERNAL
    $AMHintsTable.Add("0x80070FA0", "Windows Internet Name Service (WINS) encountered an error while processing the command.")
    #ERROR_CAN_NOT_DEL_LOCAL_WINS
    $AMHintsTable.Add("0x80070FA1", "The local WINS cannot be deleted.")
    #ERROR_STATIC_INIT
    $AMHintsTable.Add("0x80070FA2", "The importation from the file failed.")
    #ERROR_INC_BACKUP
    $AMHintsTable.Add("0x80070FA3", "The backup failed. Was a full backup done before?")
    #ERROR_FULL_BACKUP
    $AMHintsTable.Add("0x80070FA4", "The backup failed. Check the directory to which you are backing the database.")
    #ERROR_REC_NON_EXISTENT
    $AMHintsTable.Add("0x80070FA5", "The name does not exist in the WINS database.")
    #ERROR_RPL_NOT_ALLOWED
    $AMHintsTable.Add("0x80070FA6", "Replication with a nonconfigured partner is not allowed.")
    #PEERDIST_ERROR_CONTENTINFO_VERSION_UNSUPPORTED
    $AMHintsTable.Add("0x80070FD2", "The version of the supplied content information is not supported.")
    #PEERDIST_ERROR_CANNOT_PARSE_CONTENTINFO
    $AMHintsTable.Add("0x80070FD3", "The supplied content information is malformed.")
    #PEERDIST_ERROR_MISSING_DATA
    $AMHintsTable.Add("0x80070FD4", "The requested data cannot be found in local or peer caches.")
    #PEERDIST_ERROR_NO_MORE
    $AMHintsTable.Add("0x80070FD5", "No more data is available or required.")
    #PEERDIST_ERROR_NOT_INITIALIZED
    $AMHintsTable.Add("0x80070FD6", "The supplied object has not been initialized.")
    #PEERDIST_ERROR_ALREADY_INITIALIZED
    $AMHintsTable.Add("0x80070FD7", "The supplied object has already been initialized.")
    #PEERDIST_ERROR_SHUTDOWN_IN_PROGRESS
    $AMHintsTable.Add("0x80070FD8", "A shutdown operation is already in progress.")
    #PEERDIST_ERROR_INVALIDATED
    $AMHintsTable.Add("0x80070FD9", "The supplied object has already been invalidated.")
    #PEERDIST_ERROR_ALREADY_EXISTS
    $AMHintsTable.Add("0x80070FDA", "An element already exists and was not replaced.")
    #PEERDIST_ERROR_OPERATION_NOTFOUND
    $AMHintsTable.Add("0x80070FDB", "Can not cancel the requested operation as it has already been completed.")
    #PEERDIST_ERROR_ALREADY_COMPLETED
    $AMHintsTable.Add("0x80070FDC", "Can not perform the reqested operation because it has already been carried out.")
    #PEERDIST_ERROR_OUT_OF_BOUNDS
    $AMHintsTable.Add("0x80070FDD", "An operation accessed data beyond the bounds of valid data.")
    #PEERDIST_ERROR_VERSION_UNSUPPORTED
    $AMHintsTable.Add("0x80070FDE", "The requested version is not supported.")
    #PEERDIST_ERROR_INVALID_CONFIGURATION
    $AMHintsTable.Add("0x80070FDF", "A configuration value is invalid.")
    #PEERDIST_ERROR_NOT_LICENSED
    $AMHintsTable.Add("0x80070FE0", "The SKU is not licensed.")
    #PEERDIST_ERROR_SERVICE_UNAVAILABLE
    $AMHintsTable.Add("0x80070FE1", "PeerDist Service is still initializing and will be available shortly.")
    #ERROR_DHCP_ADDRESS_CONFLICT
    $AMHintsTable.Add("0x80071004", "The Dynamic Host Configuration Protocol (DHCP) client has obtained an IP address that is already in use on the network. The local interface will be disabled until the DHCP client can obtain a new address.")
    #ERROR_WMI_GUID_NOT_FOUND
    $AMHintsTable.Add("0x80071068", "The GUID passed was not recognized as valid by a WMI data provider.")
    #ERROR_WMI_INSTANCE_NOT_FOUND
    $AMHintsTable.Add("0x80071069", "The instance name passed was not recognized as valid by a WMI data provider.")
    #ERROR_WMI_ITEMID_NOT_FOUND
    $AMHintsTable.Add("0x8007106A", "The data item ID passed was not recognized as valid by a WMI data provider.")
    #ERROR_WMI_TRY_AGAIN
    $AMHintsTable.Add("0x8007106B", "The WMI request could not be completed and should be retried.")
    #ERROR_WMI_DP_NOT_FOUND
    $AMHintsTable.Add("0x8007106C", "The WMI data provider could not be located.")
    #ERROR_WMI_UNRESOLVED_INSTANCE_REF
    $AMHintsTable.Add("0x8007106D", "The WMI data provider references an instance set that has not been registered.")
    #ERROR_WMI_ALREADY_ENABLED
    $AMHintsTable.Add("0x8007106E", "The WMI data block or event notification has already been enabled.")
    #ERROR_WMI_GUID_DISCONNECTED
    $AMHintsTable.Add("0x8007106F", "The WMI data block is no longer available.")
    #ERROR_WMI_SERVER_UNAVAILABLE
    $AMHintsTable.Add("0x80071070", "The WMI data service is not available.")
    #ERROR_WMI_DP_FAILED
    $AMHintsTable.Add("0x80071071", "The WMI data provider failed to carry out the request.")
    #ERROR_WMI_INVALID_MOF
    $AMHintsTable.Add("0x80071072", "The WMI Managed Object Format (MOF) information is not valid.")
    #ERROR_WMI_INVALID_REGINFO
    $AMHintsTable.Add("0x80071073", "The WMI registration information is not valid.")
    #ERROR_WMI_ALREADY_DISABLED
    $AMHintsTable.Add("0x80071074", "The WMI data block or event notification has already been disabled.")
    #ERROR_WMI_READ_ONLY
    $AMHintsTable.Add("0x80071075", "The WMI data item or data block is read-only.")
    #ERROR_WMI_SET_FAILURE
    $AMHintsTable.Add("0x80071076", "The WMI data item or data block could not be changed.")
    #ERROR_INVALID_MEDIA
    $AMHintsTable.Add("0x800710CC", "The media identifier does not represent a valid medium.")
    #ERROR_INVALID_LIBRARY
    $AMHintsTable.Add("0x800710CD", "The library identifier does not represent a valid library.")
    #ERROR_INVALID_MEDIA_POOL
    $AMHintsTable.Add("0x800710CE", "The media pool identifier does not represent a valid media pool.")
    #ERROR_DRIVE_MEDIA_MISMATCH
    $AMHintsTable.Add("0x800710CF", "The drive and medium are not compatible, or they exist in different libraries.")
    #ERROR_MEDIA_OFFLINE
    $AMHintsTable.Add("0x800710D0", "The medium currently exists in an offline library and must be online to perform this operation.")
    #ERROR_LIBRARY_OFFLINE
    $AMHintsTable.Add("0x800710D1", "The operation cannot be performed on an offline library.")
    #ERROR_EMPTY
    $AMHintsTable.Add("0x800710D2", "The library, drive, or media pool is empty.")
    #ERROR_NOT_EMPTY
    $AMHintsTable.Add("0x800710D3", "The library, drive, or media pool must be empty to perform this operation.")
    #ERROR_MEDIA_UNAVAILABLE
    $AMHintsTable.Add("0x800710D4", "No media is currently available in this media pool or library.")
    #ERROR_RESOURCE_DISABLED
    $AMHintsTable.Add("0x800710D5", "A resource required for this operation is disabled.")
    #ERROR_INVALID_CLEANER
    $AMHintsTable.Add("0x800710D6", "The media identifier does not represent a valid cleaner.")
    #ERROR_UNABLE_TO_CLEAN
    $AMHintsTable.Add("0x800710D7", "The drive cannot be cleaned or does not support cleaning.")
    #ERROR_OBJECT_NOT_FOUND
    $AMHintsTable.Add("0x800710D8", "The object identifier does not represent a valid object.")
    #ERROR_DATABASE_FAILURE
    $AMHintsTable.Add("0x800710D9", "Unable to read from or write to the database.")
    #ERROR_DATABASE_FULL
    $AMHintsTable.Add("0x800710DA", "The database is full.")
    #ERROR_MEDIA_INCOMPATIBLE
    $AMHintsTable.Add("0x800710DB", "The medium is not compatible with the device or media pool.")
    #ERROR_RESOURCE_NOT_PRESENT
    $AMHintsTable.Add("0x800710DC", "The resource required for this operation does not exist.")
    #ERROR_INVALID_OPERATION
    $AMHintsTable.Add("0x800710DD", "The operation identifier is not valid.")
    #ERROR_MEDIA_NOT_AVAILABLE
    $AMHintsTable.Add("0x800710DE", "The media is not mounted or ready for use.")
    #ERROR_DEVICE_NOT_AVAILABLE
    $AMHintsTable.Add("0x800710DF", "The device is not ready for use.")
    #ERROR_REQUEST_REFUSED
    $AMHintsTable.Add("0x800710E0", "The operator or administrator has refused the request.")
    #ERROR_INVALID_DRIVE_OBJECT
    $AMHintsTable.Add("0x800710E1", "The drive identifier does not represent a valid drive.")
    #ERROR_LIBRARY_FULL
    $AMHintsTable.Add("0x800710E2", "Library is full. No slot is available for use.")
    #ERROR_MEDIUM_NOT_ACCESSIBLE
    $AMHintsTable.Add("0x800710E3", "The transport cannot access the medium.")
    #ERROR_UNABLE_TO_LOAD_MEDIUM
    $AMHintsTable.Add("0x800710E4", "Unable to load the medium into the drive.")
    #ERROR_UNABLE_TO_INVENTORY_DRIVE
    $AMHintsTable.Add("0x800710E5", "Unable to retrieve the drive status.")
    #ERROR_UNABLE_TO_INVENTORY_SLOT
    $AMHintsTable.Add("0x800710E6", "Unable to retrieve the slot status.")
    #ERROR_UNABLE_TO_INVENTORY_TRANSPORT
    $AMHintsTable.Add("0x800710E7", "Unable to retrieve status about the transport.")
    #ERROR_TRANSPORT_FULL
    $AMHintsTable.Add("0x800710E8", "Cannot use the transport because it is already in use.")
    #ERROR_CONTROLLING_IEPORT
    $AMHintsTable.Add("0x800710E9", "Unable to open or close the inject/eject port.")
    #ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA
    $AMHintsTable.Add("0x800710EA", "Unable to eject the medium because it is in a drive.")
    #ERROR_CLEANER_SLOT_SET
    $AMHintsTable.Add("0x800710EB", "A cleaner slot is already reserved.")
    #ERROR_CLEANER_SLOT_NOT_SET
    $AMHintsTable.Add("0x800710EC", "A cleaner slot is not reserved.")
    #ERROR_CLEANER_CARTRIDGE_SPENT
    $AMHintsTable.Add("0x800710ED", "The cleaner cartridge has performed the maximum number of drive cleanings.")
    #ERROR_UNEXPECTED_OMID
    $AMHintsTable.Add("0x800710EE", "Unexpected on-medium identifier.")
    #ERROR_CANT_DELETE_LAST_ITEM
    $AMHintsTable.Add("0x800710EF", "The last remaining item in this group or resource cannot be deleted.")
    #ERROR_MESSAGE_EXCEEDS_MAX_SIZE
    $AMHintsTable.Add("0x800710F0", "The message provided exceeds the maximum size allowed for this parameter.")
    #ERROR_VOLUME_CONTAINS_SYS_FILES
    $AMHintsTable.Add("0x800710F1", "The volume contains system or paging files.")
    #ERROR_INDIGENOUS_TYPE
    $AMHintsTable.Add("0x800710F2", "The media type cannot be removed from this library because at least one drive in the library reports it can support this media type.")
    #ERROR_NO_SUPPORTING_DRIVES
    $AMHintsTable.Add("0x800710F3", "This offline media cannot be mounted on this system because no enabled drives are present that can be used.")
    #ERROR_CLEANER_CARTRIDGE_INSTALLED
    $AMHintsTable.Add("0x800710F4", "A cleaner cartridge is present in the tape library.")
    #ERROR_IEPORT_FULL
    $AMHintsTable.Add("0x800710F5", "Cannot use the IEport because it is not empty.")
    #ERROR_FILE_OFFLINE
    $AMHintsTable.Add("0x800710FE", "The remote storage service was not able to recall the file.")
    #ERROR_REMOTE_STORAGE_NOT_ACTIVE
    $AMHintsTable.Add("0x800710FF", "The remote storage service is not operational at this time.")
    #ERROR_REMOTE_STORAGE_MEDIA_ERROR
    $AMHintsTable.Add("0x80071100", "The remote storage service encountered a media error.")
    #ERROR_NOT_A_REPARSE_POINT
    $AMHintsTable.Add("0x80071126", "The file or directory is not a reparse point.")
    #ERROR_REPARSE_ATTRIBUTE_CONFLICT
    $AMHintsTable.Add("0x80071127", "The reparse point attribute cannot be set because it conflicts with an existing attribute.")
    #ERROR_INVALID_REPARSE_DATA
    $AMHintsTable.Add("0x80071128", "The data present in the reparse point buffer is invalid.")
    #ERROR_REPARSE_TAG_INVALID
    $AMHintsTable.Add("0x80071129", "The tag present in the reparse point buffer is invalid.")
    #ERROR_REPARSE_TAG_MISMATCH
    $AMHintsTable.Add("0x8007112A", "There is a mismatch between the tag specified in the request and the tag present in the reparse point.")
    #ERROR_VOLUME_NOT_SIS_ENABLED
    $AMHintsTable.Add("0x80071194", "Single Instance Storage (SIS) is not available on this volume.")
    #ERROR_DEPENDENT_RESOURCE_EXISTS
    $AMHintsTable.Add("0x80071389", "The operation cannot be completed because other resources depend on this resource.")
    #ERROR_DEPENDENCY_NOT_FOUND
    $AMHintsTable.Add("0x8007138A", "The cluster resource dependency cannot be found.")
    #ERROR_DEPENDENCY_ALREADY_EXISTS
    $AMHintsTable.Add("0x8007138B", "The cluster resource cannot be made dependent on the specified resource because it is already dependent.")
    #ERROR_RESOURCE_NOT_ONLINE
    $AMHintsTable.Add("0x8007138C", "The cluster resource is not online.")
    #ERROR_HOST_NODE_NOT_AVAILABLE
    $AMHintsTable.Add("0x8007138D", "A cluster node is not available for this operation.")
    #ERROR_RESOURCE_NOT_AVAILABLE
    $AMHintsTable.Add("0x8007138E", "The cluster resource is not available.")
    #ERROR_RESOURCE_NOT_FOUND
    $AMHintsTable.Add("0x8007138F", "The cluster resource could not be found.")
    #ERROR_SHUTDOWN_CLUSTER
    $AMHintsTable.Add("0x80071390", "The cluster is being shut down.")
    #ERROR_CANT_EVICT_ACTIVE_NODE
    $AMHintsTable.Add("0x80071391", "A cluster node cannot be evicted from the cluster unless the node is down or it is the last node.")
    #ERROR_OBJECT_ALREADY_EXISTS
    $AMHintsTable.Add("0x80071392", "The object already exists.")
    #ERROR_OBJECT_IN_LIST
    $AMHintsTable.Add("0x80071393", "The object is already in the list.")
    #ERROR_GROUP_NOT_AVAILABLE
    $AMHintsTable.Add("0x80071394", "The cluster group is not available for any new requests.")
    #ERROR_GROUP_NOT_FOUND
    $AMHintsTable.Add("0x80071395", "The cluster group could not be found.")
    #ERROR_GROUP_NOT_ONLINE
    $AMHintsTable.Add("0x80071396", "The operation could not be completed because the cluster group is not online.")
    #ERROR_HOST_NODE_NOT_RESOURCE_OWNER
    $AMHintsTable.Add("0x80071397", "The operation failed because either the specified cluster node is not the owner of the resource, or the node is not a possible owner of the resource.")
    #ERROR_HOST_NODE_NOT_GROUP_OWNER
    $AMHintsTable.Add("0x80071398", "The operation failed because either the specified cluster node is not the owner of the group, or the node is not a possible owner of the group.")
    #ERROR_RESMON_CREATE_FAILED
    $AMHintsTable.Add("0x80071399", "The cluster resource could not be created in the specified resource monitor.")
    #ERROR_RESMON_ONLINE_FAILED
    $AMHintsTable.Add("0x8007139A", "The cluster resource could not be brought online by the resource monitor.")
    #ERROR_RESOURCE_ONLINE
    $AMHintsTable.Add("0x8007139B", "The operation could not be completed because the cluster resource is online.")
    #ERROR_QUORUM_RESOURCE
    $AMHintsTable.Add("0x8007139C", "The cluster resource could not be deleted or brought offline because it is the quorum resource.")
    #ERROR_NOT_QUORUM_CAPABLE
    $AMHintsTable.Add("0x8007139D", "The cluster could not make the specified resource a quorum resource because it is not capable of being a quorum resource.")
    #ERROR_CLUSTER_SHUTTING_DOWN
    $AMHintsTable.Add("0x8007139E", "The cluster software is shutting down.")
    #ERROR_INVALID_STATE
    $AMHintsTable.Add("0x8007139F", "The group or resource is not in the correct state to perform the requested operation.")
    #ERROR_RESOURCE_PROPERTIES_STORED
    $AMHintsTable.Add("0x800713A0", "The properties were stored but not all changes will take effect until the next time the resource is brought online.")
    #ERROR_NOT_QUORUM_CLASS
    $AMHintsTable.Add("0x800713A1", "The cluster could not make the specified resource a quorum resource because it does not belong to a shared storage class.")
    #ERROR_CORE_RESOURCE
    $AMHintsTable.Add("0x800713A2", "The cluster resource could not be deleted because it is a core resource.")
    #ERROR_QUORUM_RESOURCE_ONLINE_FAILED
    $AMHintsTable.Add("0x800713A3", "The quorum resource failed to come online.")
    #ERROR_QUORUMLOG_OPEN_FAILED
    $AMHintsTable.Add("0x800713A4", "The quorum log could not be created or mounted successfully.")
    #ERROR_CLUSTERLOG_CORRUPT
    $AMHintsTable.Add("0x800713A5", "The cluster log is corrupt.")
    #ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE
    $AMHintsTable.Add("0x800713A6", "The record could not be written to the cluster log because it exceeds the maximum size.")
    #ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE
    $AMHintsTable.Add("0x800713A7", "The cluster log exceeds its maximum size.")
    #ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND
    $AMHintsTable.Add("0x800713A8", "No checkpoint record was found in the cluster log.")
    #ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE
    $AMHintsTable.Add("0x800713A9", "The minimum required disk space needed for logging is not available.")
    #ERROR_QUORUM_OWNER_ALIVE
    $AMHintsTable.Add("0x800713AA", "The cluster node failed to take control of the quorum resource because the resource is owned by another active node.")
    #ERROR_NETWORK_NOT_AVAILABLE
    $AMHintsTable.Add("0x800713AB", "A cluster network is not available for this operation.")
    #ERROR_NODE_NOT_AVAILABLE
    $AMHintsTable.Add("0x800713AC", "A cluster node is not available for this operation.")
    #ERROR_ALL_NODES_NOT_AVAILABLE
    $AMHintsTable.Add("0x800713AD", "All cluster nodes must be running to perform this operation.")
    #ERROR_RESOURCE_FAILED
    $AMHintsTable.Add("0x800713AE", "A cluster resource failed.")
    #ERROR_CLUSTER_INVALID_NODE
    $AMHintsTable.Add("0x800713AF", "The cluster node is not valid.")
    #ERROR_CLUSTER_NODE_EXISTS
    $AMHintsTable.Add("0x800713B0", "The cluster node already exists.")
    #ERROR_CLUSTER_JOIN_IN_PROGRESS
    $AMHintsTable.Add("0x800713B1", "A node is in the process of joining the cluster.")
    #ERROR_CLUSTER_NODE_NOT_FOUND
    $AMHintsTable.Add("0x800713B2", "The cluster node was not found.")
    #ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND
    $AMHintsTable.Add("0x800713B3", "The cluster local node information was not found.")
    #ERROR_CLUSTER_NETWORK_EXISTS
    $AMHintsTable.Add("0x800713B4", "The cluster network already exists.")
    #ERROR_CLUSTER_NETWORK_NOT_FOUND
    $AMHintsTable.Add("0x800713B5", "The cluster network was not found.")
    #ERROR_CLUSTER_NETINTERFACE_EXISTS
    $AMHintsTable.Add("0x800713B6", "The cluster network interface already exists.")
    #ERROR_CLUSTER_NETINTERFACE_NOT_FOUND
    $AMHintsTable.Add("0x800713B7", "The cluster network interface was not found.")
    #ERROR_CLUSTER_INVALID_REQUEST
    $AMHintsTable.Add("0x800713B8", "The cluster request is not valid for this object.")
    #ERROR_CLUSTER_INVALID_NETWORK_PROVIDER
    $AMHintsTable.Add("0x800713B9", "The cluster network provider is not valid.")
    #ERROR_CLUSTER_NODE_DOWN
    $AMHintsTable.Add("0x800713BA", "The cluster node is down.")
    #ERROR_CLUSTER_NODE_UNREACHABLE
    $AMHintsTable.Add("0x800713BB", "The cluster node is not reachable.")
    #ERROR_CLUSTER_NODE_NOT_MEMBER
    $AMHintsTable.Add("0x800713BC", "The cluster node is not a member of the cluster.")
    #ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS
    $AMHintsTable.Add("0x800713BD", "A cluster join operation is not in progress.")
    #ERROR_CLUSTER_INVALID_NETWORK
    $AMHintsTable.Add("0x800713BE", "The cluster network is not valid.")
    #ERROR_CLUSTER_NODE_UP
    $AMHintsTable.Add("0x800713C0", "The cluster node is up.")
    #ERROR_CLUSTER_IPADDR_IN_USE
    $AMHintsTable.Add("0x800713C1", "The cluster IP address is already in use.")
    #ERROR_CLUSTER_NODE_NOT_PAUSED
    $AMHintsTable.Add("0x800713C2", "The cluster node is not paused.")
    #ERROR_CLUSTER_NO_SECURITY_CONTEXT
    $AMHintsTable.Add("0x800713C3", "No cluster security context is available.")
    #ERROR_CLUSTER_NETWORK_NOT_INTERNAL
    $AMHintsTable.Add("0x800713C4", "The cluster network is not configured for internal cluster communication.")
    #ERROR_CLUSTER_NODE_ALREADY_UP
    $AMHintsTable.Add("0x800713C5", "The cluster node is already up.")
    #ERROR_CLUSTER_NODE_ALREADY_DOWN
    $AMHintsTable.Add("0x800713C6", "The cluster node is already down.")
    #ERROR_CLUSTER_NETWORK_ALREADY_ONLINE
    $AMHintsTable.Add("0x800713C7", "The cluster network is already online.")
    #ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE
    $AMHintsTable.Add("0x800713C8", "The cluster network is already offline.")
    #ERROR_CLUSTER_NODE_ALREADY_MEMBER
    $AMHintsTable.Add("0x800713C9", "The cluster node is already a member of the cluster.")
    #ERROR_CLUSTER_LAST_INTERNAL_NETWORK
    $AMHintsTable.Add("0x800713CA", "The cluster network is the only one configured for internal cluster communication between two or more active cluster nodes. The internal communication capability cannot be removed from the network.")
    #ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS
    $AMHintsTable.Add("0x800713CB", "One or more cluster resources depend on the network to provide service to clients. The client access capability cannot be removed from the network.")
    #ERROR_INVALID_OPERATION_ON_QUORUM
    $AMHintsTable.Add("0x800713CC", "This operation cannot be performed on the cluster resource because it is the quorum resource. You may not bring the quorum resource offline or modify its possible owners list.")
    #ERROR_DEPENDENCY_NOT_ALLOWED
    $AMHintsTable.Add("0x800713CD", "The cluster quorum resource is not allowed to have any dependencies.")
    #ERROR_CLUSTER_NODE_PAUSED
    $AMHintsTable.Add("0x800713CE", "The cluster node is paused.")
    #ERROR_NODE_CANT_HOST_RESOURCE
    $AMHintsTable.Add("0x800713CF", "The cluster resource cannot be brought online. The owner node cannot run this resource.")
    #ERROR_CLUSTER_NODE_NOT_READY
    $AMHintsTable.Add("0x800713D0", "The cluster node is not ready to perform the requested operation.")
    #ERROR_CLUSTER_NODE_SHUTTING_DOWN
    $AMHintsTable.Add("0x800713D1", "The cluster node is shutting down.")
    #ERROR_CLUSTER_JOIN_ABORTED
    $AMHintsTable.Add("0x800713D2", "The cluster join operation was aborted.")
    #ERROR_CLUSTER_INCOMPATIBLE_VERSIONS
    $AMHintsTable.Add("0x800713D3", "The cluster join operation failed due to incompatible software versions between the joining node and its sponsor.")
    #ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED
    $AMHintsTable.Add("0x800713D4", "This resource cannot be created because the cluster has reached the limit on the number of resources it can monitor.")
    #ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED
    $AMHintsTable.Add("0x800713D5", "The system configuration changed during the cluster join or form operation. The join or form operation was aborted.")
    #ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND
    $AMHintsTable.Add("0x800713D6", "The specified resource type was not found.")
    #ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED
    $AMHintsTable.Add("0x800713D7", "The specified node does not support a resource of this type. This may be due to version inconsistencies or due to the absence of the resource DLL on this node.")
    #ERROR_CLUSTER_RESNAME_NOT_FOUND
    $AMHintsTable.Add("0x800713D8", "The specified resource name is not supported by this resource DLL. This may be due to a bad (or changed) name supplied to the resource DLL.")
    #ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED
    $AMHintsTable.Add("0x800713D9", "No authentication package could be registered with the RPC server.")
    #ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST
    $AMHintsTable.Add("0x800713DA", "You cannot bring the group online because the owner of the group is not in the preferred list for the group. To change the owner node for the group, move the group.")
    #ERROR_CLUSTER_DATABASE_SEQMISMATCH
    $AMHintsTable.Add("0x800713DB", "The join operation failed because the cluster database sequence number has changed or is incompatible with the locker node. This may happen during a join operation if the cluster database was changing during the join.")
    #ERROR_RESMON_INVALID_STATE
    $AMHintsTable.Add("0x800713DC", "The resource monitor will not allow the fail operation to be performed while the resource is in its current state. This may happen if the resource is in a pending state.")
    #ERROR_CLUSTER_GUM_NOT_LOCKER
    $AMHintsTable.Add("0x800713DD", "A non-locker code received a request to reserve the lock for making global updates.")
    #ERROR_QUORUM_DISK_NOT_FOUND
    $AMHintsTable.Add("0x800713DE", "The quorum disk could not be located by the cluster service.")
    #ERROR_DATABASE_BACKUP_CORRUPT
    $AMHintsTable.Add("0x800713DF", "The backed-up cluster database is possibly corrupt.")
    #ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT
    $AMHintsTable.Add("0x800713E0", "A DFS root already exists in this cluster node.")
    #ERROR_RESOURCE_PROPERTY_UNCHANGEABLE
    $AMHintsTable.Add("0x800713E1", "An attempt to modify a resource property failed because it conflicts with another existing property.")
    #ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE
    $AMHintsTable.Add("0x80071702", "An operation was attempted that is incompatible with the current membership state of the node.")
    #ERROR_CLUSTER_QUORUMLOG_NOT_FOUND
    $AMHintsTable.Add("0x80071703", "The quorum resource does not contain the quorum log.")
    #ERROR_CLUSTER_MEMBERSHIP_HALT
    $AMHintsTable.Add("0x80071704", "The membership engine requested shutdown of the cluster service on this node.")
    #ERROR_CLUSTER_INSTANCE_ID_MISMATCH
    $AMHintsTable.Add("0x80071705", "The join operation failed because the cluster instance ID of the joining node does not match the cluster instance ID of the sponsor node.")
    #ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP
    $AMHintsTable.Add("0x80071706", "A matching cluster network for the specified IP address could not be found.")
    #ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH
    $AMHintsTable.Add("0x80071707", "The actual data type of the property did not match the expected data type of the property.")
    #ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP
    $AMHintsTable.Add("0x80071708", "The cluster node was evicted from the cluster successfully, but the node was not cleaned up. To determine what clean-up steps failed and how to recover, see the Failover Clustering application event log using Event Viewer.")
    #ERROR_CLUSTER_PARAMETER_MISMATCH
    $AMHintsTable.Add("0x80071709", "Two or more parameter values specified for a resource's properties are in conflict.")
    #ERROR_NODE_CANNOT_BE_CLUSTERED
    $AMHintsTable.Add("0x8007170A", "This computer cannot be made a member of a cluster.")
    #ERROR_CLUSTER_WRONG_OS_VERSION
    $AMHintsTable.Add("0x8007170B", "This computer cannot be made a member of a cluster because it does not have the correct version of Windows installed.")
    #ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME
    $AMHintsTable.Add("0x8007170C", "A cluster cannot be created with the specified cluster name because that cluster name is already in use. Specify a different name for the cluster.")
    #ERROR_CLUSCFG_ALREADY_COMMITTED
    $AMHintsTable.Add("0x8007170D", "The cluster configuration action has already been committed.")
    #ERROR_CLUSCFG_ROLLBACK_FAILED
    $AMHintsTable.Add("0x8007170E", "The cluster configuration action could not be rolled back.")
    #ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT
    $AMHintsTable.Add("0x8007170F", "The drive letter assigned to a system disk on one node conflicted with the drive letter assigned to a disk on another node.")
    #ERROR_CLUSTER_OLD_VERSION
    $AMHintsTable.Add("0x80071710", "One or more nodes in the cluster are running a version of Windows that does not support this operation.")
    #ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME
    $AMHintsTable.Add("0x80071711", "The name of the corresponding computer account does not match the network name for this resource.")
    #ERROR_CLUSTER_NO_NET_ADAPTERS
    $AMHintsTable.Add("0x80071712", "No network adapters are available.")
    #ERROR_CLUSTER_POISONED
    $AMHintsTable.Add("0x80071713", "The cluster node has been poisoned.")
    #ERROR_CLUSTER_GROUP_MOVING
    $AMHintsTable.Add("0x80071714", "The group is unable to accept the request because it is moving to another node.")
    #ERROR_CLUSTER_RESOURCE_TYPE_BUSY
    $AMHintsTable.Add("0x80071715", "The resource type cannot accept the request because it is too busy performing another operation.")
    #ERROR_RESOURCE_CALL_TIMED_OUT
    $AMHintsTable.Add("0x80071716", "The call to the cluster resource DLL timed out.")
    #ERROR_INVALID_CLUSTER_IPV6_ADDRESS
    $AMHintsTable.Add("0x80071717", "The address is not valid for an IPv6 Address resource. A global IPv6 address is required, and it must match a cluster network. Compatibility addresses are not permitted.")
    #ERROR_CLUSTER_INTERNAL_INVALID_FUNCTION
    $AMHintsTable.Add("0x80071718", "An internal cluster error occurred. A call to an invalid function was attempted.")
    #ERROR_CLUSTER_PARAMETER_OUT_OF_BOUNDS
    $AMHintsTable.Add("0x80071719", "A parameter value is out of acceptable range.")
    #ERROR_CLUSTER_PARTIAL_SEND
    $AMHintsTable.Add("0x8007171A", "A network error occurred while sending data to another node in the cluster. The number of bytes transmitted was less than required.")
    #ERROR_CLUSTER_REGISTRY_INVALID_FUNCTION
    $AMHintsTable.Add("0x8007171B", "An invalid cluster registry operation was attempted.")
    #ERROR_CLUSTER_INVALID_STRING_TERMINATION
    $AMHintsTable.Add("0x8007171C", "An input string of characters is not properly terminated.")
    #ERROR_CLUSTER_INVALID_STRING_FORMAT
    $AMHintsTable.Add("0x8007171D", "An input string of characters is not in a valid format for the data it represents.")
    #ERROR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS
    $AMHintsTable.Add("0x8007171E", "An internal cluster error occurred. A cluster database transaction was attempted while a transaction was already in progress.")
    #ERROR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS
    $AMHintsTable.Add("0x8007171F", "An internal cluster error occurred. There was an attempt to commit a cluster database transaction while no transaction was in progress.")
    #ERROR_CLUSTER_NULL_DATA
    $AMHintsTable.Add("0x80071720", "An internal cluster error occurred. Data was not properly initialized.")
    #ERROR_CLUSTER_PARTIAL_READ
    $AMHintsTable.Add("0x80071721", "An error occurred while reading from a stream of data. An unexpected number of bytes was returned.")
    #ERROR_CLUSTER_PARTIAL_WRITE
    $AMHintsTable.Add("0x80071722", "An error occurred while writing to a stream of data. The required number of bytes could not be written.")
    #ERROR_CLUSTER_CANT_DESERIALIZE_DATA
    $AMHintsTable.Add("0x80071723", "An error occurred while deserializing a stream of cluster data.")
    #ERROR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT
    $AMHintsTable.Add("0x80071724", "One or more property values for this resource are in conflict with one or more property values associated with its dependent resources.")
    #ERROR_CLUSTER_NO_QUORUM
    $AMHintsTable.Add("0x80071725", "A quorum of cluster nodes was not present to form a cluster.")
    #ERROR_CLUSTER_INVALID_IPV6_NETWORK
    $AMHintsTable.Add("0x80071726", "The cluster network is not valid for an IPv6 address resource, or it does not match the configured address.")
    #ERROR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK
    $AMHintsTable.Add("0x80071727", "The cluster network is not valid for an IPv6 tunnel resource. Check the configuration of the IP Address resource on which the IPv6 tunnel resource depends.")
    #ERROR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP
    $AMHintsTable.Add("0x80071728", "Quorum resource cannot reside in the available storage group.")
    #ERROR_ENCRYPTION_FAILED
    $AMHintsTable.Add("0x80071770", "The specified file could not be encrypted.")
    #ERROR_DECRYPTION_FAILED
    $AMHintsTable.Add("0x80071771", "The specified file could not be decrypted.")
    #ERROR_FILE_ENCRYPTED
    $AMHintsTable.Add("0x80071772", "The specified file is encrypted and the user does not have the ability to decrypt it.")
    #ERROR_NO_RECOVERY_POLICY
    $AMHintsTable.Add("0x80071773", "There is no valid encryption recovery policy configured for this system.")
    #ERROR_NO_EFS
    $AMHintsTable.Add("0x80071774", "The required encryption driver is not loaded for this system.")
    #ERROR_WRONG_EFS
    $AMHintsTable.Add("0x80071775", "The file was encrypted with a different encryption driver than is currently loaded.")
    #ERROR_NO_USER_KEYS
    $AMHintsTable.Add("0x80071776", "There are no Encrypting File System (EFS) keys defined for the user.")
    #ERROR_FILE_NOT_ENCRYPTED
    $AMHintsTable.Add("0x80071777", "The specified file is not encrypted.")
    #ERROR_NOT_EXPORT_FORMAT
    $AMHintsTable.Add("0x80071778", "The specified file is not in the defined EFS export format.")
    #ERROR_FILE_READ_ONLY
    $AMHintsTable.Add("0x80071779", "The specified file is read-only.")
    #ERROR_DIR_EFS_DISALLOWED
    $AMHintsTable.Add("0x8007177A", "The directory has been disabled for encryption.")
    #ERROR_EFS_SERVER_NOT_TRUSTED
    $AMHintsTable.Add("0x8007177B", "The server is not trusted for remote encryption operation.")
    #ERROR_BAD_RECOVERY_POLICY
    $AMHintsTable.Add("0x8007177C", "Recovery policy configured for this system contains invalid recovery certificate.")
    #ERROR_EFS_ALG_BLOB_TOO_BIG
    $AMHintsTable.Add("0x8007177D", "The encryption algorithm used on the source file needs a bigger key buffer than the one on the destination file.")
    #ERROR_VOLUME_NOT_SUPPORT_EFS
    $AMHintsTable.Add("0x8007177E", "The disk partition does not support file encryption.")
    #ERROR_EFS_DISABLED
    $AMHintsTable.Add("0x8007177F", "This machine is disabled for file encryption.")
    #ERROR_EFS_VERSION_NOT_SUPPORT
    $AMHintsTable.Add("0x80071780", "A newer system is required to decrypt this encrypted file.")
    #ERROR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE
    $AMHintsTable.Add("0x80071781", "The remote server sent an invalid response for a file being opened with client-side encryption.")
    #ERROR_CS_ENCRYPTION_UNSUPPORTED_SERVER
    $AMHintsTable.Add("0x80071782", "Client-side encryption is not supported by the remote server even though it claims to support it.")
    #ERROR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE
    $AMHintsTable.Add("0x80071783", "File is encrypted and should be opened in client-side encryption mode.")
    #ERROR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE
    $AMHintsTable.Add("0x80071784", "A new encrypted file is being created and a `$EFS needs to be provided.")
    #ERROR_CS_ENCRYPTION_FILE_NOT_CSE
    $AMHintsTable.Add("0x80071785", "The SMB client requested a client-side extension (CSE) file system control (FSCTL) on a non-CSE file.")
    #ERROR_NO_BROWSER_SERVERS_FOUND
    $AMHintsTable.Add("0x800717E6", "The list of servers for this workgroup is not currently available")
    #SCHED_E_SERVICE_NOT_LOCALSYSTEM
    $AMHintsTable.Add("0x80071838", "The Task Scheduler service must be configured to run in the System account to function properly. Individual tasks may be configured to run in other accounts.")
    #ERROR_LOG_SECTOR_INVALID
    $AMHintsTable.Add("0x800719C8", "The log service encountered an invalid log sector.")
    #ERROR_LOG_SECTOR_PARITY_INVALID
    $AMHintsTable.Add("0x800719C9", "The log service encountered a log sector with invalid block parity.")
    #ERROR_LOG_SECTOR_REMAPPED
    $AMHintsTable.Add("0x800719CA", "The log service encountered a remapped log sector.")
    #ERROR_LOG_BLOCK_INCOMPLETE
    $AMHintsTable.Add("0x800719CB", "The log service encountered a partial or incomplete log block.")
    #ERROR_LOG_INVALID_RANGE
    $AMHintsTable.Add("0x800719CC", "The log service encountered an attempt to access data outside the active log range.")
    #ERROR_LOG_BLOCKS_EXHAUSTED
    $AMHintsTable.Add("0x800719CD", "The log service user marshaling buffers are exhausted.")
    #ERROR_LOG_READ_CONTEXT_INVALID
    $AMHintsTable.Add("0x800719CE", "The log service encountered an attempt to read from a marshaling area with an invalid read context.")
    #ERROR_LOG_RESTART_INVALID
    $AMHintsTable.Add("0x800719CF", "The log service encountered an invalid log restart area.")
    #ERROR_LOG_BLOCK_VERSION
    $AMHintsTable.Add("0x800719D0", "The log service encountered an invalid log block version.")
    #ERROR_LOG_BLOCK_INVALID
    $AMHintsTable.Add("0x800719D1", "The log service encountered an invalid log block.")
    #ERROR_LOG_READ_MODE_INVALID
    $AMHintsTable.Add("0x800719D2", "The log service encountered an attempt to read the log with an invalid read mode.")
    #ERROR_LOG_NO_RESTART
    $AMHintsTable.Add("0x800719D3", "The log service encountered a log stream with no restart area.")
    #ERROR_LOG_METADATA_CORRUPT
    $AMHintsTable.Add("0x800719D4", "The log service encountered a corrupted metadata file.")
    #ERROR_LOG_METADATA_INVALID
    $AMHintsTable.Add("0x800719D5", "The log service encountered a metadata file that could not be created by the log file system.")
    #ERROR_LOG_METADATA_INCONSISTENT
    $AMHintsTable.Add("0x800719D6", "The log service encountered a metadata file with inconsistent data.")
    #ERROR_LOG_RESERVATION_INVALID
    $AMHintsTable.Add("0x800719D7", "The log service encountered an attempt to erroneous allocate or dispose reservation space.")
    #ERROR_LOG_CANT_DELETE
    $AMHintsTable.Add("0x800719D8", "The log service cannot delete a log file or file system container.")
    #ERROR_LOG_CONTAINER_LIMIT_EXCEEDED
    $AMHintsTable.Add("0x800719D9", "The log service has reached the maximum allowable containers allocated to a log file.")
    #ERROR_LOG_START_OF_LOG
    $AMHintsTable.Add("0x800719DA", "The log service has attempted to read or write backward past the start of the log.")
    #ERROR_LOG_POLICY_ALREADY_INSTALLED
    $AMHintsTable.Add("0x800719DB", "The log policy could not be installed because a policy of the same type is already present.")
    #ERROR_LOG_POLICY_NOT_INSTALLED
    $AMHintsTable.Add("0x800719DC", "The log policy in question was not installed at the time of the request.")
    #ERROR_LOG_POLICY_INVALID
    $AMHintsTable.Add("0x800719DD", "The installed set of policies on the log is invalid.")
    #ERROR_LOG_POLICY_CONFLICT
    $AMHintsTable.Add("0x800719DE", "A policy on the log in question prevented the operation from completing.")
    #ERROR_LOG_PINNED_ARCHIVE_TAIL
    $AMHintsTable.Add("0x800719DF", "Log space cannot be reclaimed because the log is pinned by the archive tail.")
    #ERROR_LOG_RECORD_NONEXISTENT
    $AMHintsTable.Add("0x800719E0", "The log record is not a record in the log file.")
    #ERROR_LOG_RECORDS_RESERVED_INVALID
    $AMHintsTable.Add("0x800719E1", "The number of reserved log records or the adjustment of the number of reserved log records is invalid.")
    #ERROR_LOG_SPACE_RESERVED_INVALID
    $AMHintsTable.Add("0x800719E2", "The reserved log space or the adjustment of the log space is invalid.")
    #ERROR_LOG_TAIL_INVALID
    $AMHintsTable.Add("0x800719E3", "A new or existing archive tail or base of the active log is invalid.")
    #ERROR_LOG_FULL
    $AMHintsTable.Add("0x800719E4", "The log space is exhausted.")
    #ERROR_COULD_NOT_RESIZE_LOG
    $AMHintsTable.Add("0x800719E5", "The log could not be set to the requested size.")
    #ERROR_LOG_MULTIPLEXED
    $AMHintsTable.Add("0x800719E6", "The log is multiplexed; no direct writes to the physical log are allowed.")
    #ERROR_LOG_DEDICATED
    $AMHintsTable.Add("0x800719E7", "The operation failed because the log is a dedicated log.")
    #ERROR_LOG_ARCHIVE_NOT_IN_PROGRESS
    $AMHintsTable.Add("0x800719E8", "The operation requires an archive context.")
    #ERROR_LOG_ARCHIVE_IN_PROGRESS
    $AMHintsTable.Add("0x800719E9", "Log archival is in progress.")
    #ERROR_LOG_EPHEMERAL
    $AMHintsTable.Add("0x800719EA", "The operation requires a non-ephemeral log, but the log is ephemeral.")
    #ERROR_LOG_NOT_ENOUGH_CONTAINERS
    $AMHintsTable.Add("0x800719EB", "The log must have at least two containers before it can be read from or written to.")
    #ERROR_LOG_CLIENT_ALREADY_REGISTERED
    $AMHintsTable.Add("0x800719EC", "A log client has already registered on the stream.")
    #ERROR_LOG_CLIENT_NOT_REGISTERED
    $AMHintsTable.Add("0x800719ED", "A log client has not been registered on the stream.")
    #ERROR_LOG_FULL_HANDLER_IN_PROGRESS
    $AMHintsTable.Add("0x800719EE", "A request has already been made to handle the log full condition.")
    #ERROR_LOG_CONTAINER_READ_FAILED
    $AMHintsTable.Add("0x800719EF", "The log service encountered an error when attempting to read from a log container.")
    #ERROR_LOG_CONTAINER_WRITE_FAILED
    $AMHintsTable.Add("0x800719F0", "The log service encountered an error when attempting to write to a log container.")
    #ERROR_LOG_CONTAINER_OPEN_FAILED
    $AMHintsTable.Add("0x800719F1", "The log service encountered an error when attempting to open a log container.")
    #ERROR_LOG_CONTAINER_STATE_INVALID
    $AMHintsTable.Add("0x800719F2", "The log service encountered an invalid container state when attempting a requested action.")
    #ERROR_LOG_STATE_INVALID
    $AMHintsTable.Add("0x800719F3", "The log service is not in the correct state to perform a requested action.")
    #ERROR_LOG_PINNED
    $AMHintsTable.Add("0x800719F4", "The log space cannot be reclaimed because the log is pinned.")
    #ERROR_LOG_METADATA_FLUSH_FAILED
    $AMHintsTable.Add("0x800719F5", "The log metadata flush failed.")
    #ERROR_LOG_INCONSISTENT_SECURITY
    $AMHintsTable.Add("0x800719F6", "Security on the log and its containers is inconsistent.")
    #ERROR_LOG_APPENDED_FLUSH_FAILED
    $AMHintsTable.Add("0x800719F7", "Records were appended to the log or reservation changes were made, but the log could not be flushed.")
    #ERROR_LOG_PINNED_RESERVATION
    $AMHintsTable.Add("0x800719F8", "The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available.")
    #ERROR_INVALID_TRANSACTION
    $AMHintsTable.Add("0x80071A2C", "The transaction handle associated with this operation is not valid.")
    #ERROR_TRANSACTION_NOT_ACTIVE
    $AMHintsTable.Add("0x80071A2D", "The requested operation was made in the context of a transaction that is no longer active.")
    #ERROR_TRANSACTION_REQUEST_NOT_VALID
    $AMHintsTable.Add("0x80071A2E", "The requested operation is not valid on the transaction object in its current state.")
    #ERROR_TRANSACTION_NOT_REQUESTED
    $AMHintsTable.Add("0x80071A2F", "The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller.")
    #ERROR_TRANSACTION_ALREADY_ABORTED
    $AMHintsTable.Add("0x80071A30", "It is too late to perform the requested operation because the transaction has already been aborted.")
    #ERROR_TRANSACTION_ALREADY_COMMITTED
    $AMHintsTable.Add("0x80071A31", "It is too late to perform the requested operation because the transaction has already been committed.")
    #ERROR_TM_INITIALIZATION_FAILED
    $AMHintsTable.Add("0x80071A32", "The transaction manager was unable to be successfully initialized. Transacted operations are not supported.")
    #ERROR_RESOURCEMANAGER_READ_ONLY
    $AMHintsTable.Add("0x80071A33", "The specified resource manager made no changes or updates to the resource under this transaction.")
    #ERROR_TRANSACTION_NOT_JOINED
    $AMHintsTable.Add("0x80071A34", "The resource manager has attempted to prepare a transaction that it has not successfully joined.")
    #ERROR_TRANSACTION_SUPERIOR_EXISTS
    $AMHintsTable.Add("0x80071A35", "The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed.")
    #ERROR_CRM_PROTOCOL_ALREADY_EXISTS
    $AMHintsTable.Add("0x80071A36", "The resource manager tried to register a protocol that already exists.")
    #ERROR_TRANSACTION_PROPAGATION_FAILED
    $AMHintsTable.Add("0x80071A37", "The attempt to propagate the transaction failed.")
    #ERROR_CRM_PROTOCOL_NOT_FOUND
    $AMHintsTable.Add("0x80071A38", "The requested propagation protocol was not registered as a CRM.")
    #ERROR_TRANSACTION_INVALID_MARSHALL_BUFFER
    $AMHintsTable.Add("0x80071A39", "The buffer passed in to PushTransaction or PullTransaction is not in a valid format.")
    #ERROR_CURRENT_TRANSACTION_NOT_VALID
    $AMHintsTable.Add("0x80071A3A", "The current transaction context associated with the thread is not a valid handle to a transaction object.")
    #ERROR_TRANSACTION_NOT_FOUND
    $AMHintsTable.Add("0x80071A3B", "The specified transaction object could not be opened because it was not found.")
    #ERROR_RESOURCEMANAGER_NOT_FOUND
    $AMHintsTable.Add("0x80071A3C", "The specified resource manager object could not be opened because it was not found.")
    #ERROR_ENLISTMENT_NOT_FOUND
    $AMHintsTable.Add("0x80071A3D", "The specified enlistment object could not be opened because it was not found.")
    #ERROR_TRANSACTIONMANAGER_NOT_FOUND
    $AMHintsTable.Add("0x80071A3E", "The specified transaction manager object could not be opened because it was not found.")
    #ERROR_TRANSACTIONMANAGER_NOT_ONLINE
    $AMHintsTable.Add("0x80071A3F", "The specified resource manager was unable to create an enlistment because its associated transaction manager is not online.")
    #ERROR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION
    $AMHintsTable.Add("0x80071A40", "The specified transaction manager was unable to create the objects contained in its log file in the ObjectB namespace. Therefore, the transaction manager was unable to recover.")
    #ERROR_TRANSACTIONAL_CONFLICT
    $AMHintsTable.Add("0x80071A90", "The function attempted to use a name that is reserved for use by another transaction.")
    #ERROR_RM_NOT_ACTIVE
    $AMHintsTable.Add("0x80071A91", "Transaction support within the specified file system resource manager is not started or was shut down due to an error.")
    #ERROR_RM_METADATA_CORRUPT
    $AMHintsTable.Add("0x80071A92", "The metadata of the resource manager has been corrupted. The resource manager will not function.")
    #ERROR_DIRECTORY_NOT_RM
    $AMHintsTable.Add("0x80071A93", "The specified directory does not contain a resource manager.")
    #ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE
    $AMHintsTable.Add("0x80071A95", "The remote server or share does not support transacted file operations.")
    #ERROR_LOG_RESIZE_INVALID_SIZE
    $AMHintsTable.Add("0x80071A96", "The requested log size is invalid.")
    #ERROR_OBJECT_NO_LONGER_EXISTS
    $AMHintsTable.Add("0x80071A97", "The object (file, stream, link) corresponding to the handle has been deleted by a transaction savepoint rollback.")
    #ERROR_STREAM_MINIVERSION_NOT_FOUND
    $AMHintsTable.Add("0x80071A98", "The specified file miniversion was not found for this transacted file open.")
    #ERROR_STREAM_MINIVERSION_NOT_VALID
    $AMHintsTable.Add("0x80071A99", "The specified file miniversion was found but has been invalidated. The most likely cause is a transaction savepoint rollback.")
    #ERROR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION
    $AMHintsTable.Add("0x80071A9A", "A miniversion may only be opened in the context of the transaction that created it.")
    #ERROR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT
    $AMHintsTable.Add("0x80071A9B", "It is not possible to open a miniversion with modify access.")
    #ERROR_CANT_CREATE_MORE_STREAM_MINIVERSIONS
    $AMHintsTable.Add("0x80071A9C", "It is not possible to create any more miniversions for this stream.")
    #ERROR_REMOTE_FILE_VERSION_MISMATCH
    $AMHintsTable.Add("0x80071A9E", "The remote server sent mismatching version numbers or FID for a file opened with transactions.")
    #ERROR_HANDLE_NO_LONGER_VALID
    $AMHintsTable.Add("0x80071A9F", "The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file, or an open handle when the transaction ended or rolled back to savepoint.")
    #ERROR_NO_TXF_METADATA
    $AMHintsTable.Add("0x80071AA0", "There is no transaction metadata on the file.")
    #ERROR_LOG_CORRUPTION_DETECTED
    $AMHintsTable.Add("0x80071AA1", "The log data is corrupt.")
    #ERROR_CANT_RECOVER_WITH_HANDLE_OPEN
    $AMHintsTable.Add("0x80071AA2", "The file cannot be recovered because a handle is still open on it.")
    #ERROR_RM_DISCONNECTED
    $AMHintsTable.Add("0x80071AA3", "The transaction outcome is unavailable because the resource manager responsible for it is disconnected.")
    #ERROR_ENLISTMENT_NOT_SUPERIOR
    $AMHintsTable.Add("0x80071AA4", "The request was rejected because the enlistment in question is not a superior enlistment.")
    #ERROR_RECOVERY_NOT_NEEDED
    $AMHintsTable.Add("0x80071AA5", "The transactional resource manager is already consistent. Recovery is not needed.")
    #ERROR_RM_ALREADY_STARTED
    $AMHintsTable.Add("0x80071AA6", "The transactional resource manager has already been started.")
    #ERROR_FILE_IDENTITY_NOT_PERSISTENT
    $AMHintsTable.Add("0x80071AA7", "The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction.")
    #ERROR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY
    $AMHintsTable.Add("0x80071AA8", "The operation cannot be performed because another transaction is depending on the fact that this property will not change.")
    #ERROR_CANT_CROSS_RM_BOUNDARY
    $AMHintsTable.Add("0x80071AA9", "The operation would involve a single file with two transactional resource managers and is therefore not allowed.")
    #ERROR_TXF_DIR_NOT_EMPTY
    $AMHintsTable.Add("0x80071AAA", "The `$Txf directory must be empty for this operation to succeed.")
    #ERROR_INDOUBT_TRANSACTIONS_EXIST
    $AMHintsTable.Add("0x80071AAB", "The operation would leave a transactional resource manager in an inconsistent state and is, therefore, not allowed.")
    #ERROR_TM_VOLATILE
    $AMHintsTable.Add("0x80071AAC", "The operation could not be completed because the transaction manager does not have a log.")
    #ERROR_ROLLBACK_TIMER_EXPIRED
    $AMHintsTable.Add("0x80071AAD", "A rollback could not be scheduled because a previously scheduled rollback has already been executed or is queued for execution.")
    #ERROR_TXF_ATTRIBUTE_CORRUPT
    $AMHintsTable.Add("0x80071AAE", "The transactional metadata attribute on the file or directory is corrupt and unreadable.")
    #ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION
    $AMHintsTable.Add("0x80071AAF", "The encryption operation could not be completed because a transaction is active.")
    #ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED
    $AMHintsTable.Add("0x80071AB0", "This object is not allowed to be opened in a transaction.")
    #ERROR_LOG_GROWTH_FAILED
    $AMHintsTable.Add("0x80071AB1", "An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log.")
    #ERROR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE
    $AMHintsTable.Add("0x80071AB2", "Memory mapping (creating a mapped section) to a remote file under a transaction is not supported.")
    #ERROR_TXF_METADATA_ALREADY_PRESENT
    $AMHintsTable.Add("0x80071AB3", "Transaction metadata is already present on this file and cannot be superseded.")
    #ERROR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET
    $AMHintsTable.Add("0x80071AB4", "A transaction scope could not be entered because the scope handler has not been initialized.")
    #ERROR_TRANSACTION_REQUIRED_PROMOTION
    $AMHintsTable.Add("0x80071AB5", "Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it.")
    #ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION
    $AMHintsTable.Add("0x80071AB6", "This file is open for modification in an unresolved transaction and may be opened for execution only by a transacted reader.")
    #ERROR_TRANSACTIONS_NOT_FROZEN
    $AMHintsTable.Add("0x80071AB7", "The request to thaw frozen transactions was ignored because transactions were not previously frozen.")
    #ERROR_TRANSACTION_FREEZE_IN_PROGRESS
    $AMHintsTable.Add("0x80071AB8", "Transactions cannot be frozen because a freeze is already in progress.")
    #ERROR_NOT_SNAPSHOT_VOLUME
    $AMHintsTable.Add("0x80071AB9", "The target volume is not a snapshot volume. This operation is only valid on a volume mounted as a snapshot.")
    #ERROR_NO_SAVEPOINT_WITH_OPEN_FILES
    $AMHintsTable.Add("0x80071ABA", "The savepoint operation failed because files are open on the transaction. This is not permitted.")
    #ERROR_DATA_LOST_REPAIR
    $AMHintsTable.Add("0x80071ABB", "Windows has discovered corruption in a file, and that file has since been repaired. Data loss may have occurred.")
    #ERROR_SPARSE_NOT_ALLOWED_IN_TRANSACTION
    $AMHintsTable.Add("0x80071ABC", "The sparse operation could not be completed because a transaction is active on the file.")
    #ERROR_TM_IDENTITY_MISMATCH
    $AMHintsTable.Add("0x80071ABD", "The call to create a transaction manager object failed because the Tm Identity stored in the logfile does not match the Tm Identity that was passed in as an argument.")
    #ERROR_FLOATED_SECTION
    $AMHintsTable.Add("0x80071ABE", "I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data.")
    #ERROR_CANNOT_ACCEPT_TRANSACTED_WORK
    $AMHintsTable.Add("0x80071ABF", "The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources.")
    #ERROR_CANNOT_ABORT_TRANSACTIONS
    $AMHintsTable.Add("0x80071AC0", "The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down.")
    #ERROR_CTX_WINSTATION_NAME_INVALID
    $AMHintsTable.Add("0x80071B59", "The specified session name is invalid.")
    #ERROR_CTX_INVALID_PD
    $AMHintsTable.Add("0x80071B5A", "The specified protocol driver is invalid.")
    #ERROR_CTX_PD_NOT_FOUND
    $AMHintsTable.Add("0x80071B5B", "The specified protocol driver was not found in the system path.")
    #ERROR_CTX_WD_NOT_FOUND
    $AMHintsTable.Add("0x80071B5C", "The specified terminal connection driver was not found in the system path.")
    #ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY
    $AMHintsTable.Add("0x80071B5D", "A registry key for event logging could not be created for this session.")
    #ERROR_CTX_SERVICE_NAME_COLLISION
    $AMHintsTable.Add("0x80071B5E", "A service with the same name already exists on the system.")
    #ERROR_CTX_CLOSE_PENDING
    $AMHintsTable.Add("0x80071B5F", "A close operation is pending on the session.")
    #ERROR_CTX_NO_OUTBUF
    $AMHintsTable.Add("0x80071B60", "There are no free output buffers available.")
    #ERROR_CTX_MODEM_INF_NOT_FOUND
    $AMHintsTable.Add("0x80071B61", "The MODEM.INF file was not found.")
    #ERROR_CTX_INVALID_MODEMNAME
    $AMHintsTable.Add("0x80071B62", "The modem name was not found in the MODEM.INF file.")
    #ERROR_CTX_MODEM_RESPONSE_ERROR
    $AMHintsTable.Add("0x80071B63", "The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem.")
    #ERROR_CTX_MODEM_RESPONSE_TIMEOUT
    $AMHintsTable.Add("0x80071B64", "The modem did not respond to the command sent to it. Verify that the modem is properly cabled and turned on.")
    #ERROR_CTX_MODEM_RESPONSE_NO_CARRIER
    $AMHintsTable.Add("0x80071B65", "Carrier detect has failed or carrier has been dropped due to disconnect.")
    #ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE
    $AMHintsTable.Add("0x80071B66", "Dial tone not detected within the required time. Verify that the phone cable is properly attached and functional.")
    #ERROR_CTX_MODEM_RESPONSE_BUSY
    $AMHintsTable.Add("0x80071B67", "Busy signal detected at remote site on callback.")
    #ERROR_CTX_MODEM_RESPONSE_VOICE
    $AMHintsTable.Add("0x80071B68", "Voice detected at remote site on callback.")
    #ERROR_CTX_TD_ERROR
    $AMHintsTable.Add("0x80071B69", "Transport driver error.")
    #ERROR_CTX_WINSTATION_NOT_FOUND
    $AMHintsTable.Add("0x80071B6E", "The specified session cannot be found.")
    #ERROR_CTX_WINSTATION_ALREADY_EXISTS
    $AMHintsTable.Add("0x80071B6F", "The specified session name is already in use.")
    #ERROR_CTX_WINSTATION_BUSY
    $AMHintsTable.Add("0x80071B70", "The requested operation cannot be completed because the terminal connection is currently busy processing a connect, disconnect, reset, or delete operation.")
    #ERROR_CTX_BAD_VIDEO_MODE
    $AMHintsTable.Add("0x80071B71", "An attempt has been made to connect to a session whose video mode is not supported by the current client.")
    #ERROR_CTX_GRAPHICS_INVALID
    $AMHintsTable.Add("0x80071B7B", "The application attempted to enable DOS graphics mode. DOS graphics mode is not supported.")
    #ERROR_CTX_LOGON_DISABLED
    $AMHintsTable.Add("0x80071B7D", "Your interactive logon privilege has been disabled. Contact your administrator.")
    #ERROR_CTX_NOT_CONSOLE
    $AMHintsTable.Add("0x80071B7E", "The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access.")
    #ERROR_CTX_CLIENT_QUERY_TIMEOUT
    $AMHintsTable.Add("0x80071B80", "The client failed to respond to the server connect message.")
    #ERROR_CTX_CONSOLE_DISCONNECT
    $AMHintsTable.Add("0x80071B81", "Disconnecting the console session is not supported.")
    #ERROR_CTX_CONSOLE_CONNECT
    $AMHintsTable.Add("0x80071B82", "Reconnecting a disconnected session to the console is not supported.")
    #ERROR_CTX_SHADOW_DENIED
    $AMHintsTable.Add("0x80071B84", "The request to control another session remotely was denied.")
    #ERROR_CTX_WINSTATION_ACCESS_DENIED
    $AMHintsTable.Add("0x80071B85", "The requested session access is denied.")
    #ERROR_CTX_INVALID_WD
    $AMHintsTable.Add("0x80071B89", "The specified terminal connection driver is invalid.")
    #ERROR_CTX_SHADOW_INVALID
    $AMHintsTable.Add("0x80071B8A", "The requested session cannot be controlled remotely. This may be because the session is disconnected or does not currently have a user logged on.")
    #ERROR_CTX_SHADOW_DISABLED
    $AMHintsTable.Add("0x80071B8B", "The requested session is not configured to allow remote control.")
    #ERROR_CTX_CLIENT_LICENSE_IN_USE
    $AMHintsTable.Add("0x80071B8C", "Your request to connect to this terminal server has been rejected. Your terminal server client license number is currently being used by another user. Call your system administrator to obtain a unique license number.")
    #ERROR_CTX_CLIENT_LICENSE_NOT_SET
    $AMHintsTable.Add("0x80071B8D", "Your request to connect to this terminal server has been rejected. Your terminal server client license number has not been entered for this copy of the terminal server client. Contact your system administrator.")
    #ERROR_CTX_LICENSE_NOT_AVAILABLE
    $AMHintsTable.Add("0x80071B8E", "The number of connections to this computer is limited and all connections are in use right now. Try connecting later or contact your system administrator.")
    #ERROR_CTX_LICENSE_CLIENT_INVALID
    $AMHintsTable.Add("0x80071B8F", "The client you are using is not licensed to use this system. Your logon request is denied.")
    #ERROR_CTX_LICENSE_EXPIRED
    $AMHintsTable.Add("0x80071B90", "The system license has expired. Your logon request is denied.")
    #ERROR_CTX_SHADOW_NOT_RUNNING
    $AMHintsTable.Add("0x80071B91", "Remote control could not be terminated because the specified session is not currently being remotely controlled.")
    #ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE
    $AMHintsTable.Add("0x80071B92", "The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported.")
    #ERROR_ACTIVATION_COUNT_EXCEEDED
    $AMHintsTable.Add("0x80071B93", "Activation has already been reset the maximum number of times for this installation. Your activation timer will not be cleared.")
    #ERROR_CTX_WINSTATIONS_DISABLED
    $AMHintsTable.Add("0x80071B94", "Remote logons are currently disabled.")
    #ERROR_CTX_ENCRYPTION_LEVEL_REQUIRED
    $AMHintsTable.Add("0x80071B95", "You do not have the proper encryption level to access this session.")
    #ERROR_CTX_SESSION_IN_USE
    $AMHintsTable.Add("0x80071B96", "The user %s\\%s is currently logged on to this computer. Only the current user or an administrator can log on to this computer.")
    #ERROR_CTX_NO_FORCE_LOGOFF
    $AMHintsTable.Add("0x80071B97", "The user %s\\%s is already logged on to the console of this computer. You do not have permission to log in at this time. To resolve this issue, contact %s\\%s and have them log off.")
    #ERROR_CTX_ACCOUNT_RESTRICTION
    $AMHintsTable.Add("0x80071B98", "Unable to log you on because of an account restriction.")
    #ERROR_RDP_PROTOCOL_ERROR
    $AMHintsTable.Add("0x80071B99", "The RDP component %2 detected an error in the protocol stream and has disconnected the client.")
    #ERROR_CTX_CDM_CONNECT
    $AMHintsTable.Add("0x80071B9A", "The Client Drive Mapping Service has connected on terminal connection.")
    #ERROR_CTX_CDM_DISCONNECT
    $AMHintsTable.Add("0x80071B9B", "The Client Drive Mapping Service has disconnected on terminal connection.")
    #ERROR_CTX_SECURITY_LAYER_ERROR
    $AMHintsTable.Add("0x80071B9C", "The terminal server security layer detected an error in the protocol stream and has disconnected the client.")
    #ERROR_TS_INCOMPATIBLE_SESSIONS
    $AMHintsTable.Add("0x80071B9D", "The target session is incompatible with the current session.")
    #FRS_ERR_INVALID_API_SEQUENCE
    $AMHintsTable.Add("0x80071F41", "The file replication service API was called incorrectly.")
    #FRS_ERR_STARTING_SERVICE
    $AMHintsTable.Add("0x80071F42", "The file replication service cannot be started.")
    #FRS_ERR_STOPPING_SERVICE
    $AMHintsTable.Add("0x80071F43", "The file replication service cannot be stopped.")
    #FRS_ERR_INTERNAL_API
    $AMHintsTable.Add("0x80071F44", "The file replication service API terminated the request. The event log may have more information.")
    #FRS_ERR_INTERNAL
    $AMHintsTable.Add("0x80071F45", "The file replication service terminated the request. The event log may have more information.")
    #FRS_ERR_SERVICE_COMM
    $AMHintsTable.Add("0x80071F46", "The file replication service cannot be contacted. The event log may have more information.")
    #FRS_ERR_INSUFFICIENT_PRIV
    $AMHintsTable.Add("0x80071F47", "The file replication service cannot satisfy the request because the user has insufficient privileges. The event log may have more information.")
    #FRS_ERR_AUTHENTICATION
    $AMHintsTable.Add("0x80071F48", "The file replication service cannot satisfy the request because authenticated RPC is not available. The event log may have more information.")
    #FRS_ERR_PARENT_INSUFFICIENT_PRIV
    $AMHintsTable.Add("0x80071F49", "The file replication service cannot satisfy the request because the user has insufficient privileges on the domain controller. The event log may have more information.")
    #FRS_ERR_PARENT_AUTHENTICATION
    $AMHintsTable.Add("0x80071F4A", "The file replication service cannot satisfy the request because authenticated RPC is not available on the domain controller. The event log may have more information.")
    #FRS_ERR_CHILD_TO_PARENT_COMM
    $AMHintsTable.Add("0x80071F4B", "The file replication service cannot communicate with the file replication service on the domain controller. The event log may have more information.")
    #FRS_ERR_PARENT_TO_CHILD_COMM
    $AMHintsTable.Add("0x80071F4C", "The file replication service on the domain controller cannot communicate with the file replication service on this computer. The event log may have more information.")
    #FRS_ERR_SYSVOL_POPULATE
    $AMHintsTable.Add("0x80071F4D", "The file replication service cannot populate the system volume because of an internal error. The event log may have more information.")
    #FRS_ERR_SYSVOL_POPULATE_TIMEOUT
    $AMHintsTable.Add("0x80071F4E", "The file replication service cannot populate the system volume because of an internal time-out. The event log may have more information.")
    #FRS_ERR_SYSVOL_IS_BUSY
    $AMHintsTable.Add("0x80071F4F", "The file replication service cannot process the request. The system volume is busy with a previous request.")
    #FRS_ERR_SYSVOL_DEMOTE
    $AMHintsTable.Add("0x80071F50", "The file replication service cannot stop replicating the system volume because of an internal error. The event log may have more information.")
    #FRS_ERR_INVALID_SERVICE_PARAMETER
    $AMHintsTable.Add("0x80071F51", "The file replication service detected an invalid parameter.")
    #ERROR_DS_NOT_INSTALLED
    $AMHintsTable.Add("0x80072008", "An error occurred while installing the directory service. For more information, see the event log.")
    #ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY
    $AMHintsTable.Add("0x80072009", "The directory service evaluated group memberships locally.")
    #ERROR_DS_NO_ATTRIBUTE_OR_VALUE
    $AMHintsTable.Add("0x8007200A", "The specified directory service attribute or value does not exist.")
    #ERROR_DS_INVALID_ATTRIBUTE_YNTAX
    $AMHintsTable.Add("0x8007200B", "The attribute syntax specified to the directory service is invalid.")
    #ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED
    $AMHintsTable.Add("0x8007200C", "The attribute type specified to the directory service is not defined.")
    #ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS
    $AMHintsTable.Add("0x8007200D", "The specified directory service attribute or value already exists.")
    #ERROR_DS_BUSY
    $AMHintsTable.Add("0x8007200E", "The directory service is busy.")
    #ERROR_DS_UNAVAILABLE
    $AMHintsTable.Add("0x8007200F", "The directory service is unavailable.")
    #ERROR_DS_NO_RIDS_ALLOCATED
    $AMHintsTable.Add("0x80072010", "The directory service was unable to allocate a relative identifier.")
    #ERROR_DS_NO_MORE_RIDS
    $AMHintsTable.Add("0x80072011", "The directory service has exhausted the pool of relative identifiers.")
    #ERROR_DS_INCORRECT_ROLE_OWNER
    $AMHintsTable.Add("0x80072012", "The requested operation could not be performed because the directory service is not the master for that type of operation.")
    #ERROR_DS_RIDMGR_INIT_ERROR
    $AMHintsTable.Add("0x80072013", "The directory service was unable to initialize the subsystem that allocates relative identifiers.")
    #ERROR_DS_OBJ_CLASS_VIOLATION
    $AMHintsTable.Add("0x80072014", "The requested operation did not satisfy one or more constraints associated with the class of the object.")
    #ERROR_DS_CANT_ON_NON_LEAF
    $AMHintsTable.Add("0x80072015", "The directory service can perform the requested operation only on a leaf object.")
    #ERROR_DS_CANT_ON_RDN
    $AMHintsTable.Add("0x80072016", "The directory service cannot perform the requested operation on the relative distinguished name (RDN) attribute of an object.")
    #ERROR_DS_CANT_MOD_OBJ_CLASS
    $AMHintsTable.Add("0x80072017", "The directory service detected an attempt to modify the object class of an object.")
    #ERROR_DS_CROSS_DOM_MOVE_ERROR
    $AMHintsTable.Add("0x80072018", "The requested cross-domain move operation could not be performed.")
    #ERROR_DS_GC_NOT_AVAILABLE
    $AMHintsTable.Add("0x80072019", "Unable to contact the global catalog (GC) server.")
    #ERROR_SHARED_POLICY
    $AMHintsTable.Add("0x8007201A", "The policy object is shared and can only be modified at the root.")
    #ERROR_POLICY_OBJECT_NOT_FOUND
    $AMHintsTable.Add("0x8007201B", "The policy object does not exist.")
    #ERROR_POLICY_ONLY_IN_DS
    $AMHintsTable.Add("0x8007201C", "The requested policy information is only in the directory service.")
    #ERROR_PROMOTION_ACTIVE
    $AMHintsTable.Add("0x8007201D", "A domain controller promotion is currently active.")
    #ERROR_NO_PROMOTION_ACTIVE
    $AMHintsTable.Add("0x8007201E", "A domain controller promotion is not currently active.")
    #ERROR_DS_OPERATIONS_ERROR
    $AMHintsTable.Add("0x80072020", "An operations error occurred.")
    #ERROR_DS_PROTOCOL_ERROR
    $AMHintsTable.Add("0x80072021", "A protocol error occurred.")
    #ERROR_DS_TIMELIMIT_EXCEEDED
    $AMHintsTable.Add("0x80072022", "The time limit for this request was exceeded.")
    #ERROR_DS_SIZELIMIT_EXCEEDED
    $AMHintsTable.Add("0x80072023", "The size limit for this request was exceeded.")
    #ERROR_DS_ADMIN_LIMIT_EXCEEDED
    $AMHintsTable.Add("0x80072024", "The administrative limit for this request was exceeded.")
    #ERROR_DS_COMPARE_FALSE
    $AMHintsTable.Add("0x80072025", "The compare response was false.")
    #ERROR_DS_COMPARE_TRUE
    $AMHintsTable.Add("0x80072026", "The compare response was true.")
    #ERROR_DS_AUTH_METHOD_NOT_SUPPORTED
    $AMHintsTable.Add("0x80072027", "The requested authentication method is not supported by the server.")
    #ERROR_DS_STRONG_AUTH_REQUIRED
    $AMHintsTable.Add("0x80072028", "A more secure authentication method is required for this server.")
    #ERROR_DS_INAPPROPRIATE_AUTH
    $AMHintsTable.Add("0x80072029", "Inappropriate authentication.")
    #ERROR_DS_AUTH_UNKNOWN
    $AMHintsTable.Add("0x8007202A", "The authentication mechanism is unknown.")
    #ERROR_DS_REFERRAL
    $AMHintsTable.Add("0x8007202B", "A referral was returned from the server.")
    #ERROR_DS_UNAVAILABLE_CRIT_EXTENSION
    $AMHintsTable.Add("0x8007202C", "The server does not support the requested critical extension.")
    #ERROR_DS_CONFIDENTIALITY_REQUIRED
    $AMHintsTable.Add("0x8007202D", "This request requires a secure connection.")
    #ERROR_DS_INAPPROPRIATE_MATCHING
    $AMHintsTable.Add("0x8007202E", "Inappropriate matching.")
    #ERROR_DS_CONSTRAINT_VIOLATION
    $AMHintsTable.Add("0x8007202F", "A constraint violation occurred.")
    #ERROR_DS_NO_SUCH_OBJECT
    $AMHintsTable.Add("0x80072030", "There is no such object on the server.")
    #ERROR_DS_ALIAS_PROBLEM
    $AMHintsTable.Add("0x80072031", "There is an alias problem.")
    #ERROR_DS_INVALID_DN_SYNTAX
    $AMHintsTable.Add("0x80072032", "An invalid dn syntax has been specified.")
    #ERROR_DS_IS_LEAF
    $AMHintsTable.Add("0x80072033", "The object is a leaf object.")
    #ERROR_DS_ALIAS_DEREF_PROBLEM
    $AMHintsTable.Add("0x80072034", "There is an alias dereferencing problem.")
    #ERROR_DS_UNWILLING_TO_PERFORM
    $AMHintsTable.Add("0x80072035", "The server is unwilling to process the request.")
    #ERROR_DS_LOOP_DETECT
    $AMHintsTable.Add("0x80072036", "A loop has been detected.")
    #ERROR_DS_NAMING_VIOLATION
    $AMHintsTable.Add("0x80072037", "There is a naming violation.")
    #ERROR_DS_OBJECT_RESULTS_TOO_LARGE
    $AMHintsTable.Add("0x80072038", "The result set is too large.")
    #ERROR_DS_AFFECTS_MULTIPLE_DSAS
    $AMHintsTable.Add("0x80072039", "The operation affects multiple DSAs.")
    #ERROR_DS_SERVER_DOWN
    $AMHintsTable.Add("0x8007203A", "The server is not operational.")
    #ERROR_DS_LOCAL_ERROR
    $AMHintsTable.Add("0x8007203B", "A local error has occurred.")
    #ERROR_DS_ENCODING_ERROR
    $AMHintsTable.Add("0x8007203C", "An encoding error has occurred.")
    #ERROR_DS_DECODING_ERROR
    $AMHintsTable.Add("0x8007203D", "A decoding error has occurred.")
    #ERROR_DS_FILTER_UNKNOWN
    $AMHintsTable.Add("0x8007203E", "The search filter cannot be recognized.")
    #ERROR_DS_PARAM_ERROR
    $AMHintsTable.Add("0x8007203F", "One or more parameters are illegal.")
    #ERROR_DS_NOT_SUPPORTED
    $AMHintsTable.Add("0x80072040", "The specified method is not supported.")
    #ERROR_DS_NO_RESULTS_RETURNED
    $AMHintsTable.Add("0x80072041", "No results were returned.")
    #ERROR_DS_CONTROL_NOT_FOUND
    $AMHintsTable.Add("0x80072042", "The specified control is not supported by the server.")
    #ERROR_DS_CLIENT_LOOP
    $AMHintsTable.Add("0x80072043", "A referral loop was detected by the client.")
    #ERROR_DS_REFERRAL_LIMIT_EXCEEDED
    $AMHintsTable.Add("0x80072044", "The preset referral limit was exceeded.")
    #ERROR_DS_SORT_CONTROL_MISSING
    $AMHintsTable.Add("0x80072045", "The search requires a SORT control.")
    #ERROR_DS_OFFSET_RANGE_ERROR
    $AMHintsTable.Add("0x80072046", "The search results exceed the offset range specified.")
    #ERROR_DS_ROOT_MUST_BE_NC
    $AMHintsTable.Add("0x8007206D", "The root object must be the head of a naming context. The root object cannot have an instantiated parent.")
    #ERROR_DS_ADD_REPLICA_INHIBITED
    $AMHintsTable.Add("0x8007206E", "The add replica operation cannot be performed. The naming context must be writable to create the replica.")
    #ERROR_DS_ATT_NOT_DEF_IN_SCHEMA
    $AMHintsTable.Add("0x8007206F", "A reference to an attribute that is not defined in the schema occurred.")
    #ERROR_DS_MAX_OBJ_SIZE_EXCEEDED
    $AMHintsTable.Add("0x80072070", "The maximum size of an object has been exceeded.")
    #ERROR_DS_OBJ_STRING_NAME_EXISTS
    $AMHintsTable.Add("0x80072071", "An attempt was made to add an object to the directory with a name that is already in use.")
    #ERROR_DS_NO_RDN_DEFINED_IN_SCHEMA
    $AMHintsTable.Add("0x80072072", "An attempt was made to add an object of a class that does not have an RDN defined in the schema.")
    #ERROR_DS_RDN_DOESNT_MATCH_SCHEMA
    $AMHintsTable.Add("0x80072073", "An attempt was made to add an object using an RDN that is not the RDN defined in the schema.")
    #ERROR_DS_NO_REQUESTED_ATTS_FOUND
    $AMHintsTable.Add("0x80072074", "None of the requested attributes were found on the objects.")
    #ERROR_DS_USER_BUFFER_TO_SMALL
    $AMHintsTable.Add("0x80072075", "The user buffer is too small.")
    #ERROR_DS_ATT_IS_NOT_ON_OBJ
    $AMHintsTable.Add("0x80072076", "The attribute specified in the operation is not present on the object.")
    #ERROR_DS_ILLEGAL_MOD_OPERATION
    $AMHintsTable.Add("0x80072077", "Illegal modify operation. Some aspect of the modification is not permitted.")
    #ERROR_DS_OBJ_TOO_LARGE
    $AMHintsTable.Add("0x80072078", "The specified object is too large.")
    #ERROR_DS_BAD_INSTANCE_TYPE
    $AMHintsTable.Add("0x80072079", "The specified instance type is not valid.")
    #ERROR_DS_MASTERDSA_REQUIRED
    $AMHintsTable.Add("0x8007207A", "The operation must be performed at a master DSA.")
    #ERROR_DS_OBJECT_CLASS_REQUIRED
    $AMHintsTable.Add("0x8007207B", "The object class attribute must be specified.")
    #ERROR_DS_MISSING_REQUIRED_ATT
    $AMHintsTable.Add("0x8007207C", "A required attribute is missing.")
    #ERROR_DS_ATT_NOT_DEF_FOR_CLASS
    $AMHintsTable.Add("0x8007207D", "An attempt was made to modify an object to include an attribute that is not legal for its class.")
    #ERROR_DS_ATT_ALREADY_EXISTS
    $AMHintsTable.Add("0x8007207E", "The specified attribute is already present on the object.")
    #ERROR_DS_CANT_ADD_ATT_VALUES
    $AMHintsTable.Add("0x80072080", "The specified attribute is not present, or has no values.")
    #ERROR_DS_SINGLE_VALUE_CONSTRAINT
    $AMHintsTable.Add("0x80072081", "Multiple values were specified for an attribute that can have only one value.")
    #ERROR_DS_RANGE_CONSTRAINT
    $AMHintsTable.Add("0x80072082", "A value for the attribute was not in the acceptable range of values.")
    #ERROR_DS_ATT_VAL_ALREADY_EXISTS
    $AMHintsTable.Add("0x80072083", "The specified value already exists.")
    #ERROR_DS_CANT_REM_MISSING_ATT
    $AMHintsTable.Add("0x80072084", "The attribute cannot be removed because it is not present on the object.")
    #ERROR_DS_CANT_REM_MISSING_ATT_VAL
    $AMHintsTable.Add("0x80072085", "The attribute value cannot be removed because it is not present on the object.")
    #ERROR_DS_ROOT_CANT_BE_SUBREF
    $AMHintsTable.Add("0x80072086", "The specified root object cannot be a subreference.")
    #ERROR_DS_NO_CHAINING
    $AMHintsTable.Add("0x80072087", "Chaining is not permitted.")
    #ERROR_DS_NO_CHAINED_EVAL
    $AMHintsTable.Add("0x80072088", "Chained evaluation is not permitted.")
    #ERROR_DS_NO_PARENT_OBJECT
    $AMHintsTable.Add("0x80072089", "The operation could not be performed because the object's parent is either uninstantiated or deleted.")
    #ERROR_DS_PARENT_IS_AN_ALIAS
    $AMHintsTable.Add("0x8007208A", "Having a parent that is an alias is not permitted. Aliases are leaf objects.")
    #ERROR_DS_CANT_MIX_MASTER_AND_REPS
    $AMHintsTable.Add("0x8007208B", "The object and parent must be of the same type, either both masters or both replicas.")
    #ERROR_DS_CHILDREN_EXIST
    $AMHintsTable.Add("0x8007208C", "The operation cannot be performed because child objects exist. This operation can only be performed on a leaf object.")
    #ERROR_DS_OBJ_NOT_FOUND
    $AMHintsTable.Add("0x8007208D", "Directory object not found.")
    #ERROR_DS_ALIASED_OBJ_MISSING
    $AMHintsTable.Add("0x8007208E", "The aliased object is missing.")
    #ERROR_DS_BAD_NAME_SYNTAX
    $AMHintsTable.Add("0x8007208F", "The object name has bad syntax.")
    #ERROR_DS_ALIAS_POINTS_TO_ALIAS
    $AMHintsTable.Add("0x80072090", "An alias is not permitted to refer to another alias.")
    #ERROR_DS_CANT_DEREF_ALIAS
    $AMHintsTable.Add("0x80072091", "The alias cannot be dereferenced.")
    #ERROR_DS_OUT_OF_SCOPE
    $AMHintsTable.Add("0x80072092", "The operation is out of scope.")
    #ERROR_DS_OBJECT_BEING_REMOVED
    $AMHintsTable.Add("0x80072093", "The operation cannot continue because the object is in the process of being removed.")
    #ERROR_DS_CANT_DELETE_DSA_OBJ
    $AMHintsTable.Add("0x80072094", "The DSA object cannot be deleted.")
    #ERROR_DS_GENERIC_ERROR
    $AMHintsTable.Add("0x80072095", "A directory service error has occurred.")
    #ERROR_DS_DSA_MUST_BE_INT_MASTER
    $AMHintsTable.Add("0x80072096", "The operation can only be performed on an internal master DSA object.")
    #ERROR_DS_CLASS_NOT_DSA
    $AMHintsTable.Add("0x80072097", "The object must be of class DSA.")
    #ERROR_DS_INSUFF_ACCESS_RIGHTS
    $AMHintsTable.Add("0x80072098", "Insufficient access rights to perform the operation.")
    #ERROR_DS_ILLEGAL_SUPERIOR
    $AMHintsTable.Add("0x80072099", "The object cannot be added because the parent is not on the list of possible superiors.")
    #ERROR_DS_ATTRIBUTE_OWNED_BY_SAM
    $AMHintsTable.Add("0x8007209A", "Access to the attribute is not permitted because the attribute is owned by the SAM.")
    #ERROR_DS_NAME_TOO_MANY_PARTS
    $AMHintsTable.Add("0x8007209B", "The name has too many parts.")
    #ERROR_DS_NAME_TOO_LONG
    $AMHintsTable.Add("0x8007209C", "The name is too long.")
    #ERROR_DS_NAME_VALUE_TOO_LONG
    $AMHintsTable.Add("0x8007209D", "The name value is too long.")
    #ERROR_DS_NAME_UNPARSEABLE
    $AMHintsTable.Add("0x8007209E", "The directory service encountered an error parsing a name.")
    #ERROR_DS_NAME_TYPE_UNKNOWN
    $AMHintsTable.Add("0x8007209F", "The directory service cannot get the attribute type for a name.")
    #ERROR_DS_NOT_AN_OBJECT
    $AMHintsTable.Add("0x800720A0", "The name does not identify an object; the name identifies a phantom.")
    #ERROR_DS_SEC_DESC_TOO_SHORT
    $AMHintsTable.Add("0x800720A1", "The security descriptor is too short.")
    #ERROR_DS_SEC_DESC_INVALID
    $AMHintsTable.Add("0x800720A2", "The security descriptor is invalid.")
    #ERROR_DS_NO_DELETED_NAME
    $AMHintsTable.Add("0x800720A3", "Failed to create name for deleted object.")
    #ERROR_DS_SUBREF_MUST_HAVE_PARENT
    $AMHintsTable.Add("0x800720A4", "The parent of a new subreference must exist.")
    #ERROR_DS_NCNAME_MUST_BE_NC
    $AMHintsTable.Add("0x800720A5", "The object must be a naming context.")
    #ERROR_DS_CANT_ADD_SYSTEM_ONLY
    $AMHintsTable.Add("0x800720A6", "It is not permitted to add an attribute that is owned by the system.")
    #ERROR_DS_CLASS_MUST_BE_CONCRETE
    $AMHintsTable.Add("0x800720A7", "The class of the object must be structural; you cannot instantiate an abstract class.")
    #ERROR_DS_INVALID_DMD
    $AMHintsTable.Add("0x800720A8", "The schema object could not be found.")
    #ERROR_DS_OBJ_GUID_EXISTS
    $AMHintsTable.Add("0x800720A9", "A local object with this GUID (dead or alive) already exists.")
    #ERROR_DS_NOT_ON_BACKLINK
    $AMHintsTable.Add("0x800720AA", "The operation cannot be performed on a back link.")
    #ERROR_DS_NO_CROSSREF_FOR_NC
    $AMHintsTable.Add("0x800720AB", "The cross-reference for the specified naming context could not be found.")
    #ERROR_DS_SHUTTING_DOWN
    $AMHintsTable.Add("0x800720AC", "The operation could not be performed because the directory service is shutting down.")
    #ERROR_DS_UNKNOWN_OPERATION
    $AMHintsTable.Add("0x800720AD", "The directory service request is invalid.")
    #ERROR_DS_INVALID_ROLE_OWNER
    $AMHintsTable.Add("0x800720AE", "The role owner attribute could not be read.")
    #ERROR_DS_COULDNT_CONTACT_FSMO
    $AMHintsTable.Add("0x800720AF", "The requested Flexible Single Master Operations (FSMO) operation failed. The current FSMO holder could not be contacted.")
    #ERROR_DS_CROSS_NC_DN_RENAME
    $AMHintsTable.Add("0x800720B0", "Modification of a distinguished name across a naming context is not permitted.")
    #ERROR_DS_CANT_MOD_SYSTEM_ONLY
    $AMHintsTable.Add("0x800720B1", "The attribute cannot be modified because it is owned by the system.")
    #ERROR_DS_REPLICATOR_ONLY
    $AMHintsTable.Add("0x800720B2", "Only the replicator can perform this function.")
    #ERROR_DS_OBJ_CLASS_NOT_DEFINED
    $AMHintsTable.Add("0x800720B3", "The specified class is not defined.")
    #ERROR_DS_OBJ_CLASS_NOT_SUBCLASS
    $AMHintsTable.Add("0x800720B4", "The specified class is not a subclass.")
    #ERROR_DS_NAME_REFERENCE_INVALID
    $AMHintsTable.Add("0x800720B5", "The name reference is invalid.")
    #ERROR_DS_CROSS_REF_EXISTS
    $AMHintsTable.Add("0x800720B6", "A cross-reference already exists.")
    #ERROR_DS_CANT_DEL_MASTER_CROSSREF
    $AMHintsTable.Add("0x800720B7", "It is not permitted to delete a master cross-reference.")
    #ERROR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD
    $AMHintsTable.Add("0x800720B8", "Subtree notifications are only supported on naming context (NC) heads.")
    #ERROR_DS_NOTIFY_FILTER_TOO_COMPLEX
    $AMHintsTable.Add("0x800720B9", "Notification filter is too complex.")
    #ERROR_DS_DUP_RDN
    $AMHintsTable.Add("0x800720BA", "Schema update failed: Duplicate RDN.")
    #ERROR_DS_DUP_OID
    $AMHintsTable.Add("0x800720BB", "Schema update failed: Duplicate OID.")
    #ERROR_DS_DUP_MAPI_ID
    $AMHintsTable.Add("0x800720BC", "Schema update failed: Duplicate Message Application Programming Interface (MAPI) identifier.")
    #ERROR_DS_DUP_SCHEMA_ID_GUID
    $AMHintsTable.Add("0x800720BD", "Schema update failed: Duplicate schema ID GUID.")
    #ERROR_DS_DUP_LDAP_DISPLAY_NAME
    $AMHintsTable.Add("0x800720BE", "Schema update failed: Duplicate LDAP display name.")
    #ERROR_DS_SEMANTIC_ATT_TEST
    $AMHintsTable.Add("0x800720BF", "Schema update failed: Range-Lower less than Range-Upper.")
    #ERROR_DS_SYNTAX_MISMATCH
    $AMHintsTable.Add("0x800720C0", "Schema update failed: Syntax mismatch.")
    #ERROR_DS_EXISTS_IN_MUST_HAVE
    $AMHintsTable.Add("0x800720C1", "Schema deletion failed: Attribute is used in the Must-Contain list.")
    #ERROR_DS_EXISTS_IN_MAY_HAVE
    $AMHintsTable.Add("0x800720C2", "Schema deletion failed: Attribute is used in the May-Contain list.")
    #ERROR_DS_NONEXISTENT_MAY_HAVE
    $AMHintsTable.Add("0x800720C3", "Schema update failed: Attribute in May-Contain list does not exist.")
    #ERROR_DS_NONEXISTENT_MUST_HAVE
    $AMHintsTable.Add("0x800720C4", "Schema update failed: Attribute in the Must-Contain list does not exist.")
    #ERROR_DS_AUX_CLS_TEST_FAIL
    $AMHintsTable.Add("0x800720C5", "Schema update failed: Class in the Aux Class list does not exist or is not an auxiliary class.")
    #ERROR_DS_NONEXISTENT_POSS_SUP
    $AMHintsTable.Add("0x800720C6", "Schema update failed: Class in the Poss-Superiors list does not exist.")
    #ERROR_DS_SUB_CLS_TEST_FAIL
    $AMHintsTable.Add("0x800720C7", "Schema update failed: Class in the subclass of the list does not exist or does not satisfy hierarchy rules.")
    #ERROR_DS_BAD_RDN_ATT_ID_SYNTAX
    $AMHintsTable.Add("0x800720C8", "Schema update failed: Rdn-Att-Id has wrong syntax.")
    #ERROR_DS_EXISTS_IN_AUX_CLS
    $AMHintsTable.Add("0x800720C9", "Schema deletion failed: Class is used as an auxiliary class.")
    #ERROR_DS_EXISTS_IN_SUB_CLS
    $AMHintsTable.Add("0x800720CA", "Schema deletion failed: Class is used as a subclass.")
    #ERROR_DS_EXISTS_IN_POSS_SUP
    $AMHintsTable.Add("0x800720CB", "Schema deletion failed: Class is used as a Poss-Superior.")
    #ERROR_DS_RECALCSCHEMA_FAILED
    $AMHintsTable.Add("0x800720CC", "Schema update failed in recalculating validation cache.")
    #ERROR_DS_TREE_DELETE_NOT_FINISHED
    $AMHintsTable.Add("0x800720CD", "The tree deletion is not finished. The request must be made again to continue deleting the tree.")
    #ERROR_DS_CANT_DELETE
    $AMHintsTable.Add("0x800720CE", "The requested delete operation could not be performed.")
    #ERROR_DS_ATT_SCHEMA_REQ_ID
    $AMHintsTable.Add("0x800720CF", "Cannot read the governs class identifier for the schema record.")
    #ERROR_DS_BAD_ATT_SCHEMA_SYNTAX
    $AMHintsTable.Add("0x800720D0", "The attribute schema has bad syntax.")
    #ERROR_DS_CANT_CACHE_ATT
    $AMHintsTable.Add("0x800720D1", "The attribute could not be cached.")
    #ERROR_DS_CANT_CACHE_CLASS
    $AMHintsTable.Add("0x800720D2", "The class could not be cached.")
    #ERROR_DS_CANT_REMOVE_ATT_CACHE
    $AMHintsTable.Add("0x800720D3", "The attribute could not be removed from the cache.")
    #ERROR_DS_CANT_REMOVE_CLASS_CACHE
    $AMHintsTable.Add("0x800720D4", "The class could not be removed from the cache.")
    #ERROR_DS_CANT_RETRIEVE_DN
    $AMHintsTable.Add("0x800720D5", "The distinguished name attribute could not be read.")
    #ERROR_DS_MISSING_SUPREF
    $AMHintsTable.Add("0x800720D6", "No superior reference has been configured for the directory service. The directory service is, therefore, unable to issue referrals to objects outside this forest.")
    #ERROR_DS_CANT_RETRIEVE_INSTANCE
    $AMHintsTable.Add("0x800720D7", "The instance type attribute could not be retrieved.")
    #ERROR_DS_CODE_INCONSISTENCY
    $AMHintsTable.Add("0x800720D8", "An internal error has occurred.")
    #ERROR_DS_DATABASE_ERROR
    $AMHintsTable.Add("0x800720D9", "A database error has occurred.")
    #ERROR_DS_GOVERNSID_MISSING
    $AMHintsTable.Add("0x800720DA", "The governsID attribute is missing.")
    #ERROR_DS_MISSING_EXPECTED_ATT
    $AMHintsTable.Add("0x800720DB", "An expected attribute is missing.")
    #ERROR_DS_NCNAME_MISSING_CR_REF
    $AMHintsTable.Add("0x800720DC", "The specified naming context is missing a cross-reference.")
    #ERROR_DS_SECURITY_CHECKING_ERROR
    $AMHintsTable.Add("0x800720DD", "A security checking error has occurred.")
    #ERROR_DS_SCHEMA_NOT_LOADED
    $AMHintsTable.Add("0x800720DE", "The schema is not loaded.")
    #ERROR_DS_SCHEMA_ALLOC_FAILED
    $AMHintsTable.Add("0x800720DF", "Schema allocation failed. Check if the machine is running low on memory.")
    #ERROR_DS_ATT_SCHEMA_REQ_SYNTAX
    $AMHintsTable.Add("0x800720E0", "Failed to obtain the required syntax for the attribute schema.")
    #ERROR_DS_GCVERIFY_ERROR
    $AMHintsTable.Add("0x800720E1", "The GC verification failed. The GC is not available or does not support the operation. Some part of the directory is currently not available.")
    #ERROR_DS_DRA_SCHEMA_MISMATCH
    $AMHintsTable.Add("0x800720E2", "The replication operation failed because of a schema mismatch between the servers involved.")
    #ERROR_DS_CANT_FIND_DSA_OBJ
    $AMHintsTable.Add("0x800720E3", "The DSA object could not be found.")
    #ERROR_DS_CANT_FIND_EXPECTED_NC
    $AMHintsTable.Add("0x800720E4", "The naming context could not be found.")
    #ERROR_DS_CANT_FIND_NC_IN_CACHE
    $AMHintsTable.Add("0x800720E5", "The naming context could not be found in the cache.")
    #ERROR_DS_CANT_RETRIEVE_CHILD
    $AMHintsTable.Add("0x800720E6", "The child object could not be retrieved.")
    #ERROR_DS_SECURITY_ILLEGAL_MODIFY
    $AMHintsTable.Add("0x800720E7", "The modification was not permitted for security reasons.")
    #ERROR_DS_CANT_REPLACE_HIDDEN_REC
    $AMHintsTable.Add("0x800720E8", "The operation cannot replace the hidden record.")
    #ERROR_DS_BAD_HIERARCHY_FILE
    $AMHintsTable.Add("0x800720E9", "The hierarchy file is invalid.")
    #ERROR_DS_BUILD_HIERARCHY_TABLE_FAILED
    $AMHintsTable.Add("0x800720EA", "The attempt to build the hierarchy table failed.")
    #ERROR_DS_CONFIG_PARAM_MISSING
    $AMHintsTable.Add("0x800720EB", "The directory configuration parameter is missing from the registry.")
    #ERROR_DS_COUNTING_AB_INDICES_FAILED
    $AMHintsTable.Add("0x800720EC", "The attempt to count the address book indices failed.")
    #ERROR_DS_HIERARCHY_TABLE_MALLOC_FAILED
    $AMHintsTable.Add("0x800720ED", "The allocation of the hierarchy table failed.")
    #ERROR_DS_INTERNAL_FAILURE
    $AMHintsTable.Add("0x800720EE", "The directory service encountered an internal failure.")
    #ERROR_DS_UNKNOWN_ERROR
    $AMHintsTable.Add("0x800720EF", "The directory service encountered an unknown failure.")
    #ERROR_DS_ROOT_REQUIRES_CLASS_TOP
    $AMHintsTable.Add("0x800720F0", "A root object requires a class of `"top`".")
    #ERROR_DS_REFUSING_FSMO_ROLES
    $AMHintsTable.Add("0x800720F1", "This directory server is shutting down, and cannot take ownership of new floating single-master operation roles.")
    #ERROR_DS_MISSING_FSMO_SETTINGS
    $AMHintsTable.Add("0x800720F2", "The directory service is missing mandatory configuration information and is unable to determine the ownership of floating single-master operation roles.")
    #ERROR_DS_UNABLE_TO_SURRENDER_ROLES
    $AMHintsTable.Add("0x800720F3", "The directory service was unable to transfer ownership of one or more floating single-master operation roles to other servers.")
    #ERROR_DS_DRA_GENERIC
    $AMHintsTable.Add("0x800720F4", "The replication operation failed.")
    #ERROR_DS_DRA_INVALID_PARAMETER
    $AMHintsTable.Add("0x800720F5", "An invalid parameter was specified for this replication operation.")
    #ERROR_DS_DRA_BUSY
    $AMHintsTable.Add("0x800720F6", "The directory service is too busy to complete the replication operation at this time.")
    #ERROR_DS_DRA_BAD_DN
    $AMHintsTable.Add("0x800720F7", "The DN specified for this replication operation is invalid.")
    #ERROR_DS_DRA_BAD_NC
    $AMHintsTable.Add("0x800720F8", "The naming context specified for this replication operation is invalid.")
    #ERROR_DS_DRA_DN_EXISTS
    $AMHintsTable.Add("0x800720F9", "The DN specified for this replication operation already exists.")
    #ERROR_DS_DRA_INTERNAL_ERROR
    $AMHintsTable.Add("0x800720FA", "The replication system encountered an internal error.")
    #ERROR_DS_DRA_INCONSISTENT_DIT
    $AMHintsTable.Add("0x800720FB", "The replication operation encountered a database inconsistency.")
    #ERROR_DS_DRA_CONNECTION_FAILED
    $AMHintsTable.Add("0x800720FC", "The server specified for this replication operation could not be contacted.")
    #ERROR_DS_DRA_BAD_INSTANCE_TYPE
    $AMHintsTable.Add("0x800720FD", "The replication operation encountered an object with an invalid instance type.")
    #ERROR_DS_DRA_OUT_OF_MEM
    $AMHintsTable.Add("0x800720FE", "The replication operation failed to allocate memory.")
    #ERROR_DS_DRA_MAIL_PROBLEM
    $AMHintsTable.Add("0x800720FF", "The replication operation encountered an error with the mail system.")
    #ERROR_DS_DRA_REF_ALREADY_EXISTS
    $AMHintsTable.Add("0x80072100", "The replication reference information for the target server already exists.")
    #ERROR_DS_DRA_REF_NOT_FOUND
    $AMHintsTable.Add("0x80072101", "The replication reference information for the target server does not exist.")
    #ERROR_DS_DRA_OBJ_IS_REP_SOURCE
    $AMHintsTable.Add("0x80072102", "The naming context cannot be removed because it is replicated to another server.")
    #ERROR_DS_DRA_DB_ERROR
    $AMHintsTable.Add("0x80072103", "The replication operation encountered a database error.")
    #ERROR_DS_DRA_NO_REPLICA
    $AMHintsTable.Add("0x80072104", "The naming context is in the process of being removed or is not replicated from the specified server.")
    #ERROR_DS_DRA_ACCESS_DENIED
    $AMHintsTable.Add("0x80072105", "Replication access was denied.")
    #ERROR_DS_DRA_NOT_SUPPORTED
    $AMHintsTable.Add("0x80072106", "The requested operation is not supported by this version of the directory service.")
    #ERROR_DS_DRA_RPC_CANCELLED
    $AMHintsTable.Add("0x80072107", "The replication RPC was canceled.")
    #ERROR_DS_DRA_SOURCE_DISABLED
    $AMHintsTable.Add("0x80072108", "The source server is currently rejecting replication requests.")
    #ERROR_DS_DRA_SINK_DISABLED
    $AMHintsTable.Add("0x80072109", "The destination server is currently rejecting replication requests.")
    #ERROR_DS_DRA_NAME_COLLISION
    $AMHintsTable.Add("0x8007210A", "The replication operation failed due to a collision of object names.")
    #ERROR_DS_DRA_SOURCE_REINSTALLED
    $AMHintsTable.Add("0x8007210B", "The replication source has been reinstalled.")
    #ERROR_DS_DRA_MISSING_PARENT
    $AMHintsTable.Add("0x8007210C", "The replication operation failed because a required parent object is missing.")
    #ERROR_DS_DRA_PREEMPTED
    $AMHintsTable.Add("0x8007210D", "The replication operation was preempted.")
    #ERROR_DS_DRA_ABANDON_SYNC
    $AMHintsTable.Add("0x8007210E", "The replication synchronization attempt was abandoned because of a lack of updates.")
    #ERROR_DS_DRA_SHUTDOWN
    $AMHintsTable.Add("0x8007210F", "The replication operation was terminated because the system is shutting down.")
    #ERROR_DS_DRA_INCOMPATIBLE_PARTIAL_SET
    $AMHintsTable.Add("0x80072110", "A synchronization attempt failed because the destination DC is currently waiting to synchronize new partial attributes from the source. This condition is normal if a recent schema change modified the partial attribute set. The destination partial attribute set is not a subset of the source partial attribute set.")
    #ERROR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA
    $AMHintsTable.Add("0x80072111", "The replication synchronization attempt failed because a master replica attempted to sync from a partial replica.")
    #ERROR_DS_DRA_EXTN_CONNECTION_FAILED
    $AMHintsTable.Add("0x80072112", "The server specified for this replication operation was contacted, but that server was unable to contact an additional server needed to complete the operation.")
    #ERROR_DS_INSTALL_SCHEMA_MISMATCH
    $AMHintsTable.Add("0x80072113", "The version of the directory service schema of the source forest is not compatible with the version of the directory service on this computer.")
    #ERROR_DS_DUP_LINK_ID
    $AMHintsTable.Add("0x80072114", "Schema update failed: An attribute with the same link identifier already exists.")
    #ERROR_DS_NAME_ERROR_RESOLVING
    $AMHintsTable.Add("0x80072115", "Name translation: Generic processing error.")
    #ERROR_DS_NAME_ERROR_NOT_FOUND
    $AMHintsTable.Add("0x80072116", "Name translation: Could not find the name or insufficient right to see name.")
    #ERROR_DS_NAME_ERROR_NOT_UNIQUE
    $AMHintsTable.Add("0x80072117", "Name translation: Input name mapped to more than one output name.")
    #ERROR_DS_NAME_ERROR_NO_MAPPING
    $AMHintsTable.Add("0x80072118", "Name translation: The input name was found but not the associated output format.")
    #ERROR_DS_NAME_ERROR_DOMAIN_ONLY
    $AMHintsTable.Add("0x80072119", "Name translation: Unable to resolve completely, only the domain was found.")
    #ERROR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING
    $AMHintsTable.Add("0x8007211A", "Name translation: Unable to perform purely syntactical mapping at the client without going out to the wire.")
    #ERROR_DS_CONSTRUCTED_ATT_MOD
    $AMHintsTable.Add("0x8007211B", "Modification of a constructed attribute is not allowed.")
    #ERROR_DS_WRONG_OM_OBJ_CLASS
    $AMHintsTable.Add("0x8007211C", "The OM-Object-Class specified is incorrect for an attribute with the specified syntax.")
    #ERROR_DS_DRA_REPL_PENDING
    $AMHintsTable.Add("0x8007211D", "The replication request has been posted; waiting for a reply.")
    #ERROR_DS_DS_REQUIRED
    $AMHintsTable.Add("0x8007211E", "The requested operation requires a directory service, and none was available.")
    #ERROR_DS_INVALID_LDAP_DISPLAY_NAME
    $AMHintsTable.Add("0x8007211F", "The LDAP display name of the class or attribute contains non-ASCII characters.")
    #ERROR_DS_NON_BASE_SEARCH
    $AMHintsTable.Add("0x80072120", "The requested search operation is only supported for base searches.")
    #ERROR_DS_CANT_RETRIEVE_ATTS
    $AMHintsTable.Add("0x80072121", "The search failed to retrieve attributes from the database.")
    #ERROR_DS_BACKLINK_WITHOUT_LINK
    $AMHintsTable.Add("0x80072122", "The schema update operation tried to add a backward link attribute that has no corresponding forward link.")
    #ERROR_DS_EPOCH_MISMATCH
    $AMHintsTable.Add("0x80072123", "The source and destination of a cross-domain move do not agree on the object's epoch number. Either the source or the destination does not have the latest version of the object.")
    #ERROR_DS_SRC_NAME_MISMATCH
    $AMHintsTable.Add("0x80072124", "The source and destination of a cross-domain move do not agree on the object's current name. Either the source or the destination does not have the latest version of the object.")
    #ERROR_DS_SRC_AND_DST_NC_IDENTICAL
    $AMHintsTable.Add("0x80072125", "The source and destination for the cross-domain move operation are identical. The caller should use a local move operation instead of a cross-domain move operation.")
    #ERROR_DS_DST_NC_MISMATCH
    $AMHintsTable.Add("0x80072126", "The source and destination for a cross-domain move do not agree on the naming contexts in the forest. Either the source or the destination does not have the latest version of the Partitions container.")
    #ERROR_DS_NOT_AUTHORITIVE_FOR_DST_NC
    $AMHintsTable.Add("0x80072127", "The destination of a cross-domain move is not authoritative for the destination naming context.")
    #ERROR_DS_SRC_GUID_MISMATCH
    $AMHintsTable.Add("0x80072128", "The source and destination of a cross-domain move do not agree on the identity of the source object. Either the source or the destination does not have the latest version of the source object.")
    #ERROR_DS_CANT_MOVE_DELETED_OBJECT
    $AMHintsTable.Add("0x80072129", "The object being moved across domains is already known to be deleted by the destination server. The source server does not have the latest version of the source object.")
    #ERROR_DS_PDC_OPERATION_IN_PROGRESS
    $AMHintsTable.Add("0x8007212A", "Another operation that requires exclusive access to the PDC FSMO is already in progress.")
    #ERROR_DS_CROSS_DOMAIN_CLEANUP_REQD
    $AMHintsTable.Add("0x8007212B", "A cross-domain move operation failed because two versions of the moved object exist?ne each in the source and destination domains. The destination object needs to be removed to restore the system to a consistent state.")
    #ERROR_DS_ILLEGAL_XDOM_MOVE_OPERATION
    $AMHintsTable.Add("0x8007212C", "This object may not be moved across domain boundaries either because cross-domain moves for this class are not allowed, or the object has some special characteristics, for example, a trust account or a restricted relative identifier (RID), that prevent its move.")
    #ERROR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS
    $AMHintsTable.Add("0x8007212D", "Cannot move objects with memberships across domain boundaries because, once moved, this violates the membership conditions of the account group. Remove the object from any account group memberships and retry.")
    #ERROR_DS_NC_MUST_HAVE_NC_PARENT
    $AMHintsTable.Add("0x8007212E", "A naming context head must be the immediate child of another naming context head, not of an interior node.")
    #ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE
    $AMHintsTable.Add("0x8007212F", "The directory cannot validate the proposed naming context name because it does not hold a replica of the naming context above the proposed naming context. Ensure that the domain naming master role is held by a server that is configured as a GC server, and that the server is up-to-date with its replication partners. (Applies only to Windows 2000 domain naming masters.)")
    #ERROR_DS_DST_DOMAIN_NOT_NATIVE
    $AMHintsTable.Add("0x80072130", "Destination domain must be in native mode.")
    #ERROR_DS_MISSING_INFRASTRUCTURE_CONTAINER
    $AMHintsTable.Add("0x80072131", "The operation cannot be performed because the server does not have an infrastructure container in the domain of interest.")
    #ERROR_DS_CANT_MOVE_ACCOUNT_GROUP
    $AMHintsTable.Add("0x80072132", "Cross-domain moves of nonempty account groups is not allowed.")
    #ERROR_DS_CANT_MOVE_RESOURCE_GROUP
    $AMHintsTable.Add("0x80072133", "Cross-domain moves of nonempty resource groups is not allowed.")
    #ERROR_DS_INVALID_SEARCH_FLAG
    $AMHintsTable.Add("0x80072134", "The search flags for the attribute are invalid. The ambiguous name resolution (ANR) bit is valid only on attributes of Unicode or Teletex strings.")
    #ERROR_DS_NO_TREE_DELETE_ABOVE_NC
    $AMHintsTable.Add("0x80072135", "Tree deletions starting at an object that has an NC head as a descendant are not allowed.")
    #ERROR_DS_COULDNT_LOCK_TREE_FOR_DELETE
    $AMHintsTable.Add("0x80072136", "The directory service failed to lock a tree in preparation for a tree deletion because the tree was in use.")
    #ERROR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE
    $AMHintsTable.Add("0x80072137", "The directory service failed to identify the list of objects to delete while attempting a tree deletion.")
    #ERROR_DS_SAM_INIT_FAILURE
    $AMHintsTable.Add("0x80072138", "SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system and reboot into Directory Services Restore Mode. Check the event log for detailed information.")
    #ERROR_DS_SENSITIVE_GROUP_VIOLATION
    $AMHintsTable.Add("0x80072139", "Only an administrator can modify the membership list of an administrative group.")
    #ERROR_DS_CANT_MOD_PRIMARYGROUPID
    $AMHintsTable.Add("0x8007213A", "Cannot change the primary group ID of a domain controller account.")
    #ERROR_DS_ILLEGAL_BASE_SCHEMA_MOD
    $AMHintsTable.Add("0x8007213B", "An attempt was made to modify the base schema.")
    #ERROR_DS_NONSAFE_SCHEMA_CHANGE
    $AMHintsTable.Add("0x8007213C", "Adding a new mandatory attribute to an existing class, deleting a mandatory attribute from an existing class, or adding an optional attribute to the special class Top that is not a backlink attribute (directly or through inheritance, for example, by adding or deleting an auxiliary class) is not allowed.")
    #ERROR_DS_SCHEMA_UPDATE_DISALLOWED
    $AMHintsTable.Add("0x8007213D", "Schema update is not allowed on this DC because the DC is not the schema FSMO role owner.")
    #ERROR_DS_CANT_CREATE_UNDER_SCHEMA
    $AMHintsTable.Add("0x8007213E", "An object of this class cannot be created under the schema container. You can only create Attribute-Schema and Class-Schema objects under the schema container.")
    #ERROR_DS_INSTALL_NO_SRC_SCH_VERSION
    $AMHintsTable.Add("0x8007213F", "The replica or child install failed to get the objectVersion attribute on the schema container on the source DC. Either the attribute is missing on the schema container or the credentials supplied do not have permission to read it.")
    #ERROR_DS_INSTALL_NO_SCH_VERSION_IN_INIFILE
    $AMHintsTable.Add("0x80072140", "The replica or child install failed to read the objectVersion attribute in the SCHEMA section of the file schema.ini in the System32 directory.")
    #ERROR_DS_INVALID_GROUP_TYPE
    $AMHintsTable.Add("0x80072141", "The specified group type is invalid.")
    #ERROR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN
    $AMHintsTable.Add("0x80072142", "You cannot nest global groups in a mixed domain if the group is security-enabled.")
    #ERROR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN
    $AMHintsTable.Add("0x80072143", "You cannot nest local groups in a mixed domain if the group is security-enabled.")
    #ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER
    $AMHintsTable.Add("0x80072144", "A global group cannot have a local group as a member.")
    #ERROR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER
    $AMHintsTable.Add("0x80072145", "A global group cannot have a universal group as a member.")
    #ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER
    $AMHintsTable.Add("0x80072146", "A universal group cannot have a local group as a member.")
    #ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER
    $AMHintsTable.Add("0x80072147", "A global group cannot have a cross-domain member.")
    #ERROR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER
    $AMHintsTable.Add("0x80072148", "A local group cannot have another cross domain local group as a member.")
    #ERROR_DS_HAVE_PRIMARY_MEMBERS
    $AMHintsTable.Add("0x80072149", "A group with primary members cannot change to a security-disabled group.")
    #ERROR_DS_STRING_SD_CONVERSION_FAILED
    $AMHintsTable.Add("0x8007214A", "The schema cache load failed to convert the string default security descriptor (SD) on a class-schema object.")
    #ERROR_DS_NAMING_MASTER_GC
    $AMHintsTable.Add("0x8007214B", "Only DSAs configured to be GC servers should be allowed to hold the domain naming master FSMO role. (Applies only to Windows 2000 servers.)")
    #ERROR_DS_DNS_LOOKUP_FAILURE
    $AMHintsTable.Add("0x8007214C", "The DSA operation is unable to proceed because of a DNS lookup failure.")
    #ERROR_DS_COULDNT_UPDATE_SPNS
    $AMHintsTable.Add("0x8007214D", "While processing a change to the DNS host name for an object, the SPN values could not be kept in sync.")
    #ERROR_DS_CANT_RETRIEVE_SD
    $AMHintsTable.Add("0x8007214E", "The Security Descriptor attribute could not be read.")
    #ERROR_DS_KEY_NOT_UNIQUE
    $AMHintsTable.Add("0x8007214F", "The object requested was not found, but an object with that key was found.")
    #ERROR_DS_WRONG_LINKED_ATT_SYNTAX
    $AMHintsTable.Add("0x80072150", "The syntax of the linked attribute being added is incorrect. Forward links can only have syntax 2.5.5.1, 2.5.5.7, and 2.5.5.14, and backlinks can only have syntax 2.5.5.1.")
    #ERROR_DS_SAM_NEED_BOOTKEY_PASSWORD
    $AMHintsTable.Add("0x80072151", "SAM needs to get the boot password.")
    #ERROR_DS_SAM_NEED_BOOTKEY_FLOPPY
    $AMHintsTable.Add("0x80072152", "SAM needs to get the boot key from the floppy disk.")
    #ERROR_DS_CANT_START
    $AMHintsTable.Add("0x80072153", "Directory Service cannot start.")
    #ERROR_DS_INIT_FAILURE
    $AMHintsTable.Add("0x80072154", "Directory Services could not start.")
    #ERROR_DS_NO_PKT_PRIVACY_ON_CONNECTION
    $AMHintsTable.Add("0x80072155", "The connection between client and server requires packet privacy or better.")
    #ERROR_DS_SOURCE_DOMAIN_IN_FOREST
    $AMHintsTable.Add("0x80072156", "The source domain may not be in the same forest as the destination.")
    #ERROR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST
    $AMHintsTable.Add("0x80072157", "The destination domain must be in the forest.")
    #ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED
    $AMHintsTable.Add("0x80072158", "The operation requires that destination domain auditing be enabled.")
    #ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN
    $AMHintsTable.Add("0x80072159", "The operation could not locate a DC for the source domain.")
    #ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER
    $AMHintsTable.Add("0x8007215A", "The source object must be a group or user.")
    #ERROR_DS_SRC_SID_EXISTS_IN_FOREST
    $AMHintsTable.Add("0x8007215B", "The source object's SID already exists in the destination forest.")
    #ERROR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH
    $AMHintsTable.Add("0x8007215C", "The source and destination object must be of the same type.")
    #ERROR_SAM_INIT_FAILURE
    $AMHintsTable.Add("0x8007215D", "SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system and reboot into Safe Mode. Check the event log for detailed information.")
    #ERROR_DS_DRA_SCHEMA_INFO_SHIP
    $AMHintsTable.Add("0x8007215E", "Schema information could not be included in the replication request.")
    #ERROR_DS_DRA_SCHEMA_CONFLICT
    $AMHintsTable.Add("0x8007215F", "The replication operation could not be completed due to a schema incompatibility.")
    #ERROR_DS_DRA_EARLIER_SCHEMA_CONFLICT
    $AMHintsTable.Add("0x80072160", "The replication operation could not be completed due to a previous schema incompatibility.")
    #ERROR_DS_DRA_OBJ_NC_MISMATCH
    $AMHintsTable.Add("0x80072161", "The replication update could not be applied because either the source or the destination has not yet received information regarding a recent cross-domain move operation.")
    #ERROR_DS_NC_STILL_HAS_DSAS
    $AMHintsTable.Add("0x80072162", "The requested domain could not be deleted because there exist domain controllers that still host this domain.")
    #ERROR_DS_GC_REQUIRED
    $AMHintsTable.Add("0x80072163", "The requested operation can be performed only on a GC server.")
    #ERROR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY
    $AMHintsTable.Add("0x80072164", "A local group can only be a member of other local groups in the same domain.")
    #ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS
    $AMHintsTable.Add("0x80072165", "Foreign security principals cannot be members of universal groups.")
    #ERROR_DS_CANT_ADD_TO_GC
    $AMHintsTable.Add("0x80072166", "The attribute is not allowed to be replicated to the GC because of security reasons.")
    #ERROR_DS_NO_CHECKPOINT_WITH_PDC
    $AMHintsTable.Add("0x80072167", "The checkpoint with the PDC could not be taken because too many modifications are currently being processed.")
    #ERROR_DS_SOURCE_AUDITING_NOT_ENABLED
    $AMHintsTable.Add("0x80072168", "The operation requires that source domain auditing be enabled.")
    #ERROR_DS_CANT_CREATE_IN_NONDOMAIN_NC
    $AMHintsTable.Add("0x80072169", "Security principal objects can only be created inside domain naming contexts.")
    #ERROR_DS_INVALID_NAME_FOR_SPN
    $AMHintsTable.Add("0x8007216A", "An SPN could not be constructed because the provided host name is not in the necessary format.")
    #ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS
    $AMHintsTable.Add("0x8007216B", "A filter was passed that uses constructed attributes.")
    #ERROR_DS_UNICODEPWD_NOT_IN_QUOTES
    $AMHintsTable.Add("0x8007216C", "The unicodePwd attribute value must be enclosed in quotation marks.")
    #ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED
    $AMHintsTable.Add("0x8007216D", "Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.")
    #ERROR_DS_MUST_BE_RUN_ON_DST_DC
    $AMHintsTable.Add("0x8007216E", "For security reasons, the operation must be run on the destination DC.")
    #ERROR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER
    $AMHintsTable.Add("0x8007216F", "For security reasons, the source DC must be NT4SP4 or greater.")
    #ERROR_DS_CANT_TREE_DELETE_CRITICAL_OBJ
    $AMHintsTable.Add("0x80072170", "Critical directory service system objects cannot be deleted during tree deletion operations. The tree deletion may have been partially performed.")
    #ERROR_DS_INIT_FAILURE_CONSOLE
    $AMHintsTable.Add("0x80072171", "Directory Services could not start because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system. You can use the Recovery Console to further diagnose the system.")
    #ERROR_DS_SAM_INIT_FAILURE_CONSOLE
    $AMHintsTable.Add("0x80072172", "SAM initialization failed because of the following error: %1. Error Status: 0x%2. Click OK to shut down the system. You can use the Recovery Console to further diagnose the system.")
    #ERROR_DS_FOREST_VERSION_TOO_HIGH
    $AMHintsTable.Add("0x80072173", "The version of the operating system installed is incompatible with the current forest functional level. You must upgrade to a new version of the operating system before this server can become a domain controller in this forest.")
    #ERROR_DS_DOMAIN_VERSION_TOO_HIGH
    $AMHintsTable.Add("0x80072174", "The version of the operating system installed is incompatible with the current domain functional level. You must upgrade to a new version of the operating system before this server can become a domain controller in this domain.")
    #ERROR_DS_FOREST_VERSION_TOO_LOW
    $AMHintsTable.Add("0x80072175", "The version of the operating system installed on this server no longer supports the current forest functional level. You must raise the forest functional level before this server can become a domain controller in this forest.")
    #ERROR_DS_DOMAIN_VERSION_TOO_LOW
    $AMHintsTable.Add("0x80072176", "The version of the operating system installed on this server no longer supports the current domain functional level. You must raise the domain functional level before this server can become a domain controller in this domain.")
    #ERROR_DS_INCOMPATIBLE_VERSION
    $AMHintsTable.Add("0x80072177", "The version of the operating system installed on this server is incompatible with the functional level of the domain or forest.")
    #ERROR_DS_LOW_DSA_VERSION
    $AMHintsTable.Add("0x80072178", "The functional level of the domain (or forest) cannot be raised to the requested value because one or more domain controllers in the domain (or forest) are at a lower, incompatible functional level.")
    #ERROR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN
    $AMHintsTable.Add("0x80072179", "The forest functional level cannot be raised to the requested value because one or more domains are still in mixed-domain mode. All domains in the forest must be in native mode for you to raise the forest functional level.")
    #ERROR_DS_NOT_SUPPORTED_SORT_ORDER
    $AMHintsTable.Add("0x8007217A", "The sort order requested is not supported.")
    #ERROR_DS_NAME_NOT_UNIQUE
    $AMHintsTable.Add("0x8007217B", "The requested name already exists as a unique identifier.")
    #ERROR_DS_MACHINE_ACCOUNT_CREATED_PRENT4
    $AMHintsTable.Add("0x8007217C", "The machine account was created before Windows NT 4.0. The account needs to be re-created.")
    #ERROR_DS_OUT_OF_VERSION_STORE
    $AMHintsTable.Add("0x8007217D", "The database is out of version store.")
    #ERROR_DS_INCOMPATIBLE_CONTROLS_USED
    $AMHintsTable.Add("0x8007217E", "Unable to continue operation because multiple conflicting controls were used.")
    #ERROR_DS_NO_REF_DOMAIN
    $AMHintsTable.Add("0x8007217F", "Unable to find a valid security descriptor reference domain for this partition.")
    #ERROR_DS_RESERVED_LINK_ID
    $AMHintsTable.Add("0x80072180", "Schema update failed: The link identifier is reserved.")
    #ERROR_DS_LINK_ID_NOT_AVAILABLE
    $AMHintsTable.Add("0x80072181", "Schema update failed: There are no link identifiers available.")
    #ERROR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER
    $AMHintsTable.Add("0x80072182", "An account group cannot have a universal group as a member.")
    #ERROR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE
    $AMHintsTable.Add("0x80072183", "Rename or move operations on naming context heads or read-only objects are not allowed.")
    #ERROR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC
    $AMHintsTable.Add("0x80072184", "Move operations on objects in the schema naming context are not allowed.")
    #ERROR_DS_MODIFYDN_DISALLOWED_BY_FLAG
    $AMHintsTable.Add("0x80072185", "A system flag has been set on the object that does not allow the object to be moved or renamed.")
    #ERROR_DS_MODIFYDN_WRONG_GRANDPARENT
    $AMHintsTable.Add("0x80072186", "This object is not allowed to change its grandparent container. Moves are not forbidden on this object, but are restricted to sibling containers.")
    #ERROR_DS_NAME_ERROR_TRUST_REFERRAL
    $AMHintsTable.Add("0x80072187", "Unable to resolve completely; a referral to another forest was generated.")
    #ERROR_NOT_SUPPORTED_ON_STANDARD_SERVER
    $AMHintsTable.Add("0x80072188", "The requested action is not supported on a standard server.")
    #ERROR_DS_CANT_ACCESS_REMOTE_PART_OF_AD
    $AMHintsTable.Add("0x80072189", "Could not access a partition of the directory service located on a remote server. Make sure at least one server is running for the partition in question.")
    #ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2
    $AMHintsTable.Add("0x8007218A", "The directory cannot validate the proposed naming context (or partition) name because it does not hold a replica, nor can it contact a replica of the naming context above the proposed naming context. Ensure that the parent naming context is properly registered in the DNS, and at least one replica of this naming context is reachable by the domain naming master.")
    #ERROR_DS_THREAD_LIMIT_EXCEEDED
    $AMHintsTable.Add("0x8007218B", "The thread limit for this request was exceeded.")
    #ERROR_DS_NOT_CLOSEST
    $AMHintsTable.Add("0x8007218C", "The GC server is not in the closest site.")
    #ERROR_DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF
    $AMHintsTable.Add("0x8007218D", "The directory service cannot derive an SPN with which to mutually authenticate the target server because the corresponding server object in the local DS database has no serverReference attribute.")
    #ERROR_DS_SINGLE_USER_MODE_FAILED
    $AMHintsTable.Add("0x8007218E", "The directory service failed to enter single-user mode.")
    #ERROR_DS_NTDSCRIPT_SYNTAX_ERROR
    $AMHintsTable.Add("0x8007218F", "The directory service cannot parse the script because of a syntax error.")
    #ERROR_DS_NTDSCRIPT_PROCESS_ERROR
    $AMHintsTable.Add("0x80072190", "The directory service cannot process the script because of an error.")
    #ERROR_DS_DIFFERENT_REPL_EPOCHS
    $AMHintsTable.Add("0x80072191", "The directory service cannot perform the requested operation because the servers involved are of different replication epochs (which is usually related to a domain rename that is in progress).")
    #ERROR_DS_DRS_EXTENSIONS_CHANGED
    $AMHintsTable.Add("0x80072192", "The directory service binding must be renegotiated due to a change in the server extensions information.")
    #ERROR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR
    $AMHintsTable.Add("0x80072193", "The operation is not allowed on a disabled cross-reference.")
    #ERROR_DS_NO_MSDS_INTID
    $AMHintsTable.Add("0x80072194", "Schema update failed: No values for msDS-IntId are available.")
    #ERROR_DS_DUP_MSDS_INTID
    $AMHintsTable.Add("0x80072195", "Schema update failed: Duplicate msDS-IntId. Retry the operation.")
    #ERROR_DS_EXISTS_IN_RDNATTID
    $AMHintsTable.Add("0x80072196", "Schema deletion failed: Attribute is used in rDNAttID.")
    #ERROR_DS_AUTHORIZATION_FAILED
    $AMHintsTable.Add("0x80072197", "The directory service failed to authorize the request.")
    #ERROR_DS_INVALID_SCRIPT
    $AMHintsTable.Add("0x80072198", "The directory service cannot process the script because it is invalid.")
    #ERROR_DS_REMOTE_CROSSREF_OP_FAILED
    $AMHintsTable.Add("0x80072199", "The remote create cross-reference operation failed on the domain naming master FSMO. The operation's error is in the extended data.")
    #ERROR_DS_CROSS_REF_BUSY
    $AMHintsTable.Add("0x8007219A", "A cross-reference is in use locally with the same name.")
    #ERROR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN
    $AMHintsTable.Add("0x8007219B", "The directory service cannot derive an SPN with which to mutually authenticate the target server because the server's domain has been deleted from the forest.")
    #ERROR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC
    $AMHintsTable.Add("0x8007219C", "Writable NCs prevent this DC from demoting.")
    #ERROR_DS_DUPLICATE_ID_FOUND
    $AMHintsTable.Add("0x8007219D", "The requested object has a nonunique identifier and cannot be retrieved.")
    #ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT
    $AMHintsTable.Add("0x8007219E", "Insufficient attributes were given to create an object. This object may not exist because it may have been deleted and the garbage already collected.")
    #ERROR_DS_GROUP_CONVERSION_ERROR
    $AMHintsTable.Add("0x8007219F", "The group cannot be converted due to attribute restrictions on the requested group type.")
    #ERROR_DS_CANT_MOVE_APP_BASIC_GROUP
    $AMHintsTable.Add("0x800721A0", "Cross-domain moves of nonempty basic application groups is not allowed.")
    #ERROR_DS_CANT_MOVE_APP_QUERY_GROUP
    $AMHintsTable.Add("0x800721A1", "Cross-domain moves of nonempty query-based application groups is not allowed.")
    #ERROR_DS_ROLE_NOT_VERIFIED
    $AMHintsTable.Add("0x800721A2", "The FSMO role ownership could not be verified because its directory partition did not replicate successfully with at least one replication partner.")
    #ERROR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL
    $AMHintsTable.Add("0x800721A3", "The target container for a redirection of a well-known object container cannot already be a special container.")
    #ERROR_DS_DOMAIN_RENAME_IN_PROGRESS
    $AMHintsTable.Add("0x800721A4", "The directory service cannot perform the requested operation because a domain rename operation is in progress.")
    #ERROR_DS_EXISTING_AD_CHILD_NC
    $AMHintsTable.Add("0x800721A5", "The directory service detected a child partition below the requested partition name. The partition hierarchy must be created in a top down method.")
    #ERROR_DS_REPL_LIFETIME_EXCEEDED
    $AMHintsTable.Add("0x800721A6", "The directory service cannot replicate with this server because the time since the last replication with this server has exceeded the tombstone lifetime.")
    #ERROR_DS_DISALLOWED_IN_SYSTEM_CONTAINER
    $AMHintsTable.Add("0x800721A7", "The requested operation is not allowed on an object under the system container.")
    #ERROR_DS_LDAP_SEND_QUEUE_FULL
    $AMHintsTable.Add("0x800721A8", "The LDAP server's network send queue has filled up because the client is not processing the results of its requests fast enough. No more requests will be processed until the client catches up. If the client does not catch up then it will be disconnected.")
    #ERROR_DS_DRA_OUT_SCHEDULE_WINDOW
    $AMHintsTable.Add("0x800721A9", "The scheduled replication did not take place because the system was too busy to execute the request within the schedule window. The replication queue is overloaded. Consider reducing the number of partners or decreasing the scheduled replication frequency.")
    #ERROR_DS_POLICY_NOT_KNOWN
    $AMHintsTable.Add("0x800721AA", "At this time, it cannot be determined if the branch replication policy is available on the hub domain controller. Retry at a later time to account for replication latencies.")
    #ERROR_NO_SITE_SETTINGS_OBJECT
    $AMHintsTable.Add("0x800721AB", "The site settings object for the specified site does not exist.")
    #ERROR_NO_SECRETS
    $AMHintsTable.Add("0x800721AC", "The local account store does not contain secret material for the specified account.")
    #ERROR_NO_WRITABLE_DC_FOUND
    $AMHintsTable.Add("0x800721AD", "Could not find a writable domain controller in the domain.")
    #ERROR_DS_NO_SERVER_OBJECT
    $AMHintsTable.Add("0x800721AE", "The server object for the domain controller does not exist.")
    #ERROR_DS_NO_NTDSA_OBJECT
    $AMHintsTable.Add("0x800721AF", "The NTDS Settings object for the domain controller does not exist.")
    #ERROR_DS_NON_ASQ_SEARCH
    $AMHintsTable.Add("0x800721B0", "The requested search operation is not supported for attribute scoped query (ASQ) searches.")
    #ERROR_DS_AUDIT_FAILURE
    $AMHintsTable.Add("0x800721B1", "A required audit event could not be generated for the operation.")
    #ERROR_DS_INVALID_SEARCH_FLAG_SUBTREE
    $AMHintsTable.Add("0x800721B2", "The search flags for the attribute are invalid. The subtree index bit is valid only on single-valued attributes.")
    #ERROR_DS_INVALID_SEARCH_FLAG_TUPLE
    $AMHintsTable.Add("0x800721B3", "The search flags for the attribute are invalid. The tuple index bit is valid only on attributes of Unicode strings.")
    #DNS_ERROR_RCODE_FORMAT_ERROR
    $AMHintsTable.Add("0x80072329", "DNS server unable to interpret format.")
    #DNS_ERROR_RCODE_SERVER_FAILURE
    $AMHintsTable.Add("0x8007232A", "DNS server failure.")
    #DNS_ERROR_RCODE_NAME_ERROR
    $AMHintsTable.Add("0x8007232B", "DNS name does not exist.")
    #DNS_ERROR_RCODE_NOT_IMPLEMENTED
    $AMHintsTable.Add("0x8007232C", "DNS request not supported by name server.")
    #DNS_ERROR_RCODE_REFUSED
    $AMHintsTable.Add("0x8007232D", "DNS operation refused.")
    #DNS_ERROR_RCODE_YXDOMAIN
    $AMHintsTable.Add("0x8007232E", "DNS name that should not exist, does exist.")
    #DNS_ERROR_RCODE_YXRRSET
    $AMHintsTable.Add("0x8007232F", "DNS resource record (RR) set that should not exist, does exist.")
    #DNS_ERROR_RCODE_NXRRSET
    $AMHintsTable.Add("0x80072330", "DNS RR set that should to exist, does not exist.")
    #DNS_ERROR_RCODE_NOTAUTH
    $AMHintsTable.Add("0x80072331", "DNS server not authoritative for zone.")
    #DNS_ERROR_RCODE_NOTZONE
    $AMHintsTable.Add("0x80072332", "DNS name in update or prereq is not in zone.")
    #DNS_ERROR_RCODE_BADSIG
    $AMHintsTable.Add("0x80072338", "DNS signature failed to verify.")
    #DNS_ERROR_RCODE_BADKEY
    $AMHintsTable.Add("0x80072339", "DNS bad key.")
    #DNS_ERROR_RCODE_BADTIME
    $AMHintsTable.Add("0x8007233A", "DNS signature validity expired.")
    #DNS_INFO_NO_RECORDS
    $AMHintsTable.Add("0x8007251D", "No records found for given DNS query.")
    #DNS_ERROR_BAD_PACKET
    $AMHintsTable.Add("0x8007251E", "Bad DNS packet.")
    #DNS_ERROR_NO_PACKET
    $AMHintsTable.Add("0x8007251F", "No DNS packet.")
    #DNS_ERROR_RCODE
    $AMHintsTable.Add("0x80072520", "DNS error, check rcode.")
    #DNS_ERROR_UNSECURE_PACKET
    $AMHintsTable.Add("0x80072521", "Unsecured DNS packet.")
    #DNS_ERROR_INVALID_TYPE
    $AMHintsTable.Add("0x8007254F", "Invalid DNS type.")
    #DNS_ERROR_INVALID_IP_ADDRESS
    $AMHintsTable.Add("0x80072550", "Invalid IP address.")
    #DNS_ERROR_INVALID_PROPERTY
    $AMHintsTable.Add("0x80072551", "Invalid property.")
    #DNS_ERROR_TRY_AGAIN_LATER
    $AMHintsTable.Add("0x80072552", "Try DNS operation again later.")
    #DNS_ERROR_NOT_UNIQUE
    $AMHintsTable.Add("0x80072553", "Record for given name and type is not unique.")
    #DNS_ERROR_NON_RFC_NAME
    $AMHintsTable.Add("0x80072554", "DNS name does not comply with RFC specifications.")
    #DNS_STATUS_FQDN
    $AMHintsTable.Add("0x80072555", "DNS name is a fully qualified DNS name.")
    #DNS_STATUS_DOTTED_NAME
    $AMHintsTable.Add("0x80072556", "DNS name is dotted (multilabel).")
    #DNS_STATUS_SINGLE_PART_NAME
    $AMHintsTable.Add("0x80072557", "DNS name is a single-part name.")
    #DNS_ERROR_INVALID_NAME_CHAR
    $AMHintsTable.Add("0x80072558", "DNS name contains an invalid character.")
    #DNS_ERROR_NUMERIC_NAME
    $AMHintsTable.Add("0x80072559", "DNS name is entirely numeric.")
    #DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER
    $AMHintsTable.Add("0x8007255A", "The operation requested is not permitted on a DNS root server.")
    #DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION
    $AMHintsTable.Add("0x8007255B", "The record could not be created because this part of the DNS namespace has been delegated to another server.")
    #DNS_ERROR_CANNOT_FIND_ROOT_HINTS
    $AMHintsTable.Add("0x8007255C", "The DNS server could not find a set of root hints.")
    #DNS_ERROR_INCONSISTENT_ROOT_HINTS
    $AMHintsTable.Add("0x8007255D", "The DNS server found root hints but they were not consistent across all adapters.")
    #DNS_ERROR_DWORD_VALUE_TOO_SMALL
    $AMHintsTable.Add("0x8007255E", "The specified value is too small for this parameter.")
    #DNS_ERROR_DWORD_VALUE_TOO_LARGE
    $AMHintsTable.Add("0x8007255F", "The specified value is too large for this parameter.")
    #DNS_ERROR_BACKGROUND_LOADING
    $AMHintsTable.Add("0x80072560", "This operation is not allowed while the DNS server is loading zones in the background. Try again later.")
    #DNS_ERROR_NOT_ALLOWED_ON_RODC
    $AMHintsTable.Add("0x80072561", "The operation requested is not permitted on against a DNS server running on a read-only DC.")
    #DNS_ERROR_ZONE_DOES_NOT_EXIST
    $AMHintsTable.Add("0x80072581", "DNS zone does not exist.")
    #DNS_ERROR_NO_ZONE_INFO
    $AMHintsTable.Add("0x80072582", "DNS zone information not available.")
    #DNS_ERROR_INVALID_ZONE_OPERATION
    $AMHintsTable.Add("0x80072583", "Invalid operation for DNS zone.")
    #DNS_ERROR_ZONE_CONFIGURATION_ERROR
    $AMHintsTable.Add("0x80072584", "Invalid DNS zone configuration.")
    #DNS_ERROR_ZONE_HAS_NO_SOA_RECORD
    $AMHintsTable.Add("0x80072585", "DNS zone has no start of authority (SOA) record.")
    #DNS_ERROR_ZONE_HAS_NO_NS_RECORDS
    $AMHintsTable.Add("0x80072586", "DNS zone has no Name Server (NS) record.")
    #DNS_ERROR_ZONE_LOCKED
    $AMHintsTable.Add("0x80072587", "DNS zone is locked.")
    #DNS_ERROR_ZONE_CREATION_FAILED
    $AMHintsTable.Add("0x80072588", "DNS zone creation failed.")
    #DNS_ERROR_ZONE_ALREADY_EXISTS
    $AMHintsTable.Add("0x80072589", "DNS zone already exists.")
    #DNS_ERROR_AUTOZONE_ALREADY_EXISTS
    $AMHintsTable.Add("0x8007258A", "DNS automatic zone already exists.")
    #DNS_ERROR_INVALID_ZONE_TYPE
    $AMHintsTable.Add("0x8007258B", "Invalid DNS zone type.")
    #DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP
    $AMHintsTable.Add("0x8007258C", "Secondary DNS zone requires master IP address.")
    #DNS_ERROR_ZONE_NOT_SECONDARY
    $AMHintsTable.Add("0x8007258D", "DNS zone not secondary.")
    #DNS_ERROR_NEED_SECONDARY_ADDRESSES
    $AMHintsTable.Add("0x8007258E", "Need secondary IP address.")
    #DNS_ERROR_WINS_INIT_FAILED
    $AMHintsTable.Add("0x8007258F", "WINS initialization failed.")
    #DNS_ERROR_NEED_WINS_SERVERS
    $AMHintsTable.Add("0x80072590", "Need WINS servers.")
    #DNS_ERROR_NBSTAT_INIT_FAILED
    $AMHintsTable.Add("0x80072591", "NBTSTAT initialization call failed.")
    #DNS_ERROR_SOA_DELETE_INVALID
    $AMHintsTable.Add("0x80072592", "Invalid delete of SOA.")
    #DNS_ERROR_FORWARDER_ALREADY_EXISTS
    $AMHintsTable.Add("0x80072593", "A conditional forwarding zone already exists for that name.")
    #DNS_ERROR_ZONE_REQUIRES_MASTER_IP
    $AMHintsTable.Add("0x80072594", "This zone must be configured with one or more master DNS server IP addresses.")
    #DNS_ERROR_ZONE_IS_SHUTDOWN
    $AMHintsTable.Add("0x80072595", "The operation cannot be performed because this zone is shut down.")
    #DNS_ERROR_PRIMARY_REQUIRES_DATAFILE
    $AMHintsTable.Add("0x800725B3", "The primary DNS zone requires a data file.")
    #DNS_ERROR_INVALID_DATAFILE_NAME
    $AMHintsTable.Add("0x800725B4", "Invalid data file name for the DNS zone.")
    #DNS_ERROR_DATAFILE_OPEN_FAILURE
    $AMHintsTable.Add("0x800725B5", "Failed to open the data file for the DNS zone.")
    #DNS_ERROR_FILE_WRITEBACK_FAILED
    $AMHintsTable.Add("0x800725B6", "Failed to write the data file for the DNS zone.")
    #DNS_ERROR_DATAFILE_PARSING
    $AMHintsTable.Add("0x800725B7", "Failure while reading datafile for DNS zone.")
    #DNS_ERROR_RECORD_DOES_NOT_EXIST
    $AMHintsTable.Add("0x800725E5", "DNS record does not exist.")
    #DNS_ERROR_RECORD_FORMAT
    $AMHintsTable.Add("0x800725E6", "DNS record format error.")
    #DNS_ERROR_NODE_CREATION_FAILED
    $AMHintsTable.Add("0x800725E7", "Node creation failure in DNS.")
    #DNS_ERROR_UNKNOWN_RECORD_TYPE
    $AMHintsTable.Add("0x800725E8", "Unknown DNS record type.")
    #DNS_ERROR_RECORD_TIMED_OUT
    $AMHintsTable.Add("0x800725E9", "DNS record timed out.")
    #DNS_ERROR_NAME_NOT_IN_ZONE
    $AMHintsTable.Add("0x800725EA", "Name not in DNS zone.")
    #DNS_ERROR_CNAME_LOOP
    $AMHintsTable.Add("0x800725EB", "CNAME loop detected.")
    #DNS_ERROR_NODE_IS_CNAME
    $AMHintsTable.Add("0x800725EC", "Node is a CNAME DNS record.")
    #DNS_ERROR_CNAME_COLLISION
    $AMHintsTable.Add("0x800725ED", "A CNAME record already exists for the given name.")
    #DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT
    $AMHintsTable.Add("0x800725EE", "Record is only at DNS zone root.")
    #DNS_ERROR_RECORD_ALREADY_EXISTS
    $AMHintsTable.Add("0x800725EF", "DNS record already exists.")
    #DNS_ERROR_SECONDARY_DATA
    $AMHintsTable.Add("0x800725F0", "Secondary DNS zone data error.")
    #DNS_ERROR_NO_CREATE_CACHE_DATA
    $AMHintsTable.Add("0x800725F1", "Could not create DNS cache data.")
    #DNS_ERROR_NAME_DOES_NOT_EXIST
    $AMHintsTable.Add("0x800725F2", "DNS name does not exist.")
    #DNS_WARNING_PTR_CREATE_FAILED
    $AMHintsTable.Add("0x800725F3", "Could not create pointer (PTR) record.")
    #DNS_WARNING_DOMAIN_UNDELETED
    $AMHintsTable.Add("0x800725F4", "DNS domain was undeleted.")
    #DNS_ERROR_DS_UNAVAILABLE
    $AMHintsTable.Add("0x800725F5", "The directory service is unavailable.")
    #DNS_ERROR_DS_ZONE_ALREADY_EXISTS
    $AMHintsTable.Add("0x800725F6", "DNS zone already exists in the directory service.")
    #DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE
    $AMHintsTable.Add("0x800725F7", "DNS server not creating or reading the boot file for the directory service integrated DNS zone.")
    #DNS_INFO_AXFR_COMPLETE
    $AMHintsTable.Add("0x80072617", "DNS AXFR (zone transfer) complete.")
    #DNS_ERROR_AXFR
    $AMHintsTable.Add("0x80072618", "DNS zone transfer failed.")
    #DNS_INFO_ADDED_LOCAL_WINS
    $AMHintsTable.Add("0x80072619", "Added local WINS server.")
    #DNS_STATUS_CONTINUE_NEEDED
    $AMHintsTable.Add("0x80072649", "Secure update call needs to continue update request.")
    #DNS_ERROR_NO_TCPIP
    $AMHintsTable.Add("0x8007267B", "TCP/IP network protocol not installed.")
    #DNS_ERROR_NO_DNS_SERVERS
    $AMHintsTable.Add("0x8007267C", "No DNS servers configured for local system.")
    #DNS_ERROR_DP_DOES_NOT_EXIST
    $AMHintsTable.Add("0x800726AD", "The specified directory partition does not exist.")
    #DNS_ERROR_DP_ALREADY_EXISTS
    $AMHintsTable.Add("0x800726AE", "The specified directory partition already exists.")
    #DNS_ERROR_DP_NOT_ENLISTED
    $AMHintsTable.Add("0x800726AF", "This DNS server is not enlisted in the specified directory partition.")
    #DNS_ERROR_DP_ALREADY_ENLISTED
    $AMHintsTable.Add("0x800726B0", "This DNS server is already enlisted in the specified directory partition.")
    #DNS_ERROR_DP_NOT_AVAILABLE
    $AMHintsTable.Add("0x800726B1", "The directory partition is not available at this time. Wait a few minutes and try again.")
    #DNS_ERROR_DP_FSMO_ERROR
    $AMHintsTable.Add("0x800726B2", "The application directory partition operation failed. The domain controller holding the domain naming master role is down or unable to service the request or is not running Windows Server 2003.")
    #WSAEINTR
    $AMHintsTable.Add("0x80072714", "A blocking operation was interrupted by a call to WSACancelBlockingCall.")
    #WSAEBADF
    $AMHintsTable.Add("0x80072719", "The file handle supplied is not valid.")
    #WSAEACCES
    $AMHintsTable.Add("0x8007271D", "An attempt was made to access a socket in a way forbidden by its access permissions.")
    #WSAEFAULT
    $AMHintsTable.Add("0x8007271E", "The system detected an invalid pointer address in attempting to use a pointer argument in a call.")
    #WSAEINVAL
    $AMHintsTable.Add("0x80072726", "An invalid argument was supplied.")
    #WSAEMFILE
    $AMHintsTable.Add("0x80072728", "Too many open sockets.")
    #WSAEWOULDBLOCK
    $AMHintsTable.Add("0x80072733", "A nonblocking socket operation could not be completed immediately.")
    #WSAEINPROGRESS
    $AMHintsTable.Add("0x80072734", "A blocking operation is currently executing.")
    #WSAEALREADY
    $AMHintsTable.Add("0x80072735", "An operation was attempted on a nonblocking socket that already had an operation in progress.")
    #WSAENOTSOCK
    $AMHintsTable.Add("0x80072736", "An operation was attempted on something that is not a socket.")
    #WSAEDESTADDRREQ
    $AMHintsTable.Add("0x80072737", "A required address was omitted from an operation on a socket.")
    #WSAEMSGSIZE
    $AMHintsTable.Add("0x80072738", "A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself.")
    #WSAEPROTOTYPE
    $AMHintsTable.Add("0x80072739", "A protocol was specified in the socket function call that does not support the semantics of the socket type requested.")
    #WSAENOPROTOOPT
    $AMHintsTable.Add("0x8007273A", "An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call.")
    #WSAEPROTONOSUPPORT
    $AMHintsTable.Add("0x8007273B", "The requested protocol has not been configured into the system, or no implementation for it exists.")
    #WSAESOCKTNOSUPPORT
    $AMHintsTable.Add("0x8007273C", "The support for the specified socket type does not exist in this address family.")
    #WSAEOPNOTSUPP
    $AMHintsTable.Add("0x8007273D", "The attempted operation is not supported for the type of object referenced.")
    #WSAEPFNOSUPPORT
    $AMHintsTable.Add("0x8007273E", "The protocol family has not been configured into the system or no implementation for it exists.")
    #WSAEAFNOSUPPORT
    $AMHintsTable.Add("0x8007273F", "An address incompatible with the requested protocol was used.")
    #WSAEADDRINUSE
    $AMHintsTable.Add("0x80072740", "Only one usage of each socket address (protocol/network address/port) is normally permitted.")
    #WSAEADDRNOTAVAIL
    $AMHintsTable.Add("0x80072741", "The requested address is not valid in its context.")
    #WSAENETDOWN
    $AMHintsTable.Add("0x80072742", "A socket operation encountered a dead network.")
    #WSAENETUNREACH
    $AMHintsTable.Add("0x80072743", "A socket operation was attempted to an unreachable network.")
    #WSAENETRESET
    $AMHintsTable.Add("0x80072744", "The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress.")
    #WSAECONNABORTED
    $AMHintsTable.Add("0x80072745", "An established connection was aborted by the software in your host machine.")
    #WSAECONNRESET
    $AMHintsTable.Add("0x80072746", "An existing connection was forcibly closed by the remote host.")
    #WSAENOBUFS
    $AMHintsTable.Add("0x80072747", "An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full.")
    #WSAEISCONN
    $AMHintsTable.Add("0x80072748", "A connect request was made on an already connected socket.")
    #WSAENOTCONN
    $AMHintsTable.Add("0x80072749", "A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied.")
    #WSAESHUTDOWN
    $AMHintsTable.Add("0x8007274A", "A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.")
    #WSAETOOMANYREFS
    $AMHintsTable.Add("0x8007274B", "Too many references to a kernel object.")
    #WSAETIMEDOUT
    $AMHintsTable.Add("0x8007274C", "A connection attempt failed because the connected party did not properly respond after a period of time, or the established connection failed because the connected host failed to respond.")
    #WSAECONNREFUSED
    $AMHintsTable.Add("0x8007274D", "No connection could be made because the target machine actively refused it.")
    #WSAELOOP
    $AMHintsTable.Add("0x8007274E", "Cannot translate name.")
    #WSAENAMETOOLONG
    $AMHintsTable.Add("0x8007274F", "Name or name component was too long.")
    #WSAEHOSTDOWN
    $AMHintsTable.Add("0x80072750", "A socket operation failed because the destination host was down.")
    #WSAEHOSTUNREACH
    $AMHintsTable.Add("0x80072751", "A socket operation was attempted to an unreachable host.")
    #WSAENOTEMPTY
    $AMHintsTable.Add("0x80072752", "Cannot remove a directory that is not empty.")
    #WSAEPROCLIM
    $AMHintsTable.Add("0x80072753", "A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously.")
    #WSAEUSERS
    $AMHintsTable.Add("0x80072754", "Ran out of quota.")
    #WSAEDQUOT
    $AMHintsTable.Add("0x80072755", "Ran out of disk quota.")
    #WSAESTALE
    $AMHintsTable.Add("0x80072756", "File handle reference is no longer available.")
    #WSAEREMOTE
    $AMHintsTable.Add("0x80072757", "Item is not available locally.")
    #WSASYSNOTREADY
    $AMHintsTable.Add("0x8007276B", "WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable.")
    #WSAVERNOTSUPPORTED
    $AMHintsTable.Add("0x8007276C", "The Windows Sockets version requested is not supported.")
    #WSANOTINITIALISED
    $AMHintsTable.Add("0x8007276D", "Either the application has not called WSAStartup, or WSAStartup failed.")
    #WSAEDISCON
    $AMHintsTable.Add("0x80072775", "Returned by WSARecv or WSARecvFrom to indicate that the remote party has initiated a graceful shutdown sequence.")
    #WSAENOMORE
    $AMHintsTable.Add("0x80072776", "No more results can be returned by WSALookupServiceNext.")
    #WSAECANCELLED
    $AMHintsTable.Add("0x80072777", "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.")
    #WSAEINVALIDPROCTABLE
    $AMHintsTable.Add("0x80072778", "The procedure call table is invalid.")
    #WSAEINVALIDPROVIDER
    $AMHintsTable.Add("0x80072779", "The requested service provider is invalid.")
    #WSAEPROVIDERFAILEDINIT
    $AMHintsTable.Add("0x8007277A", "The requested service provider could not be loaded or initialized.")
    #WSASYSCALLFAILURE
    $AMHintsTable.Add("0x8007277B", "A system call that should never fail has failed.")
    #WSASERVICE_NOT_FOUND
    $AMHintsTable.Add("0x8007277C", "No such service is known. The service cannot be found in the specified namespace.")
    #WSATYPE_NOT_FOUND
    $AMHintsTable.Add("0x8007277D", "The specified class was not found.")
    #WSA_E_NO_MORE
    $AMHintsTable.Add("0x8007277E", "No more results can be returned by WSALookupServiceNext.")
    #WSA_E_CANCELLED
    $AMHintsTable.Add("0x8007277F", "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.")
    #WSAEREFUSED
    $AMHintsTable.Add("0x80072780", "A database query failed because it was actively refused.")
    #WSAHOST_NOT_FOUND
    $AMHintsTable.Add("0x80072AF9", "No such host is known.")
    #WSATRY_AGAIN
    $AMHintsTable.Add("0x80072AFA", "This is usually a temporary error during host name resolution and means that the local server did not receive a response from an authoritative server.")
    #WSANO_RECOVERY
    $AMHintsTable.Add("0x80072AFB", "A nonrecoverable error occurred during a database lookup.")
    #WSANO_DATA
    $AMHintsTable.Add("0x80072AFC", "The requested name is valid, but no data of the requested type was found.")
    #WSA_QOS_RECEIVERS
    $AMHintsTable.Add("0x80072AFD", "At least one reserve has arrived.")
    #WSA_QOS_SENDERS
    $AMHintsTable.Add("0x80072AFE", "At least one path has arrived.")
    #WSA_QOS_NO_SENDERS
    $AMHintsTable.Add("0x80072AFF", "There are no senders.")
    #WSA_QOS_NO_RECEIVERS
    $AMHintsTable.Add("0x80072B00", "There are no receivers.")
    #WSA_QOS_REQUEST_CONFIRMED
    $AMHintsTable.Add("0x80072B01", "Reserve has been confirmed.")
    #WSA_QOS_ADMISSION_FAILURE
    $AMHintsTable.Add("0x80072B02", "Error due to lack of resources.")
    #WSA_QOS_POLICY_FAILURE
    $AMHintsTable.Add("0x80072B03", "Rejected for administrative reasons?ad credentials.")
    #WSA_QOS_BAD_STYLE
    $AMHintsTable.Add("0x80072B04", "Unknown or conflicting style.")
    #WSA_QOS_BAD_OBJECT
    $AMHintsTable.Add("0x80072B05", "There is a problem with some part of the filterspec or provider-specific buffer in general.")
    #WSA_QOS_TRAFFIC_CTRL_ERROR
    $AMHintsTable.Add("0x80072B06", "There is a problem with some part of the flowspec.")
    #WSA_QOS_GENERIC_ERROR
    $AMHintsTable.Add("0x80072B07", "General quality of serve (QOS) error.")
    #WSA_QOS_ESERVICETYPE
    $AMHintsTable.Add("0x80072B08", "An invalid or unrecognized service type was found in the flowspec.")
    #WSA_QOS_EFLOWSPEC
    $AMHintsTable.Add("0x80072B09", "An invalid or inconsistent flowspec was found in the QOS structure.")
    #WSA_QOS_EPROVSPECBUF
    $AMHintsTable.Add("0x80072B0A", "Invalid QOS provider-specific buffer.")
    #WSA_QOS_EFILTERSTYLE
    $AMHintsTable.Add("0x80072B0B", "An invalid QOS filter style was used.")
    #WSA_QOS_EFILTERTYPE
    $AMHintsTable.Add("0x80072B0C", "An invalid QOS filter type was used.")
    #WSA_QOS_EFILTERCOUNT
    $AMHintsTable.Add("0x80072B0D", "An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR.")
    #WSA_QOS_EOBJLENGTH
    $AMHintsTable.Add("0x80072B0E", "An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer.")
    #WSA_QOS_EFLOWCOUNT
    $AMHintsTable.Add("0x80072B0F", "An incorrect number of flow descriptors was specified in the QOS structure.")
    #WSA_QOS_EUNKOWNPSOBJ
    $AMHintsTable.Add("0x80072B10", "An unrecognized object was found in the QOS provider-specific buffer.")
    #WSA_QOS_EPOLICYOBJ
    $AMHintsTable.Add("0x80072B11", "An invalid policy object was found in the QOS provider-specific buffer.")
    #WSA_QOS_EFLOWDESC
    $AMHintsTable.Add("0x80072B12", "An invalid QOS flow descriptor was found in the flow descriptor list.")
    #WSA_QOS_EPSFLOWSPEC
    $AMHintsTable.Add("0x80072B13", "An invalid or inconsistent flowspec was found in the QOS provider-specific buffer.")
    #WSA_QOS_EPSFILTERSPEC
    $AMHintsTable.Add("0x80072B14", "An invalid FILTERSPEC was found in the QOS provider-specific buffer.")
    #WSA_QOS_ESDMODEOBJ
    $AMHintsTable.Add("0x80072B15", "An invalid shape discard mode object was found in the QOS provider-specific buffer.")
    #WSA_QOS_ESHAPERATEOBJ
    $AMHintsTable.Add("0x80072B16", "An invalid shaping rate object was found in the QOS provider-specific buffer.")
    #WSA_QOS_RESERVED_PETYPE
    $AMHintsTable.Add("0x80072B17", "A reserved policy element was found in the QOS provider-specific buffer.")
    #ERROR_IPSEC_QM_POLICY_EXISTS
    $AMHintsTable.Add("0x800732C8", "The specified quick mode policy already exists.")
    #ERROR_IPSEC_QM_POLICY_NOT_FOUND
    $AMHintsTable.Add("0x800732C9", "The specified quick mode policy was not found.")
    #ERROR_IPSEC_QM_POLICY_IN_USE
    $AMHintsTable.Add("0x800732CA", "The specified quick mode policy is being used.")
    #ERROR_IPSEC_MM_POLICY_EXISTS
    $AMHintsTable.Add("0x800732CB", "The specified main mode policy already exists.")
    #ERROR_IPSEC_MM_POLICY_NOT_FOUND
    $AMHintsTable.Add("0x800732CC", "The specified main mode policy was not found.")
    #ERROR_IPSEC_MM_POLICY_IN_USE
    $AMHintsTable.Add("0x800732CD", "The specified main mode policy is being used.")
    #ERROR_IPSEC_MM_FILTER_EXISTS
    $AMHintsTable.Add("0x800732CE", "The specified main mode filter already exists.")
    #ERROR_IPSEC_MM_FILTER_NOT_FOUND
    $AMHintsTable.Add("0x800732CF", "The specified main mode filter was not found.")
    #ERROR_IPSEC_TRANSPORT_FILTER_EXISTS
    $AMHintsTable.Add("0x800732D0", "The specified transport mode filter already exists.")
    #ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND
    $AMHintsTable.Add("0x800732D1", "The specified transport mode filter does not exist.")
    #ERROR_IPSEC_MM_AUTH_EXISTS
    $AMHintsTable.Add("0x800732D2", "The specified main mode authentication list exists.")
    #ERROR_IPSEC_MM_AUTH_NOT_FOUND
    $AMHintsTable.Add("0x800732D3", "The specified main mode authentication list was not found.")
    #ERROR_IPSEC_MM_AUTH_IN_USE
    $AMHintsTable.Add("0x800732D4", "The specified main mode authentication list is being used.")
    #ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND
    $AMHintsTable.Add("0x800732D5", "The specified default main mode policy was not found.")
    #ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND
    $AMHintsTable.Add("0x800732D6", "The specified default main mode authentication list was not found.")
    #ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND
    $AMHintsTable.Add("0x800732D7", "The specified default quick mode policy was not found.")
    #ERROR_IPSEC_TUNNEL_FILTER_EXISTS
    $AMHintsTable.Add("0x800732D8", "The specified tunnel mode filter exists.")
    #ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND
    $AMHintsTable.Add("0x800732D9", "The specified tunnel mode filter was not found.")
    #ERROR_IPSEC_MM_FILTER_PENDING_DELETION
    $AMHintsTable.Add("0x800732DA", "The main mode filter is pending deletion.")
    #ERROR_IPSEC_TRANSPORT_FILTER_ENDING_DELETION
    $AMHintsTable.Add("0x800732DB", "The transport filter is pending deletion.")
    #ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION
    $AMHintsTable.Add("0x800732DC", "The tunnel filter is pending deletion.")
    #ERROR_IPSEC_MM_POLICY_PENDING_ELETION
    $AMHintsTable.Add("0x800732DD", "The main mode policy is pending deletion.")
    #ERROR_IPSEC_MM_AUTH_PENDING_DELETION
    $AMHintsTable.Add("0x800732DE", "The main mode authentication bundle is pending deletion.")
    #ERROR_IPSEC_QM_POLICY_PENDING_DELETION
    $AMHintsTable.Add("0x800732DF", "The quick mode policy is pending deletion.")
    #WARNING_IPSEC_MM_POLICY_PRUNED
    $AMHintsTable.Add("0x800732E0", "The main mode policy was successfully added, but some of the requested offers are not supported.")
    #WARNING_IPSEC_QM_POLICY_PRUNED
    $AMHintsTable.Add("0x800732E1", "The quick mode policy was successfully added, but some of the requested offers are not supported.")
    #ERROR_IPSEC_IKE_NEG_STATUS_BEGIN
    $AMHintsTable.Add("0x800735E8", "Starts the list of frequencies of various IKE Win32 error codes encountered during negotiations.")
    #ERROR_IPSEC_IKE_AUTH_FAIL
    $AMHintsTable.Add("0x800735E9", "The IKE authentication credentials are unacceptable.")
    #ERROR_IPSEC_IKE_ATTRIB_FAIL
    $AMHintsTable.Add("0x800735EA", "The IKE security attributes are unacceptable.")
    #ERROR_IPSEC_IKE_NEGOTIATION_PENDING
    $AMHintsTable.Add("0x800735EB", "The IKE negotiation is in progress.")
    #ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR
    $AMHintsTable.Add("0x800735EC", "General processing error.")
    #ERROR_IPSEC_IKE_TIMED_OUT
    $AMHintsTable.Add("0x800735ED", "Negotiation timed out.")
    #ERROR_IPSEC_IKE_NO_CERT
    $AMHintsTable.Add("0x800735EE", "The IKE failed to find a valid machine certificate. Contact your network security administrator about installing a valid certificate in the appropriate certificate store.")
    #ERROR_IPSEC_IKE_SA_DELETED
    $AMHintsTable.Add("0x800735EF", "The IKE security association (SA) was deleted by a peer before it was completely established.")
    #ERROR_IPSEC_IKE_SA_REAPED
    $AMHintsTable.Add("0x800735F0", "The IKE SA was deleted before it was completely established.")
    #ERROR_IPSEC_IKE_MM_ACQUIRE_DROP
    $AMHintsTable.Add("0x800735F1", "The negotiation request sat in the queue too long.")
    #ERROR_IPSEC_IKE_QM_ACQUIRE_DROP
    $AMHintsTable.Add("0x800735F2", "The negotiation request sat in the queue too long.")
    #ERROR_IPSEC_IKE_QUEUE_DROP_MM
    $AMHintsTable.Add("0x800735F3", "The negotiation request sat in the queue too long.")
    #ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM
    $AMHintsTable.Add("0x800735F4", "The negotiation request sat in the queue too long.")
    #ERROR_IPSEC_IKE_DROP_NO_RESPONSE
    $AMHintsTable.Add("0x800735F5", "There was no response from a peer.")
    #ERROR_IPSEC_IKE_MM_DELAY_DROP
    $AMHintsTable.Add("0x800735F6", "The negotiation took too long.")
    #ERROR_IPSEC_IKE_QM_DELAY_DROP
    $AMHintsTable.Add("0x800735F7", "The negotiation took too long.")
    #ERROR_IPSEC_IKE_ERROR
    $AMHintsTable.Add("0x800735F8", "An unknown error occurred.")
    #ERROR_IPSEC_IKE_CRL_FAILED
    $AMHintsTable.Add("0x800735F9", "The certificate revocation check failed.")
    #ERROR_IPSEC_IKE_INVALID_KEY_USAGE
    $AMHintsTable.Add("0x800735FA", "Invalid certificate key usage.")
    #ERROR_IPSEC_IKE_INVALID_CERT_TYPE
    $AMHintsTable.Add("0x800735FB", "Invalid certificate type.")
    #ERROR_IPSEC_IKE_NO_PRIVATE_KEY
    $AMHintsTable.Add("0x800735FC", "The IKE negotiation failed because the machine certificate used does not have a private key. IPsec certificates require a private key. Contact your network security administrator about a certificate that has a private key.")
    #ERROR_IPSEC_IKE_DH_FAIL
    $AMHintsTable.Add("0x800735FE", "There was a failure in the Diffie-Hellman computation.")
    #ERROR_IPSEC_IKE_INVALID_HEADER
    $AMHintsTable.Add("0x80073600", "Invalid header.")
    #ERROR_IPSEC_IKE_NO_POLICY
    $AMHintsTable.Add("0x80073601", "No policy configured.")
    #ERROR_IPSEC_IKE_INVALID_SIGNATURE
    $AMHintsTable.Add("0x80073602", "Failed to verify signature.")
    #ERROR_IPSEC_IKE_KERBEROS_ERROR
    $AMHintsTable.Add("0x80073603", "Failed to authenticate using Kerberos.")
    #ERROR_IPSEC_IKE_NO_PUBLIC_KEY
    $AMHintsTable.Add("0x80073604", "The peer's certificate did not have a public key.")
    #ERROR_IPSEC_IKE_PROCESS_ERR
    $AMHintsTable.Add("0x80073605", "Error processing the error payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_SA
    $AMHintsTable.Add("0x80073606", "Error processing the SA payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_PROP
    $AMHintsTable.Add("0x80073607", "Error processing the proposal payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_TRANS
    $AMHintsTable.Add("0x80073608", "Error processing the transform payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_KE
    $AMHintsTable.Add("0x80073609", "Error processing the key exchange payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_ID
    $AMHintsTable.Add("0x8007360A", "Error processing the ID payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_CERT
    $AMHintsTable.Add("0x8007360B", "Error processing the certification payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ
    $AMHintsTable.Add("0x8007360C", "Error processing the certificate request payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_HASH
    $AMHintsTable.Add("0x8007360D", "Error processing the hash payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_SIG
    $AMHintsTable.Add("0x8007360E", "Error processing the signature payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_NONCE
    $AMHintsTable.Add("0x8007360F", "Error processing the nonce payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY
    $AMHintsTable.Add("0x80073610", "Error processing the notify payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_DELETE
    $AMHintsTable.Add("0x80073611", "Error processing the delete payload.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR
    $AMHintsTable.Add("0x80073612", "Error processing the VendorId payload.")
    #ERROR_IPSEC_IKE_INVALID_PAYLOAD
    $AMHintsTable.Add("0x80073613", "Invalid payload received.")
    #ERROR_IPSEC_IKE_LOAD_SOFT_SA
    $AMHintsTable.Add("0x80073614", "Soft SA loaded.")
    #ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN
    $AMHintsTable.Add("0x80073615", "Soft SA torn down.")
    #ERROR_IPSEC_IKE_INVALID_COOKIE
    $AMHintsTable.Add("0x80073616", "Invalid cookie received.")
    #ERROR_IPSEC_IKE_NO_PEER_CERT
    $AMHintsTable.Add("0x80073617", "Peer failed to send valid machine certificate.")
    #ERROR_IPSEC_IKE_PEER_CRL_FAILED
    $AMHintsTable.Add("0x80073618", "Certification revocation check of peer's certificate failed.")
    #ERROR_IPSEC_IKE_POLICY_CHANGE
    $AMHintsTable.Add("0x80073619", "New policy invalidated SAs formed with the old policy.")
    #ERROR_IPSEC_IKE_NO_MM_POLICY
    $AMHintsTable.Add("0x8007361A", "There is no available main mode IKE policy.")
    #ERROR_IPSEC_IKE_NOTCBPRIV
    $AMHintsTable.Add("0x8007361B", "Failed to enabled trusted computer base (TCB) privilege.")
    #ERROR_IPSEC_IKE_SECLOADFAIL
    $AMHintsTable.Add("0x8007361C", "Failed to load SECURITY.DLL.")
    #ERROR_IPSEC_IKE_FAILSSPINIT
    $AMHintsTable.Add("0x8007361D", "Failed to obtain the security function table dispatch address from the SSPI.")
    #ERROR_IPSEC_IKE_FAILQUERYSSP
    $AMHintsTable.Add("0x8007361E", "Failed to query the Kerberos package to obtain the max token size.")
    #ERROR_IPSEC_IKE_SRVACQFAIL
    $AMHintsTable.Add("0x8007361F", "Failed to obtain the Kerberos server credentials for the Internet Security Association and Key Management Protocol (ISAKMP)/ERROR_IPSEC_IKE service. Kerberos authentication will not function. The most likely reason for this is lack of domain membership. This is normal if your computer is a member of a workgroup.")
    #ERROR_IPSEC_IKE_SRVQUERYCRED
    $AMHintsTable.Add("0x80073620", "Failed to determine the SSPI principal name for ISAKMP/ERROR_IPSEC_IKE service (QueryCredentialsAttributes).")
    #ERROR_IPSEC_IKE_GETSPIFAIL
    $AMHintsTable.Add("0x80073621", "Failed to obtain a new service provider interface (SPI) for the inbound SA from the IPsec driver. The most common cause for this is that the driver does not have the correct filter. Check your policy to verify the filters.")
    #ERROR_IPSEC_IKE_INVALID_FILTER
    $AMHintsTable.Add("0x80073622", "Given filter is invalid.")
    #ERROR_IPSEC_IKE_OUT_OF_MEMORY
    $AMHintsTable.Add("0x80073623", "Memory allocation failed.")
    #ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED
    $AMHintsTable.Add("0x80073624", "Failed to add an SA to the IPSec driver. The most common cause for this is if the IKE negotiation took too long to complete. If the problem persists, reduce the load on the faulting machine.")
    #ERROR_IPSEC_IKE_INVALID_POLICY
    $AMHintsTable.Add("0x80073625", "Invalid policy.")
    #ERROR_IPSEC_IKE_UNKNOWN_DOI
    $AMHintsTable.Add("0x80073626", "Invalid digital object identifier (DOI).")
    #ERROR_IPSEC_IKE_INVALID_SITUATION
    $AMHintsTable.Add("0x80073627", "Invalid situation.")
    #ERROR_IPSEC_IKE_DH_FAILURE
    $AMHintsTable.Add("0x80073628", "Diffie-Hellman failure.")
    #ERROR_IPSEC_IKE_INVALID_GROUP
    $AMHintsTable.Add("0x80073629", "Invalid Diffie-Hellman group.")
    #ERROR_IPSEC_IKE_ENCRYPT
    $AMHintsTable.Add("0x8007362A", "Error encrypting payload.")
    #ERROR_IPSEC_IKE_DECRYPT
    $AMHintsTable.Add("0x8007362B", "Error decrypting payload.")
    #ERROR_IPSEC_IKE_POLICY_MATCH
    $AMHintsTable.Add("0x8007362C", "Policy match error.")
    #ERROR_IPSEC_IKE_UNSUPPORTED_ID
    $AMHintsTable.Add("0x8007362D", "Unsupported ID.")
    #ERROR_IPSEC_IKE_INVALID_HASH
    $AMHintsTable.Add("0x8007362E", "Hash verification failed.")
    #ERROR_IPSEC_IKE_INVALID_HASH_ALG
    $AMHintsTable.Add("0x8007362F", "Invalid hash algorithm.")
    #ERROR_IPSEC_IKE_INVALID_HASH_SIZE
    $AMHintsTable.Add("0x80073630", "Invalid hash size.")
    #ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG
    $AMHintsTable.Add("0x80073631", "Invalid encryption algorithm.")
    #ERROR_IPSEC_IKE_INVALID_AUTH_ALG
    $AMHintsTable.Add("0x80073632", "Invalid authentication algorithm.")
    #ERROR_IPSEC_IKE_INVALID_SIG
    $AMHintsTable.Add("0x80073633", "Invalid certificate signature.")
    #ERROR_IPSEC_IKE_LOAD_FAILED
    $AMHintsTable.Add("0x80073634", "Load failed.")
    #ERROR_IPSEC_IKE_RPC_DELETE
    $AMHintsTable.Add("0x80073635", "Deleted by using an RPC call.")
    #ERROR_IPSEC_IKE_BENIGN_REINIT
    $AMHintsTable.Add("0x80073636", "A temporary state was created to perform reinitialization. This is not a real failure.")
    #ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY
    $AMHintsTable.Add("0x80073637", "The lifetime value received in the Responder Lifetime Notify is below the Windows 2000 configured minimum value. Fix the policy on the peer machine.")
    #ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN
    $AMHintsTable.Add("0x80073639", "Key length in the certificate is too small for configured security requirements.")
    #ERROR_IPSEC_IKE_MM_LIMIT
    $AMHintsTable.Add("0x8007363A", "Maximum number of established MM SAs to peer exceeded.")
    #ERROR_IPSEC_IKE_NEGOTIATION_DISABLED
    $AMHintsTable.Add("0x8007363B", "The IKE received a policy that disables negotiation.")
    #ERROR_IPSEC_IKE_QM_LIMIT
    $AMHintsTable.Add("0x8007363C", "Reached maximum quick mode limit for the main mode. New main mode will be started.")
    #ERROR_IPSEC_IKE_MM_EXPIRED
    $AMHintsTable.Add("0x8007363D", "Main mode SA lifetime expired or the peer sent a main mode delete.")
    #ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID
    $AMHintsTable.Add("0x8007363E", "Main mode SA assumed to be invalid because peer stopped responding.")
    #ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH
    $AMHintsTable.Add("0x8007363F", "Certificate does not chain to a trusted root in IPsec policy.")
    #ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID
    $AMHintsTable.Add("0x80073640", "Received unexpected message ID.")
    #ERROR_IPSEC_IKE_INVALID_UMATTS
    $AMHintsTable.Add("0x80073641", "Received invalid AuthIP user mode attributes.")
    #ERROR_IPSEC_IKE_DOS_COOKIE_SENT
    $AMHintsTable.Add("0x80073642", "Sent DOS cookie notify to initiator.")
    #ERROR_IPSEC_IKE_SHUTTING_DOWN
    $AMHintsTable.Add("0x80073643", "The IKE service is shutting down.")
    #ERROR_IPSEC_IKE_CGA_AUTH_FAILED
    $AMHintsTable.Add("0x80073644", "Could not verify the binding between the color graphics adapter (CGA) address and the certificate.")
    #ERROR_IPSEC_IKE_PROCESS_ERR_NATOA
    $AMHintsTable.Add("0x80073645", "Error processing the NatOA payload.")
    #ERROR_IPSEC_IKE_INVALID_MM_FOR_QM
    $AMHintsTable.Add("0x80073646", "The parameters of the main mode are invalid for this quick mode.")
    #ERROR_IPSEC_IKE_QM_EXPIRED
    $AMHintsTable.Add("0x80073647", "The quick mode SA was expired by the IPsec driver.")
    #ERROR_IPSEC_IKE_TOO_MANY_FILTERS
    $AMHintsTable.Add("0x80073648", "Too many dynamically added IKEEXT filters were detected.")
    #ERROR_IPSEC_IKE_NEG_STATUS_END
    $AMHintsTable.Add("0x80073649", "Ends the list of frequencies of various IKE Win32 error codes encountered during negotiations.")
    #ERROR_SXS_SECTION_NOT_FOUND
    $AMHintsTable.Add("0x800736B0", "The requested section was not present in the activation context.")
    #ERROR_SXS_CANT_GEN_ACTCTX
    $AMHintsTable.Add("0x800736B1", "The application has failed to start because its side-by-side configuration is incorrect. See the application event log for more detail.")
    #ERROR_SXS_INVALID_ACTCTXDATA_FORMAT
    $AMHintsTable.Add("0x800736B2", "The application binding data format is invalid.")
    #ERROR_SXS_ASSEMBLY_NOT_FOUND
    $AMHintsTable.Add("0x800736B3", "The referenced assembly is not installed on your system.")
    #ERROR_SXS_MANIFEST_FORMAT_ERROR
    $AMHintsTable.Add("0x800736B4", "The manifest file does not begin with the required tag and format information.")
    #ERROR_SXS_MANIFEST_PARSE_ERROR
    $AMHintsTable.Add("0x800736B5", "The manifest file contains one or more syntax errors.")
    #ERROR_SXS_ACTIVATION_CONTEXT_DISABLED
    $AMHintsTable.Add("0x800736B6", "The application attempted to activate a disabled activation context.")
    #ERROR_SXS_KEY_NOT_FOUND
    $AMHintsTable.Add("0x800736B7", "The requested lookup key was not found in any active activation context.")
    #ERROR_SXS_VERSION_CONFLICT
    $AMHintsTable.Add("0x800736B8", "A component version required by the application conflicts with another active component version.")
    #ERROR_SXS_WRONG_SECTION_TYPE
    $AMHintsTable.Add("0x800736B9", "The type requested activation context section does not match the query API used.")
    #ERROR_SXS_THREAD_QUERIES_DISABLED
    $AMHintsTable.Add("0x800736BA", "Lack of system resources has required isolated activation to be disabled for the current thread of execution.")
    #ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET
    $AMHintsTable.Add("0x800736BB", "An attempt to set the process default activation context failed because the process default activation context was already set.")
    #ERROR_SXS_UNKNOWN_ENCODING_GROUP
    $AMHintsTable.Add("0x800736BC", "The encoding group identifier specified is not recognized.")
    #ERROR_SXS_UNKNOWN_ENCODING
    $AMHintsTable.Add("0x800736BD", "The encoding requested is not recognized.")
    #ERROR_SXS_INVALID_XML_NAMESPACE_URI
    $AMHintsTable.Add("0x800736BE", "The manifest contains a reference to an invalid URI.")
    #ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_OT_INSTALLED
    $AMHintsTable.Add("0x800736BF", "The application manifest contains a reference to a dependent assembly that is not installed.")
    #ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED
    $AMHintsTable.Add("0x800736C0", "The manifest for an assembly used by the application has a reference to a dependent assembly that is not installed.")
    #ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE
    $AMHintsTable.Add("0x800736C1", "The manifest contains an attribute for the assembly identity that is not valid.")
    #ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE
    $AMHintsTable.Add("0x800736C2", "The manifest is missing the required default namespace specification on the assembly element.")
    #ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE
    $AMHintsTable.Add("0x800736C3", "The manifest has a default namespace specified on the assembly element but its value is not urn:schemas-microsoft-com:asm.v1`".`"")
    #ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT
    $AMHintsTable.Add("0x800736C4", "The private manifest probed has crossed the reparse-point-associated path.")
    #ERROR_SXS_DUPLICATE_DLL_NAME
    $AMHintsTable.Add("0x800736C5", "Two or more components referenced directly or indirectly by the application manifest have files by the same name.")
    #ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME
    $AMHintsTable.Add("0x800736C6", "Two or more components referenced directly or indirectly by the application manifest have window classes with the same name.")
    #ERROR_SXS_DUPLICATE_CLSID
    $AMHintsTable.Add("0x800736C7", "Two or more components referenced directly or indirectly by the application manifest have the same COM server CLSIDs.")
    #ERROR_SXS_DUPLICATE_IID
    $AMHintsTable.Add("0x800736C8", "Two or more components referenced directly or indirectly by the application manifest have proxies for the same COM interface IIDs.")
    #ERROR_SXS_DUPLICATE_TLBID
    $AMHintsTable.Add("0x800736C9", "Two or more components referenced directly or indirectly by the application manifest have the same COM type library TLBIDs.")
    #ERROR_SXS_DUPLICATE_PROGID
    $AMHintsTable.Add("0x800736CA", "Two or more components referenced directly or indirectly by the application manifest have the same COM ProgIDs.")
    #ERROR_SXS_DUPLICATE_ASSEMBLY_NAME
    $AMHintsTable.Add("0x800736CB", "Two or more components referenced directly or indirectly by the application manifest are different versions of the same component, which is not permitted.")
    #ERROR_SXS_FILE_HASH_MISMATCH
    $AMHintsTable.Add("0x800736CC", "A component's file does not match the verification information present in the component manifest.")
    #ERROR_SXS_POLICY_PARSE_ERROR
    $AMHintsTable.Add("0x800736CD", "The policy manifest contains one or more syntax errors.")
    #ERROR_SXS_XML_E_MISSINGQUOTE
    $AMHintsTable.Add("0x800736CE", "Manifest Parse Error: A string literal was expected, but no opening quotation mark was found.")
    #ERROR_SXS_XML_E_COMMENTSYNTAX
    $AMHintsTable.Add("0x800736CF", "Manifest Parse Error: Incorrect syntax was used in a comment.")
    #ERROR_SXS_XML_E_BADSTARTNAMECHAR
    $AMHintsTable.Add("0x800736D0", "Manifest Parse Error: A name started with an invalid character.")
    #ERROR_SXS_XML_E_BADNAMECHAR
    $AMHintsTable.Add("0x800736D1", "Manifest Parse Error: A name contained an invalid character.")
    #ERROR_SXS_XML_E_BADCHARINSTRING
    $AMHintsTable.Add("0x800736D2", "Manifest Parse Error: A string literal contained an invalid character.")
    #ERROR_SXS_XML_E_XMLDECLSYNTAX
    $AMHintsTable.Add("0x800736D3", "Manifest Parse Error: Invalid syntax for an XML declaration.")
    #ERROR_SXS_XML_E_BADCHARDATA
    $AMHintsTable.Add("0x800736D4", "Manifest Parse Error: An Invalid character was found in text content.")
    #ERROR_SXS_XML_E_MISSINGWHITESPACE
    $AMHintsTable.Add("0x800736D5", "Manifest Parse Error: Required white space was missing.")
    #ERROR_SXS_XML_E_EXPECTINGTAGEND
    $AMHintsTable.Add("0x800736D6", "Manifest Parse Error: The angle bracket (>) character was expected.")
    #ERROR_SXS_XML_E_MISSINGSEMICOLON
    $AMHintsTable.Add("0x800736D7", "Manifest Parse Error: A semicolon (;) was expected.")
    #ERROR_SXS_XML_E_UNBALANCEDPAREN
    $AMHintsTable.Add("0x800736D8", "Manifest Parse Error: Unbalanced parentheses.")
    #ERROR_SXS_XML_E_INTERNALERROR
    $AMHintsTable.Add("0x800736D9", "Manifest Parse Error: Internal error.")
    #ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE
    $AMHintsTable.Add("0x800736DA", "Manifest Parse Error: Whitespace is not allowed at this location.")
    #ERROR_SXS_XML_E_INCOMPLETE_ENCODING
    $AMHintsTable.Add("0x800736DB", "Manifest Parse Error: End of file reached in invalid state for current encoding.")
    #ERROR_SXS_XML_E_MISSING_PAREN
    $AMHintsTable.Add("0x800736DC", "Manifest Parse Error: Missing parenthesis.")
    #ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE
    $AMHintsTable.Add("0x800736DD", "Manifest Parse Error: A single (`') or double (`") quotation mark is missing.")
    #ERROR_SXS_XML_E_MULTIPLE_COLONS
    $AMHintsTable.Add("0x800736DE", "Manifest Parse Error: Multiple colons are not allowed in a name.")
    #ERROR_SXS_XML_E_INVALID_DECIMAL
    $AMHintsTable.Add("0x800736DF", "Manifest Parse Error: Invalid character for decimal digit.")
    #ERROR_SXS_XML_E_INVALID_HEXIDECIMAL
    $AMHintsTable.Add("0x800736E0", "Manifest Parse Error: Invalid character for hexadecimal digit.")
    #ERROR_SXS_XML_E_INVALID_UNICODE
    $AMHintsTable.Add("0x800736E1", "Manifest Parse Error: Invalid Unicode character value for this platform.")
    #ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK
    $AMHintsTable.Add("0x800736E2", "Manifest Parse Error: Expecting whitespace or question mark (?).")
    #ERROR_SXS_XML_E_UNEXPECTEDENDTAG
    $AMHintsTable.Add("0x800736E3", "Manifest Parse Error: End tag was not expected at this location.")
    #ERROR_SXS_XML_E_UNCLOSEDTAG
    $AMHintsTable.Add("0x800736E4", "Manifest Parse Error: The following tags were not closed: %1.")
    #ERROR_SXS_XML_E_DUPLICATEATTRIBUTE
    $AMHintsTable.Add("0x800736E5", "Manifest Parse Error: Duplicate attribute.")
    #ERROR_SXS_XML_E_MULTIPLEROOTS
    $AMHintsTable.Add("0x800736E6", "Manifest Parse Error: Only one top-level element is allowed in an XML document.")
    #ERROR_SXS_XML_E_INVALIDATROOTLEVEL
    $AMHintsTable.Add("0x800736E7", "Manifest Parse Error: Invalid at the top level of the document.")
    #ERROR_SXS_XML_E_BADXMLDECL
    $AMHintsTable.Add("0x800736E8", "Manifest Parse Error: Invalid XML declaration.")
    #ERROR_SXS_XML_E_MISSINGROOT
    $AMHintsTable.Add("0x800736E9", "Manifest Parse Error: XML document must have a top-level element.")
    #ERROR_SXS_XML_E_UNEXPECTEDEOF
    $AMHintsTable.Add("0x800736EA", "Manifest Parse Error: Unexpected end of file.")
    #ERROR_SXS_XML_E_BADPEREFINSUBSET
    $AMHintsTable.Add("0x800736EB", "Manifest Parse Error: Parameter entities cannot be used inside markup declarations in an internal subset.")
    #ERROR_SXS_XML_E_UNCLOSEDSTARTTAG
    $AMHintsTable.Add("0x800736EC", "Manifest Parse Error: Element was not closed.")
    #ERROR_SXS_XML_E_UNCLOSEDENDTAG
    $AMHintsTable.Add("0x800736ED", "Manifest Parse Error: End element was missing the angle bracket (>) character.")
    #ERROR_SXS_XML_E_UNCLOSEDSTRING
    $AMHintsTable.Add("0x800736EE", "Manifest Parse Error: A string literal was not closed.")
    #ERROR_SXS_XML_E_UNCLOSEDCOMMENT
    $AMHintsTable.Add("0x800736EF", "Manifest Parse Error: A comment was not closed.")
    #ERROR_SXS_XML_E_UNCLOSEDDECL
    $AMHintsTable.Add("0x800736F0", "Manifest Parse Error: A declaration was not closed.")
    #ERROR_SXS_XML_E_UNCLOSEDCDATA
    $AMHintsTable.Add("0x800736F1", "Manifest Parse Error: A CDATA section was not closed.")
    #ERROR_SXS_XML_E_RESERVEDNAMESPACE
    $AMHintsTable.Add("0x800736F2", "Manifest Parse Error: The namespace prefix is not allowed to start with the reserved string xml`".`"")
    #ERROR_SXS_XML_E_INVALIDENCODING
    $AMHintsTable.Add("0x800736F3", "Manifest Parse Error: System does not support the specified encoding.")
    #ERROR_SXS_XML_E_INVALIDSWITCH
    $AMHintsTable.Add("0x800736F4", "Manifest Parse Error: Switch from current encoding to specified encoding not supported.")
    #ERROR_SXS_XML_E_BADXMLCASE
    $AMHintsTable.Add("0x800736F5", "Manifest Parse Error: The name `"xml`" is reserved and must be lowercase.")
    #ERROR_SXS_XML_E_INVALID_STANDALONE
    $AMHintsTable.Add("0x800736F6", "Manifest Parse Error: The stand-alone attribute must have the value `"yes`" or `"no`".")
    #ERROR_SXS_XML_E_UNEXPECTED_STANDALONE
    $AMHintsTable.Add("0x800736F7", "Manifest Parse Error: The stand-alone attribute cannot be used in external entities.")
    #ERROR_SXS_XML_E_INVALID_VERSION
    $AMHintsTable.Add("0x800736F8", "Manifest Parse Error: Invalid version number.")
    #ERROR_SXS_XML_E_MISSINGEQUALS
    $AMHintsTable.Add("0x800736F9", "Manifest Parse Error: Missing equal sign (=) between the attribute and the attribute value.")
    #ERROR_SXS_PROTECTION_RECOVERY_FAILED
    $AMHintsTable.Add("0x800736FA", "Assembly Protection Error: Unable to recover the specified assembly.")
    #ERROR_SXS_PROTECTION_PUBLIC_KEY_OO_SHORT
    $AMHintsTable.Add("0x800736FB", "Assembly Protection Error: The public key for an assembly was too short to be allowed.")
    #ERROR_SXS_PROTECTION_CATALOG_NOT_VALID
    $AMHintsTable.Add("0x800736FC", "Assembly Protection Error: The catalog for an assembly is not valid, or does not match the assembly's manifest.")
    #ERROR_SXS_UNTRANSLATABLE_HRESULT
    $AMHintsTable.Add("0x800736FD", "An HRESULT could not be translated to a corresponding Win32 error code.")
    #ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING
    $AMHintsTable.Add("0x800736FE", "Assembly Protection Error: The catalog for an assembly is missing.")
    #ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE
    $AMHintsTable.Add("0x800736FF", "The supplied assembly identity is missing one or more attributes that must be present in this context.")
    #ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME
    $AMHintsTable.Add("0x80073700", "The supplied assembly identity has one or more attribute names that contain characters not permitted in XML names.")
    #ERROR_SXS_ASSEMBLY_MISSING
    $AMHintsTable.Add("0x80073701", "The referenced assembly could not be found.")
    #ERROR_SXS_CORRUPT_ACTIVATION_STACK
    $AMHintsTable.Add("0x80073702", "The activation context activation stack for the running thread of execution is corrupt.")
    #ERROR_SXS_CORRUPTION
    $AMHintsTable.Add("0x80073703", "The application isolation metadata for this process or thread has become corrupt.")
    #ERROR_SXS_EARLY_DEACTIVATION
    $AMHintsTable.Add("0x80073704", "The activation context being deactivated is not the most recently activated one.")
    #ERROR_SXS_INVALID_DEACTIVATION
    $AMHintsTable.Add("0x80073705", "The activation context being deactivated is not active for the current thread of execution.")
    #ERROR_SXS_MULTIPLE_DEACTIVATION
    $AMHintsTable.Add("0x80073706", "The activation context being deactivated has already been deactivated.")
    #ERROR_SXS_PROCESS_TERMINATION_REQUESTED
    $AMHintsTable.Add("0x80073707", "A component used by the isolation facility has requested to terminate the process.")
    #ERROR_SXS_RELEASE_ACTIVATION_ONTEXT
    $AMHintsTable.Add("0x80073708", "A kernel mode component is releasing a reference on an activation context.")
    #ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY
    $AMHintsTable.Add("0x80073709", "The activation context of the system default assembly could not be generated.")
    #ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE
    $AMHintsTable.Add("0x8007370A", "The value of an attribute in an identity is not within the legal range.")
    #ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME
    $AMHintsTable.Add("0x8007370B", "The name of an attribute in an identity is not within the legal range.")
    #ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE
    $AMHintsTable.Add("0x8007370C", "An identity contains two definitions for the same attribute.")
    #ERROR_SXS_IDENTITY_PARSE_ERROR
    $AMHintsTable.Add("0x8007370D", "The identity string is malformed. This may be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value.")
    #ERROR_MALFORMED_SUBSTITUTION_STRING
    $AMHintsTable.Add("0x8007370E", "A string containing localized substitutable content was malformed. Either a dollar sign ($) was followed by something other than a left parenthesis or another dollar sign, or a substitution's right parenthesis was not found.")
    #ERROR_SXS_INCORRECT_PUBLIC_KEY_OKEN
    $AMHintsTable.Add("0x8007370F", "The public key token does not correspond to the public key specified.")
    #ERROR_UNMAPPED_SUBSTITUTION_STRING
    $AMHintsTable.Add("0x80073710", "A substitution string had no mapping.")
    #ERROR_SXS_ASSEMBLY_NOT_LOCKED
    $AMHintsTable.Add("0x80073711", "The component must be locked before making the request.")
    #ERROR_SXS_COMPONENT_STORE_CORRUPT
    $AMHintsTable.Add("0x80073712", "The component store has been corrupted.")
    #ERROR_ADVANCED_INSTALLER_FAILED
    $AMHintsTable.Add("0x80073713", "An advanced installer failed during setup or servicing.")
    #ERROR_XML_ENCODING_MISMATCH
    $AMHintsTable.Add("0x80073714", "The character encoding in the XML declaration did not match the encoding used in the document.")
    #ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT
    $AMHintsTable.Add("0x80073715", "The identities of the manifests are identical, but the contents are different.")
    #ERROR_SXS_IDENTITIES_DIFFERENT
    $AMHintsTable.Add("0x80073716", "The component identities are different.")
    #ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT
    $AMHintsTable.Add("0x80073717", "The assembly is not a deployment.")
    #ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY
    $AMHintsTable.Add("0x80073718", "The file is not a part of the assembly.")
    #ERROR_SXS_MANIFEST_TOO_BIG
    $AMHintsTable.Add("0x80073719", "The size of the manifest exceeds the maximum allowed.")
    #ERROR_SXS_SETTING_NOT_REGISTERED
    $AMHintsTable.Add("0x8007371A", "The setting is not registered.")
    #ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE
    $AMHintsTable.Add("0x8007371B", "One or more required members of the transaction are not present.")
    #ERROR_EVT_INVALID_CHANNEL_PATH
    $AMHintsTable.Add("0x80073A98", "The specified channel path is invalid.")
    #ERROR_EVT_INVALID_QUERY
    $AMHintsTable.Add("0x80073A99", "The specified query is invalid.")
    #ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND
    $AMHintsTable.Add("0x80073A9A", "The publisher metadata cannot be found in the resource.")
    #ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND
    $AMHintsTable.Add("0x80073A9B", "The template for an event definition cannot be found in the resource (error = %1).")
    #ERROR_EVT_INVALID_PUBLISHER_NAME
    $AMHintsTable.Add("0x80073A9C", "The specified publisher name is invalid.")
    #ERROR_EVT_INVALID_EVENT_DATA
    $AMHintsTable.Add("0x80073A9D", "The event data raised by the publisher is not compatible with the event template definition in the publisher's manifest.")
    #ERROR_EVT_CHANNEL_NOT_FOUND
    $AMHintsTable.Add("0x80073A9F", "The specified channel could not be found. Check channel configuration.")
    #ERROR_EVT_MALFORMED_XML_TEXT
    $AMHintsTable.Add("0x80073AA0", "The specified XML text was not well-formed. See extended error for more details.")
    #ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL
    $AMHintsTable.Add("0x80073AA1", "The caller is trying to subscribe to a direct channel which is not allowed. The events for a direct channel go directly to a log file and cannot be subscribed to.")
    #ERROR_EVT_CONFIGURATION_ERROR
    $AMHintsTable.Add("0x80073AA2", "Configuration error.")
    #ERROR_EVT_QUERY_RESULT_STALE
    $AMHintsTable.Add("0x80073AA3", "The query result is stale or invalid. This may be due to the log being cleared or rolling over after the query result was created. Users should handle this code by releasing the query result object and reissuing the query.")
    #ERROR_EVT_QUERY_RESULT_INVALID_POSITION
    $AMHintsTable.Add("0x80073AA4", "Query result is currently at an invalid position.")
    #ERROR_EVT_NON_VALIDATING_MSXML
    $AMHintsTable.Add("0x80073AA5", "Registered Microsoft XML (MSXML) does not support validation.")
    #ERROR_EVT_FILTER_ALREADYSCOPED
    $AMHintsTable.Add("0x80073AA6", "An expression can only be followed by a change-of-scope operation if it itself evaluates to a node set and is not already part of some other change-of-scope operation.")
    #ERROR_EVT_FILTER_NOTELTSET
    $AMHintsTable.Add("0x80073AA7", "Cannot perform a step operation from a term that does not represent an element set.")
    #ERROR_EVT_FILTER_INVARG
    $AMHintsTable.Add("0x80073AA8", "Left side arguments to binary operators must be either attributes, nodes, or variables and right side arguments must be constants.")
    #ERROR_EVT_FILTER_INVTEST
    $AMHintsTable.Add("0x80073AA9", "A step operation must involve either a node test or, in the case of a predicate, an algebraic expression against which to test each node in the node set identified by the preceding node set can be evaluated.")
    #ERROR_EVT_FILTER_INVTYPE
    $AMHintsTable.Add("0x80073AAA", "This data type is currently unsupported.")
    #ERROR_EVT_FILTER_PARSEERR
    $AMHintsTable.Add("0x80073AAB", "A syntax error occurred at position %1!d!")
    #ERROR_EVT_FILTER_UNSUPPORTEDOP
    $AMHintsTable.Add("0x80073AAC", "This operator is unsupported by this implementation of the filter.")
    #ERROR_EVT_FILTER_UNEXPECTEDTOKEN
    $AMHintsTable.Add("0x80073AAD", "The token encountered was unexpected.")
    #ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL
    $AMHintsTable.Add("0x80073AAE", "The requested operation cannot be performed over an enabled direct channel. The channel must first be disabled before performing the requested operation.")
    #ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE
    $AMHintsTable.Add("0x80073AAF", "Channel property %1!s! contains an invalid value. The value has an invalid type, is outside the valid range, cannot be updated, or is not supported by this type of channel.")
    #ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE
    $AMHintsTable.Add("0x80073AB0", "Publisher property %1!s! contains an invalid value. The value has an invalid type, is outside the valid range, cannot be updated, or is not supported by this type of publisher.")
    #ERROR_EVT_CHANNEL_CANNOT_ACTIVATE
    $AMHintsTable.Add("0x80073AB1", "The channel fails to activate.")
    #ERROR_EVT_FILTER_TOO_COMPLEX
    $AMHintsTable.Add("0x80073AB2", "The xpath expression exceeded supported complexity. Simplify it or split it into two or more simple expressions.")
    #ERROR_EVT_MESSAGE_NOT_FOUND
    $AMHintsTable.Add("0x80073AB3", "The message resource is present but the message is not found in the string or message table.")
    #ERROR_EVT_MESSAGE_ID_NOT_FOUND
    $AMHintsTable.Add("0x80073AB4", "The message ID for the desired message could not be found.")
    #ERROR_EVT_UNRESOLVED_VALUE_INSERT
    $AMHintsTable.Add("0x80073AB5", "The substitution string for the insert index (%1) could not be found.")
    #ERROR_EVT_UNRESOLVED_PARAMETER_INSERT
    $AMHintsTable.Add("0x80073AB6", "The description string for the parameter reference (%1) could not be found.")
    #ERROR_EVT_MAX_INSERTS_REACHED
    $AMHintsTable.Add("0x80073AB7", "The maximum number of replacements has been reached.")
    #ERROR_EVT_EVENT_DEFINITION_NOT_OUND
    $AMHintsTable.Add("0x80073AB8", "The event definition could not be found for the event ID (%1).")
    #ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND
    $AMHintsTable.Add("0x80073AB9", "The locale-specific resource for the desired message is not present.")
    #ERROR_EVT_VERSION_TOO_OLD
    $AMHintsTable.Add("0x80073ABA", "The resource is too old to be compatible.")
    #ERROR_EVT_VERSION_TOO_NEW
    $AMHintsTable.Add("0x80073ABB", "The resource is too new to be compatible.")
    #ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY
    $AMHintsTable.Add("0x80073ABC", "The channel at index %1 of the query cannot be opened.")
    #ERROR_EVT_PUBLISHER_DISABLED
    $AMHintsTable.Add("0x80073ABD", "The publisher has been disabled and its resource is not available. This usually occurs when the publisher is in the process of being uninstalled or upgraded.")
    #ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE
    $AMHintsTable.Add("0x80073AE8", "The subscription fails to activate.")
    #ERROR_EC_LOG_DISABLED
    $AMHintsTable.Add("0x80073AE9", "The log of the subscription is in a disabled state and events cannot be forwarded to it. The log must first be enabled before the subscription can be activated.")
    #ERROR_MUI_FILE_NOT_FOUND
    $AMHintsTable.Add("0x80073AFC", "The resource loader failed to find the Multilingual User Interface (MUI) file.")
    #ERROR_MUI_INVALID_FILE
    $AMHintsTable.Add("0x80073AFD", "The resource loader failed to load the MUI file because the file failed to pass validation.")
    #ERROR_MUI_INVALID_RC_CONFIG
    $AMHintsTable.Add("0x80073AFE", "The release candidate (RC) manifest is corrupted with garbage data, is an unsupported version, or is missing a required item.")
    #ERROR_MUI_INVALID_LOCALE_NAME
    $AMHintsTable.Add("0x80073AFF", "The RC manifest has an invalid culture name.")
    #ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME
    $AMHintsTable.Add("0x80073B00", "The RC Manifest has an invalid ultimate fallback name.")
    #ERROR_MUI_FILE_NOT_LOADED
    $AMHintsTable.Add("0x80073B01", "The resource loader cache does not have a loaded MUI entry.")
    #ERROR_RESOURCE_ENUM_USER_STOP
    $AMHintsTable.Add("0x80073B02", "The user stopped resource enumeration.")
    #ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED
    $AMHintsTable.Add("0x80073B03", "User interface language installation failed.")
    #ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME
    $AMHintsTable.Add("0x80073B04", "Locale installation failed.")
    #ERROR_MCA_INVALID_CAPABILITIES_STRING
    $AMHintsTable.Add("0x80073B60", "The monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification.")
    #ERROR_MCA_INVALID_VCP_VERSION
    $AMHintsTable.Add("0x80073B61", "The monitor's VCP version (0xDF) VCP code returned an invalid version value.")
    #ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION
    $AMHintsTable.Add("0x80073B62", "The monitor does not comply with the MCCS specification it claims to support.")
    #ERROR_MCA_MCCS_VERSION_MISMATCH
    $AMHintsTable.Add("0x80073B63", "The MCCS version in a monitor's mccs_ver capability does not match the MCCS version the monitor reports when the VCP version (0xDF) VCP code is used.")
    #ERROR_MCA_UNSUPPORTED_MCCS_VERSION
    $AMHintsTable.Add("0x80073B64", "The monitor configuration API works only with monitors that support the MCCS 1.0, MCCS 2.0, or MCCS 2.0 Revision 1 specifications.")
    #ERROR_MCA_INTERNAL_ERROR
    $AMHintsTable.Add("0x80073B65", "An internal monitor configuration API error occurred.")
    #ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED
    $AMHintsTable.Add("0x80073B66", "The monitor returned an invalid monitor technology type. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification.")
    #ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE
    $AMHintsTable.Add("0x80073B67", "The SetMonitorColorTemperature() caller passed a color temperature to it that the current monitor did not support. CRT, plasma, and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification.")
    #ERROR_AMBIGUOUS_SYSTEM_DEVICE
    $AMHintsTable.Add("0x80073B92", "The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria.")
    #ERROR_SYSTEM_DEVICE_NOT_FOUND
    $AMHintsTable.Add("0x80073BC3", "The requested system device cannot be found.")


			}
				
			# Append/overwrite hints loaded from config\hints\*.xml files
			# TODO
			$HintsFolder = "$($AMEnvironment.Path)\config\hints" 
			If (Test-path $HintsFolder)
			{
				Foreach ($HintsXml in Get-ChildItem -Path $HintsFolder -Filter "*.xml")
				{
					[xml]$XmlDocument = Get-Content -Path $HintsXml.FullName			
					$XmlDocument.GetEnumerator() |  %{$_.HintDefinition} | % {
						If (($AMHintsTable.ContainsKey($_.Exception)))
						{
							$AMHintsTable.Remove($_.Exception)	
						}
						$AMHintsTable.Add($_.Exception,$_.Hint)
					}					
				}
			}
			
			
			# Lookup the hint for the exception
			$ErrType = $Error.Exception.GetBaseException().GetType().ToString()
		
			#Translate COM Exception to hex code
			If ($ErrType -eq "System.Runtime.InteropServices.COMException")
			{
				$ErrType = "0x{0:X8}" -f $_.Exception.GetBaseException().ErrorCode
			}

			
			If ($ErrType)
			{
				If ($AMHintsTable.ContainsKey($ErrType))
				{
					$Hint = $AMHintsTable.Item($ErrType)
					$UniversalTime  = $([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
					Write-Host "[" -ForegroundColor Red -NoNewline
					Write-Host "$($UniversalTime)" -NoNewline
					Write-Host "] HINT: $($Hint)" -ForegroundColor Red
					If (-not ([string]::IsNullOrEmpty($global:am_logfile)))		
					{
						Write-AMLogFile "[$($UniversalTime)] HINT: $($Hint)"
					}				
				}
			}
		}

		$GenerateFile = $false
		If ($am_context -eq "system")
  	    {
			If ($am_offline -eq $false)
			{
				$GenerateFile = $true
			}
			Write-AMEventLog -Message $ErrorMessage -EntryType Error
		}
    	
		If (-not ([string]::IsNullOrEmpty($global:am_logfile)))		
		{
			Write-AMLogFile "[$($UniversalTime)] ERROR: $($ErrorMessage + $Append)"
		}
			
		If ($GenerateFile -eq $true)
		{
		
			# Replace xml NULL characters, when they are in HTML Hex output (happens sometimes)
			$ErrorMessage = $ErrorMessage.Replace("&#x0;", "")
			$Computer = Get-AMComputer -Name $env:COMPUTERNAME
			If ($Computer -is [Object])
			{		
				#Create the folder if it does not exist
				$StatusFolder = "$AMCentralPath\$($AMEnvironment.id)\monitoring\systems\$($computer.id)\errors"
				If (!(Test-Path $StatusFolder)) {[void] (New-Item -ItemType Directory -Path $StatusFolder)}
				[xml]$StatusFile = New-Object System.Xml.XmlDocument
				$RootElement = $StatusFile.CreateElement("Dashboardstatus")
				[void] $StatusFile.AppendChild($RootElement)


				$XmlNode = $StatusFile.CreateElement("Name")
				$XmlNode.Innertext = "Error"
				[void] $RootElement.AppendChild($XmlNode)

				$XmlNode = $StatusFile.CreateElement("Value")
				If (Test-Path Variable:\Hint)
				{
					If (!([string]::IsNullOrEmpty($Hint)))
					{
						$StatusText = $($UniversalTime) + "`n" + $($ErrorMessage) + ".`nHINT: $($Hint) $Append"
					}
					else
					{
						$StatusText = $($UniversalTime) + "`n" + $($ErrorMessage) + ". $Append"
					}
				}
				else
				{
					$StatusText = $($UniversalTime) + "`n" + $($ErrorMessage) + ". $Append"
				}
				
				$XmlNode.Innertext = $($StatusText)
				[void] $RootElement.AppendChild($XmlNode)

				$XmlNode = $StatusFile.CreateElement("Backgroundcolor")
				$XmlNode.Innertext = [System.Convert]::ToInt32([System.ConsoleColor]::Red)
				[void] $RootElement.AppendChild($XmlNode)
				
				$FileName = "$StatusFolder\$([Guid]::NewGuid().ToString()).xml"
				$StatusFile.Save($FileName)
			}
		}
		
	}
	Catch [Exception]
	{
		write-host "*** Error in error handler ***" -ForegroundColor Red
        $_ | Out-Host
	}
}
<#
	.Synopsis
	Displays info messages on screen.

	.Description
	Displays info messages on screen and in the transcript.

	.Parameter Information
	The informational message to process.

	.Parameter EventLog
	If the switch is enabled the script will write the info message to the Windows Event Log too.

	.Example
	Write-AMInfo "Executing package: $Package"
#>
function Write-AMInfo
{
	param
	(
		[string] $Information,

		[switch] $EventLog
	)
	
	$UniversalTime  = $([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
	$Message = ""

	if (Test-Path Variable:Plugin)
	{
		$Message = "$($Plugin.Name.ToUpper()): $Information"
	}
	else
	{
		$Message = "CONSOLE: $Information"
	}

	$MessageWithTimestamp = "[$($UniversalTime)] $Message"

	Write-Host "$MessageWithTimestamp"
	if (-not ([string]::IsNullOrEmpty($global:am_logfile)))
	{
		Write-AMLogFile "$MessageWithTimestamp"
	}

	if ($EventLog) {
		Write-AMEventLog -Message $Message
	}
	
}

<#
	.Synopsis
	Writes logging to file.

	.Description
 	Writes logging to file.
  
	.Parameter Message
 	$Message = The message to write to log.

    .Parameter LogOrigin
    Used for custom logging, when specified, the log will be written to a file named after this parameter.

	.Example
	Write-AMLogFile "Executing package: $Package"
#>
function Write-AMLogFile
{
	Param
	(
		[String]$Message,
		[String]$LogOrigin = [String]::Empty
	)
	
    #region Set up for default/custom logging
    $LogFilePathTemplate = "$am_logpath\{0}_$(Get-Date -f yyyyMMddHHmmss){1}.log"
    
    $DefaultLoggingMode = $LogOrigin -eq [String]::Empty

    $LogFilePrefix = $(if($DefaultLoggingMode) { $Event.Name } else { $LogOrigin })
    $LogFilePath = $(if($DefaultLoggingMode) 
        { 
            $global:am_logfile 
        } 
        else 
        { 
            #get latest log or create a new file name
            $existingCustomLogFilePath = Get-ChildItem -Path $am_logpath -Filter $LogFilePrefix* | Sort-Object -Property $_.LastWriteTime -Descending | Select-Object -First 1
            if($null -eq $existingCustomLogFilePath)
            {
                [String]::Format($LogFilePathTemplate, $LogFilePrefix, [String]::Empty)     
            }
            else
            {
                "$am_logpath\$($existingCustomLogFilePath.Name)"
            }        
        })
    #endregion

	if (-not ([string]::IsNullOrEmpty($LogFilePath)))
	{
		try
		{
            $Message | Out-File -FilePath $LogFilePath -Append -Encoding "utf8" -Force -ErrorAction Stop
		}
		catch
		{
			$LogFilePath = [String]::Format($LogFilePathTemplate, $LogFilePrefix, $("-$(Get-Random)"))
            if ($DefaultLoggingMode)
            {
                $global:am_logfile = $LogFilePath
            }
            try {
                $Message | Out-File -FilePath $LogFilePath -Append -Encoding "utf8" -Force -ErrorAction Stop
            }
            catch {
                Write-Host "Unable to write to the log file for some reason"
                Write-Host "File path: $LogFilePath"
                Write-Host "Message is $Message"
            }			
		}		
	}
}
<#
	.Synopsis
	Displays status messages on screen and updates the dashboard status.

	.Description
	Displays status messages on screen and creates a status object in the centralshare that is read by the dashboard.
  
	.Parameter Status
	The status message to process.

	.Parameter EventLogEntryType
	Event log entry type (Info, Warning, Error).

    .Example
	Write-AMStatus "Installing $Package.Name"
#>
function Write-AMStatus {
    Param
    (
        [String] $Status,
		
        [ValidateSet("Info", "Warning", "Error")]
        [string] $EventLogEntryType = "Info"
    )


    $UniversalTime = $([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
		
		
    $GenerateFile = $false
    if ($am_context -eq "System") {
			
        if ($am_offline -eq $false) {
            $GenerateFile = $true
        }
    }
		
    Write-Host "[$($UniversalTime)] STATUS: $Status"
    if (-not ([string]::IsNullOrEmpty($global:am_logfile))) {
        Write-AMLogFile "[$($UniversalTime)] STATUS: $Status"
    }
		
    if ($GenerateFile -eq $true) {
        $Computer = Get-AMComputer -Name $env:COMPUTERNAME
        if ($Computer -is [Object]) {		
            #Create the folder if it does not exist
            $StatusFolder = "$AMCentralPath\$($AMEnvironment.id)\monitoring\systems\$($computer.id)\status"
            if (!(Test-Path $StatusFolder)) { [void] (New-Item -ItemType Directory -Path $StatusFolder) }
            # try to remove all status files
            $Files = Get-ChildItem -Path $StatusFolder | ? { -not $_.PSIsContainer }
            try {
                $files | Remove-Item -Force
            }
            catch { }

            [xml]$StatusFile = New-Object System.Xml.XmlDocument
            $RootElement = $StatusFile.CreateElement("Dashboardstatus")
            [void] $StatusFile.AppendChild($RootElement)

            $XmlNode = $StatusFile.CreateElement("Name")
            $XmlNode.Innertext = "Status"
            [void] $RootElement.AppendChild($XmlNode)

            $XmlNode = $StatusFile.CreateElement("Value")
            $XmlNode.Innertext = $Status
            [void] $RootElement.AppendChild($XmlNode)

            $XmlNode = $StatusFile.CreateElement("Backgroundcolor")
            $XmlNode.Innertext = [System.Convert]::ToInt32([System.ConsoleColor]::White)
            [void] $RootElement.AppendChild($XmlNode)
				
            $FileName = "$StatusFolder\$([Guid]::NewGuid().ToString()).xml"
            $StatusFile.Save($FileName)				
            Write-AMEventLog -Message "STATUS: $Status" -EntryType $EventLogEntryType
        }
    }
}
<#
.SYNOPSIS
Writes additional information about function that is being executed.

.DESCRIPTION
Writes additional information about function that is being executed. Works only in Verbose mode.

.PARAMETER Info
Invocation info.

.EXAMPLE
Write-AMVerboseHeader -Info $MyInvocation
#>
function Write-AMVerboseHeader {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [System.Management.Automation.InvocationInfo] $Info
    )

	if ([bool] $PSBoundParameters['Verbose'])
	{
		Write-Verbose "$([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")): #### Start $($Info.MyCommand) ####"
		Write-Verbose "$([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")): Executing commandline: $($Info.Line)"
	}
}
<#
	.Synopsis
	Displays warning messages on screen.

	.Description
	Displays warning messages on screen.

	.Parameter Warning
	The error message to process.

	.Parameter EventLog
	If the switch is enabled the script will write the info message to the Windows Event Log too.

	.Example
	Write-AMWarning "Error Installing Adobe Reader X"
#>
function Write-AMWarning
{
[cmdletbinding()]
	Param
	(
		[string] $Warning,
		
		[switch] $EventLog
	)
	

	Get-PSCallStack | % {Write-Verbose "Trace: $($_.Command)"}
	$UniversalTime  = $([System.DateTime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))
	Write-Host "[" -ForegroundColor Yellow -NoNewline
	Write-Host "$($UniversalTime)" -NoNewline
	Write-Host "] WARNING: $Warning" -ForegroundColor Yellow		
	If (-not ([string]::IsNullOrEmpty($global:am_logfile)))		
	{
		Write-AMLogFile "[$($UniversalTime)] WARNING: $Warning"
	}

	if ($EventLog) {
		Write-AMEventLog -Message $Warning -EntryType "Warning"
	}

}
<#
	.SYNOPSIS
	Adds a layer to the specified collection.

	.DESCRIPTION
 	Adds a layer to the specified collection's layer list.

	.PARAMETER Collection
	Collection to which the layer should be added.
	
	.PARAMETER Layer
	Layer object.
	
	.PARAMETER DefaultOrderNumber
	Layer processing order number.

	.EXAMPLE
	PS> $collection = Get-AMCollection -Name "My Collection"
	PS> Add-AMLayer -Collection $collection -Layer $(Get-AMLayer -Name "My Layer") -DefaultOrderNumber 10
	PS> Set-AMCollection -Collection $collection
#>
function Add-AMLayer {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[AutomationMachine.Data.Collection]
		$Collection,
		
		[Parameter(Mandatory = $true)]
		[AutomationMachine.Data.Layer]
		$Layer,
		
		[Parameter(Mandatory = $true)]
		[int]
		$DefaultOrderNumber
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	$AMDataManager.AddCollectionLayer($Collection.Id, $Layer.Id, $DefaultOrderNumber)
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a package to the specified layer or collection.

	.Description
 	Adds a package to the specified layer's or collection's package list.
  
	.Parameter Layer
	Layer to which the package should be added.

	.Parameter Collection
	Collection to which the package should be added.
	
	.Parameter Package
	Package object.
	
	.Parameter DefaultOrderNumber
	Default order number for all configuration categories (phases).
		 
 	.Example
	PS> $layer = Get-AMLayer -Name "Office"
 	PS> Add-AMPackage -Layer $layer -Package $(Get-AMPackage -Name "LibreOffice") -DefaultOrderNumber 20
	PS> Set-AMLayer -Layer $layer

	.Example
	PS> $collection = Get-AMCollection -Name "My Collection"
	PS> Add-AMPackage -Collection $collection -Package $(Get-AMPackage -Name "Google Chrome") -DefaultOrderNumber 10
	PS> Set-AMCollection -Collection $collection
#>
function Add-AMPackage {
	[CmdletBinding()]
	param (
	
		[Parameter(mandatory = $true, ParameterSetName = "Layer")]
		[AutomationMachine.Data.Layer]
		$Layer,

		[Parameter(mandatory = $true, ParameterSetName = "Collection")]
		[AutomationMachine.Data.Collection]
		$Collection,
		
		[Parameter(mandatory = $true, ParameterSetName = "Layer")]
		[Parameter(mandatory = $true, ParameterSetName = "Collection")]
		[AutomationMachine.Data.Package]
		$Package,
		
		[Parameter(mandatory = $true, ParameterSetName = "Layer")]
		[Parameter(mandatory = $true, ParameterSetName = "Collection")]
		[int]
		$DefaultOrderNumber
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	switch ($PSCmdlet.ParameterSetName) {
		"Layer"	{
			$AMDataManager.AddLayerPackage($Layer.Id, $Package.Id, $DefaultOrderNumber)
		}
		
		"Collection" {
			$AMDataManager.AddCollectionPackage($Collection.Id, $Package.Id, $DefaultOrderNumber)
		}
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Copies a collection.

	.Description
 	Copies a collection.
  
	.Parameter Name
	The name of the collection to copy.
	
	.Parameter NewName
	The name for the copied collection.
	
	.Parameter ParentCollectionName
	The name of the collection to which the original collection is to be copied.

	.Example
	Copy-AMCollection -Name "RootCollection" -NewName "RootCollection-Copy" -ParentCollectionName "RootParentCollection"
#>
function Copy-AMCollection
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$NewName,

		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$ParentCollectionName
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PScmdlet.ParameterSetName)
		{
			"Name" {
				$NewCollectionId = [Guid]::NewGuid()
				$ParentCollection = Get-AMCollection -Name $ParentCollectionName
				$SourceCollection = Get-AMCollection -Name $Name
				$AMDataManager.CopyAmObject($SourceCollection,$NewName,$NewCollectionId, $ParentCollection.Id, $SourceCollection.EventMapId)
			}
		}
		

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Copies a layer.

	.Description
 	Copies a layer.
  
	.Parameter Name
	The name of the layer to copy.
	
	.Parameter NewName
	The name for the copied layer.
	
	.Example
	Copy-AMLayer -Name "ChildLayer" -NewName "ChildLayer-Copy"
#>
function Copy-AMLayer
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$NewName
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PScmdlet.ParameterSetName)
		{
			"Name" {
				$NewLayerId = [Guid]::NewGuid()
				$SourceLayer = Get-AMLayer -Name $Name
				$AMDataManager.CopyAmObject($SourceLayer,$NewName,$NewLayerId)
			}
		}
		

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Copies a package.

	.Description
 	Copies a package to a packagecategory.
  
	.Parameter Name
	The name of the package to copy.
	
	.Parameter NewName
	The name for the copied package.
	
	.Parameter PackageCategory
	The name of the packagecategory to create the copy in.
		 
	
	.Example
	Copy-AMPackage -Name "Java JRE 7 update 7" -NewName "Java Copy" -PackageCategory "Applications" 
#>
function Copy-AMPackage
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$NewName,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$PackageCategory
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PScmdlet.ParameterSetName)
		{
			"Name" {
				$NewPackageId = [Guid]::NewGuid()
				$SourcePackage = Get-AMPackage -Name $Name
				$DestinationPackageCategory = Get-AMPackageCategory -Name $PackageCategory							
				$AMDataManager.CopyAmObject($SourcePackage,$NewName,$NewPackageId,$DestinationPackageCategory)
			}
		}
		

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified Collection object.

	.Description
 	Saves changes of the specified Collection object to AutomationMachine share.
  
	.Parameter Collection
	Collection object.
		 
 	.Example
	$Collection = Get-AMCollection -Name "Desktop Collection"
	$Collection.Name = "My Collection"
 	Edit-AMCollection -Collection $Collection
#>
function Edit-AMCollection
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Collection]
		$Collection
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditCollection($Collection.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified computer object.

	.Description
 	Saves changes of the specified Computer object to AutomationMachine share.
  
	.Parameter Computer
	Computer object.
		 
 	.Example
	$Computer = Get-AMComputer -Name "Computer-001"
	$Computer.Name = "Computer-002"
 	Edit-AMComputer -Computer $Computer
#>
function Edit-AMComputer
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Computer]
		$Computer
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditComputer($Computer.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified Filter object.

	.Description
 	Saves changes of the specified Filter object to AutomationMachine share.
  
	.Parameter Filter
	Filter object.
		 
 	.Example
 	Edit-AMFilter -Filter $Filter
#>
function Edit-AMFilter
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Filter]
		$Filter
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditFilter($Filter.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified layer object.

	.Description
 	Saves changes of the specified layer object to AutomationMachine share.
  
	.Parameter Layer
	Layer object.
		 
 	.Example
	$layer = Get-AMLayer -Name "desktop silo"
 	Edit-AMLayer -Layer $layer
#>
function Edit-AMLayer
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Layer]
		$Layer
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditLayer($Layer.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified Package object.

	.Description
 	Saves changes of the specified Package object to AutomationMachine share.
  
	.Parameter Package
	Package object.
		 
 	.Example
	$Package = Get-AMPackage -Name "Adobe Reader X"
	$Package.Name = "Adobe Reader XI"
 	Edit-AMPackage -Package $Package
#>
function Edit-AMPackage
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Package]
		$Package
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditPackage($Package.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified PackageCategory object.

	.Description
 	Saves changes of the specified PackageCategory object to AutomationMachine share.
  
	.Parameter PackageCategory
	Package category object.
		 
 	.Example
	$PackageCategory = Get-AMPackageCategory -Name "Office Applications"
	$PackageCategory.Name = "Office"
 	Edit-AMPackageCategory -PackageCategory $PackageCategory
#>
function Edit-AMPackageCategory
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.PackageCategory]
		$PackageCategory
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditPackageCategory($PackageCategory.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified Plugin object.

	.Description
 	Saves changes of the specified Plugin object to AutomationMachine share.
  
	.Parameter Plugin
	Plugin object.
		 
 	.Example
	$Plugin = Get-AMPlugin -Name "My Plugin"
	$Plugin.Name = "Test Plugin"
 	Edit-AMPlugin -Plugin $Plugin
#>
function Edit-AMPlugin
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Plugin]
		$Plugin
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditPlugin($Plugin.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified user targeted layer object.

	.Description
 	Saves changes of the specified user targeted layer object to AutomationMachine share.
  
	.Parameter UserTargetedLayer
	User targeted layer object.
		 
 	.Example
	$userTargetedLayer = Get-AMUserTargetedLayer -Name "My-UTL"
 	Edit-AMUserTargetedLayer -UserTargetedLayer $userTargetedLayer
#>
function Edit-AMUserTargetedLayer
{
	[CmdletBinding()]
	param 
	(	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.UserTargetedLayer]
		$UserTargetedLayer
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditUserTargetedLayer($UserTargetedLayer.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified variable object.

	.Description
 	Saves changes of the specified variable object to the specified or current environment.
  
	.Parameter Variable
	Variable object.
		 
 	.Example
	$var = Get-AMVariable -name installdir
	$var.Value += "\install"
	Edit-AMVariable -Variable $var
#>
function Edit-AMVariable
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.IVariable]
		$Variable
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.EditVariable($Variable)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified VariableFilter object.

	.Description
 	Saves changes of the specified VariableFilter object to AutomationMachine share.
  
	.Parameter Component
	The parent component of the variable.
  
	.Parameter VariableFilter
	Variable filter object.
		 
 	.Example
 	Edit-AMVariableFilter -Component $Component -VariableFilter $VariableFilter
#>
function Edit-AMVariableFilter
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.VariableFilter]
		$VariableFilter
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	
		$AMDataManager.EditVariableFilter($Component, $VariableFilter)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Imports a collection from supplied zip archive.

	.Description
 	Imports a collection from supplied zip archive. Overwrites any existing files/packages without prompting!
  
	.Parameter ArchivePath
 	The path to the zip archive for the collection.
	
	.Parameter NoMedia
	Specifies that the media included in the package exports should not be imported.
	
	.NOTES
	Does not check if files/packages already exists, just overwrites if they do!
 
 	.Example
 	Import-AMCollection -ArchivePath "C:\SomeCollectionArchive.amcol"

#>
function Import-AMCollection
{
	[cmdLetbinding()]
	param
	(
		[alias("Path")]
		[parameter(mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[string]
		$ArchivePath,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$NoMedia		
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

			if (!(Test-Path $ArchivePath))
			{
				Throw "File doesn't exist, unable to import non-existing file"	
			}
			
			$manifest = $AMDataManager.ReadImportManifest($archivePath)
			
			if ($manifest.Collections.Count -gt 0)
			{				
				$importedCollection = $manifest.Collections | ? {$_.ParentId -eq [guid]::Empty} | Select-Object -First 1
				If ($NoMedia)
				{
					$AMDataManager.ImportCollection($archivePath, $importedCollection.Id, [Guid]::Empty, $null,$null,$null,$false)			
				}
				else
				{
					$AMDataManager.ImportCollection($archivePath, $importedCollection.Id, [Guid]::Empty, $null,$null,$null,$true)			
				}
			}
			else
			{
				throw "Not a valid collection archive, unable to import"
			}

		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}
<#
	.Synopsis
	Imports a layer from supplied zip archive.

	.Description
 	Imports a layer from supplied zip archive. Overwrites any existing files/packages without prompting!
  
	.Parameter ArchivePath
 	The path to the zip archive for the package.
	
	.Parameter NoMedia
	Specifies that the media included in the package exports should not be imported.
	
	.NOTES
	Does not check if files/package already exists, just overwrites if they do!
 
 	.Example
 	Import-AMLayer -ArchivePath "C:\SomeLayerArchive.zip"

#>
function Import-AMLayer
{
	[cmdLetbinding()]
	param
	(
		[alias("Path")]
		[parameter(mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[string]
		$ArchivePath,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$NoMedia
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


			if (!(Test-Path $ArchivePath))
			{
				Throw "File doesn't exist, unable to import non-existing file"	
			}
			
			$manifest = $AMDataManager.ReadImportManifest($archivePath)
			
			if ($manifest.Layers.Count -gt 0)
			{
				If ($NoMedia)
				{
					$AMDataManager.ImportLayers($archivePath,$null,$null,$null,$false)			
				}
				else
				{
					$AMDataManager.ImportLayers($archivePath,$null,$null,$null,$true)			
				}
			}
			else
			{
				throw "Not a valid layer archive, unable to import"
			}
			

		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}
<#
	.Synopsis
	Imports media from supplied path. 

	.Description
 	Imports media from supplied path. Raw files and zip/iso archives are supported. If media already exists, the path provided will be imported as a new revision.
  
	.Parameter Path
 	The path to source file or folder for the media.
	
	.Parameter MediaInfo
	MediaInfo object describing the media to be added.
	
	.Parameter Vendor
	The vendor of the software/media to import.
	
	.Parameter SoftwareName
	The name of the software/media to import.
	
	.Parameter Language
	The language of the software/media to import.
	
	.Parameter Version
	The version of the software/media to import.
	
	
 	.Example
 	Import-AMMedia -Path "C:\SomeMediaArchive.zip" -MediaInfo $MediaInfo

#>
function Import-AMMedia
{
	[cmdLetbinding(DefaultParameterSetName="Named")]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$true,Position=0,ParameterSetName="Object")]
		[parameter(ParameterSetName="Named")]
		[ValidateNotNullOrEmpty()]
		[string]
		$Path,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=1,ParameterSetName="Object")]
		[ValidateNotNullOrEmpty()]
		[AutomationMachine.Data.MediaInfo]
		$MediaInfo,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=1,ParameterSetName="Named")]
		[ValidateNotNullOrEmpty()]
		[string]
		$Vendor,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=2,ParameterSetName="Named")]
		[ValidateNotNullOrEmpty()]
		[string]
		$SoftwareName,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=3,ParameterSetName="Named")]
		[ValidateNotNullOrEmpty()]
		[string]
		$Language,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=4,ParameterSetName="Named")]
		[ValidateNotNullOrEmpty()]
		[string]
		$Version

		
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


			if (!(Test-Path $Path))
			{
				Throw "$($Path) doesn't exist, unable to import non-existing file/folder"	
			}
			If (-not (Test-Path -Path $Path -PathType Container))
			{
				$Extension = [System.IO.Path]::GetExtension($Path)
				If (-not (($Extension -eq ".iso") -or ($Extension -eq ".zip")))
				{
					throw "$($Path) is not a folder, zip or ISO file, cannot import media"
				}
			}
			Switch ($PSCmdlet.ParameterSetName)
			{
				"Object" 
				{
					if($MediaInfo -eq $null)
					{
						Throw "Please supply a MediaInfo object describing the media to be imported"
					}
				}
				"Named"
				{
					$MediaInfo = New-Object AutomationMachine.Data.MediaInfo
					$MediaInfo.Vendor = $Vendor
					$MediaInfo.SoftwareName = $SoftwareName
					$Mediainfo.Language = $Language
					$MediaInfo.Version = $Version
				}
			}
			
			
			Write-Verbose "Importing media $($MediaInfo.Vendor)-$($MediaInfo.SoftwareName)-$($MediaInfo.Language)-$($MediaInfo.Version) from $($Path)"
			$AMDataManager.AddMediaSynchronous($MediaInfo, $Path)
			
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}
<#
	.Synopsis
	Imports a package from a supplied zip archive.

	.Description
 	Imports a package from a supplied zip archive into the PackageCategoryID specified. Overwrites any existing files/packages without prompting!
  
	.Parameter Path
 	The path to the zip archive for the package.
	
	.Parameter PackageCategoryID
	The ID of the PackageCategory to import into.
	
	.Parameter NoMedia
	Specifies that the media included in the package export should not be imported.
  
	.NOTES
	Does not check if files/package already exists, just overwrites if they do!
 
 	.Example
 	$PkgCat = Get-AMPackageCategory -Name "Software"
	Import-AMPackage -Path "C:\SomePackageArchive.zip" -PackageCategoryID $PkgCat.Id

#>
function Import-AMPackage
{
	[cmdLetbinding()]
	param
	(
		[alias("ArchivePath")]
		[parameter(mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[string]
		$Path,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=1)]
		[string]
		$PackageCategoryID,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$NoMedia
		
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

			if (!(Test-Path $Path))
			{
				Throw "File doesn't exist, unable to import non-existing file"	
			}
			
			try {
				$zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
				$contents = $zip.Entries | ? { $_.FullName -eq "contents.xml" }
				if ($contents -ne $null)
				{
					$stream = $contents.Open()
					$contentsXmlDocument = New-Object System.Xml.XmlDocument
					$contentsXmlDocument.Load($stream)
					$item = $contentsXmlDocument.DocumentElement
					if (($item.ChildNodes | ? { $_.Name -eq "Id" }) -ne $null) { # old format
						$packageId = $item.Id
					}
					else { # new format
						$packageId = $item.Packages.Package.Id
					}
					If ($packageId -ne $null)
					{
						If ($NoMedia)
						{
							$AMDataManager.ImportPackage($Path,$null,$packageId,$packageCategoryID,$false)	
						}
						else
						{
							$AMDataManager.ImportPackage($Path,$null,$packageId,$packageCategoryID,$true)			
						}
					}
					else
					{
						throw "Unable to locate the packageId for this archive, unable to import"
					}
				}
				else
				{
					throw "Not a valid AM archive, unable to import"
				}
			}
			catch {
				throw $_
			}
			finally {
				if ($stream -ne $null) {
					$stream.Dispose()
				}
				if ($zip -ne $null) {
					$zip.Dispose()
				}
			}
			
		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Adds a new action item object to the share.

	.Description
 	Adds a new action item object to the specified component's action set.
	
	.Parameter Component
	The component to which action item belongs.
	
	.Parameter ActionItem
	Action item object.
	
 	.Example
	$template = Get-AMActionItemTemplate -Name "Custom Script"
	$component = Get-AMPackage -Name "Adobe Reader X"
	$actionSet = $component.ActionSets | Where-Object { $_.Name -eq "Default" }
 	$actionItem = New-AMActionItemInstance -Component $component -Template $template
	$actionItem.ActionSetId = $actionSet.Id
	$var = $actionItem.Variables[0]
	$var.Value.Path = "C:\test\test.txt"
	New-AMActionItem -Component $component -ActionItem $actionItem
#>
function New-AMActionItem
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
		
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.ActionItem]
		$ActionItem
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.AddActionItem($Component.Id, $ActionItem)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Creates new instance of ActionItem object.

	.Description
 	Creates new instance of ActionItem object and adds it to the specified action set.
	
	.Parameter Component
	The component to which action item belongs.
	
	.Parameter Template
	Specifies the action item template.
		 
 	.Example
	$template = Get-AMActionItemTemplate -Name "Custom Script"
	$component = Get-AMPackage -Name "Adobe Reader X"
 	$actionItem = New-AMActionItemInstance -Component $component -Template $template
#>
function New-AMActionItemInstance
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.ActionItemTemplate]
		$Template
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		return $Template.CreateInstance($Component.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a collection to the specified or current environment.

	.Description
 	Adds a new collection object to Automation Environment.
  
	.Parameter Collection
	Collection object.
	
	.Parameter Name
	The name for the new collection.
	
	.Parameter Parent
	The parent for the new collection.
	
	.Parameter EventMap
	The Eventmap for the new collection.
	
 	.Example
	$EventMap = Get-AMEventmap -Name "SBC"
	$Parent = Get-AMCollection -Name "Parent Collection"
	$Collection = New-Object AutomationMachine.Data.Collection
	$Collection.Id = [System.Guid]::NewGuid()
	$Collection.Name = "My Collection"
	$Collection.Parent = $Parent
	$Collection.EvenMapId = $EventMap.Id
 	New-AMCollection -Collection $Collection
	
	.Example
	New-AMCollection -Name "MyCollection" -Parent "CollectionParent" -EventMap "SBC"
	
	.Example
	New-AMCollection -Name "MyCollection" -EventMap "SBC"
#>

function New-AMCollection
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Object")]
		[AutomationMachine.Data.Collection]
		$Collection,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$Parent,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$EventMap
		
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		
		Switch ($PSCmdlet.ParameterSetName)
		{
			"Object" {}
			"Name" {
				$EvtMap= Get-AMEventMap -Name $EventMap
				$ParentCol = Get-AMCollection -Name $Parent
				$Collection = New-Object AutomationMachine.Data.Collection
				$Collection.id = [Guid]::NewGuid()
				$Collection.Name = $Name
				If ($ParentCol -ne $null)
				{
					$Collection.Parent = $ParentCol
				}
				If ($EvtMap -ne $null)
				{
					$Collection.EventMapId = $EvtMap.Id
				}
			}
		}
		$AMDataManager.AddCollection($Collection)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a computer to Automation Machine.

	.Description
 	Adds a new computer object to Automation Machine.
	
	.Parameter Computer
 	Computer object.
	
	.Parameter Name
	The name for the computer to create.
	
	.Parameter Collection
	The name of the collection to add the computer to.
		 
 	.Example
	$Computer = New-Object AutomationMachine.Data.Computer
	$Computer.Id = [System.Guid]::NewGuid()
	$Computer.Name = "Computer-001"
	$Computer.CollectionId = Get-AMCollection -Name "Desktop Collection" | %{ $_.Id }
	New-AMComputer -Computer $Computer
	
	.Example
	New-AMComputer -Name "Computer-001" -Collection "RootCollection"
#>
function New-AMComputer
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Object")]
		[AutomationMachine.Data.Computer]
		$Computer,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Collection		
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PSCmdlet.ParameterSetName)
		{
			"Object" {}
			"Name" {
				$Col = Get-AMCollection -Name $Collection
				$Computer = New-Object AutomationMachine.Data.Computer
				$Computer.Id = [Guid]::NewGuid()
				If ($Col -ne $null)
				{
					$Computer.CollectionId = $Col.Id
				}
				$Computer.Name = $Name
			}
		}
		$AMDataManager.AddComputer($Computer)

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a configuration category to Automation Machine.

	.Description
 	Adds a new configuration category object to Automation Machine.
	
	.Parameter ConfigurationCategory
 	Configuration category object.
	
	.Parameter Name
	The name of the configuration category.
		 
 	.Example
	$Category = New-Object AutomationMachine.Data.ConfigurationCategory
	$Category.Id = [System.Guid]::NewGuid()
	$Category.Name = "CustomCategory"
	New-AMConfigurationCategory -ConfigurationCategory $Category
	
	.Example
	New-AMConfigurationCategory -Name "My Configuration Category"
#>
function New-AMConfigurationCategory
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$true,ParameterSetName="Object")]
		[AutomationMachine.Data.ConfigurationCategory]
		$ConfigurationCategory,
		
		[parameter(mandatory=$true,ParameterSetName="Name")]
		[string]
		$Name
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		if ($PSCmdlet.ParameterSetName -eq "Name") {
			$ConfigurationCategory = New-Object AutomationMachine.Data.ConfigurationCategory
			$ConfigurationCategory.Id = [System.Guid]::NewGuid()
			$ConfigurationCategory.Name = $Name
		}
		$AMDataManager.AddConfigurationCategory($ConfigurationCategory)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a filter to the specified or current environment.

	.Description
 	Adds a filter object to Automation Environment.
  
	.Parameter Filter
	Filter object.
	
 	.Example
 	New-AMFilter -Filter $Filter
#>
function New-AMFilter
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Filter]
		$Filter
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.AddFilter($Filter)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a layer to the specified or current environment.

	.Description
 	Adds a layer object to the specified or current environment.
  
	.Parameter Layer
	Layer object.
	
	.Parameter Name
	The name of the layer to create.
	
	.Parameter Parent
	The parent of the layer to create.
		 
 	.Example
 	$layer = New-Object AutomationMachine.Data.Layer
	$layer.Id = [Guid]::NewGuid()
	$layer.Name = "My Layer"
	New-AMLayer -Layer $layer
	
	.Example
	New-AMLayer -Name "My Layer" -Parent "My Parent Layer"
	
	.Example
	New-AMLayer -Name "My Layer"
	
#>
function New-AMLayer
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$true,ValueFromPipeline=$false,ParameterSetName="Object")]
		[AutomationMachine.Data.Layer]
		$Layer,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Parent
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PSCmdlet.ParameterSetName)
		{
			"Object" {}
			"Name" {
				$Layer = New-Object AutomationMachine.Data.Layer
				$Layer.Id = [Guid]::NewGuid()
				$Layer.Name = $Name
				$ParentLayer = Get-AMLayer -Name $Parent
				If ($ParentLayer -ne $null)
				{
					$Layer.Parent = $ParentLayer
				}
			}
		}
		$AMDataManager.AddLayer($Layer)

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a package to the current environment.

	.Description
 	Adds a package to the current Automation Machine environment.
  
	.Parameter Package
	Package object.
	
	.Parameter Name
	The name of the package to create.
	
	.Parameter PackageCategory
	The name of the packagecategory to add this package to.
		 
 	.Example
 	$package = New-Object AutomationMachine.Data.Package
	$package.Id = [Guid]::NewGuid()
	$package.Name = "Java JRE 7 update 7"
	$package.PackageCategory = Get-AMPackageCategory -Name "Applications"
	New-AMPackage -Package $package
	
	.Example
	New-AMPackage -Name "Java JRE 7 update 7" -PackageCategory "Applications"
#>
function New-AMPackage
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Object")]
		[AutomationMachine.Data.Package]
		$Package,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[String]
		$PackageCategory
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PScmdlet.ParameterSetName)
		{
			"Object" {}
			"Name" {
				$package = New-Object AutomationMachine.Data.Package
				$package.Id = [Guid]::NewGuid()
				$package.Name = $Name
				$package.PackageCategory = Get-AMPackageCategory -Name $PackageCategory					
			}
		}
		$AMDataManager.AddPackage($Package)

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a package category to the share.

	.Description
	Adds a new package category object to the current environment and saves it to the file in the Automation Machine share.
  
	.Parameter PackageCategory
	Package category object.
	
	.Parameter Name
	Name of the package category to create.
	
	.Parameter Parent
	The parent this packagecategory belongs to
		 
 	.Example
	$PackageCategory = New-Object AutomationMachine.Data.PackageCategory
	$PackageCategory.Id = [System.Guid]::NewGuid()
	$PackageCategory.Name = "Office Applications"
	$PackageCategory.Parent = Get-AMPackageCategory -Name "Applications"
 	New-AMPackageCategory -PackageCategory $PackageCategory
	
	.Example
	New-AMPackageCategory -Name "Office Applications" -Parent "Applications"
	
	.Example
	New-AMPackageCategory -Name "Office Applications" 
#>
function New-AMPackageCategory
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Object")]
		[AutomationMachine.Data.PackageCategory]
		$PackageCategory,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Parent
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PSCmdlet.ParameterSetName)
		{
			"Object"  {}
			"Name" {
				$PackageCategory = New-Object AutomationMachine.Data.PackageCategory
				$PackageCategory.Id = [System.Guid]::NewGuid()
				$PackageCategory.Name = $Name
				If ($Parent -ne $null)
				{
					$PackageCategory.Parent = Get-AMPackageCategory -Name $Parent
				}
			}
		}
		$AMDataManager.AddPackageCategory($PackageCategory)

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a plugin to the current environment.

	.Description
 	Adds a plugin to the current Automation Machine environment and saves it.
  
	.Parameter Plugin
	Plugin object.
		 
 	.Example
 	New-AMPlugin -Plugin $Plugin
#>
function New-AMPlugin
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Plugin]
		$Plugin
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


		$AMDataManager.AddPlugin($Plugin)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a user targeted layer to the specified or current environment.

	.Description
 	Adds a user targeted layer object to the specified or current environment.
  
	.Parameter UserTargetedLayer
	User targeted layer object.
	
	.Parameter Name
	The name of the user targeted layer to create.
	
	.Parameter SecurityGroup
	The security group of the user targeted layer.
		 
 	.Example
 	$userTargetedLayer = New-Object AutomationMachine.Data.UserTargetedLayer
	$userTargetedLayer.Id = [Guid]::NewGuid()
	$userTargetedLayer.Name = "My User Targeted Layer"
	$userTargetedLayer.SecurityGroup = "My-Security-Group"
	New-AMUserTargetedLayer -UserTargetedLayer $userTargetedLayer
	
	.Example
	New-AMUserTargetedLayer -Name "My User Targeted Layer" -SecurityGroup "My-Security-Group"
	
#>
function New-AMUserTargetedLayer
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$true,ValueFromPipeline=$false,ParameterSetName="Object")]
		[AutomationMachine.Data.UserTargetedLayer]
		$UserTargetedLayer,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$SecurityGroup
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Switch ($PSCmdlet.ParameterSetName)
		{
			"Object" {}
			"Name" {
				$UserTargetedLayer = New-Object AutomationMachine.Data.UserTargetedLayer
				$UserTargetedLayer.Id = [Guid]::NewGuid()
				$UserTargetedLayer.Name = $Name
				$UserTargetedLayer.SecurityGroup = $SecurityGroup				
			}
		}
		$AMDataManager.AddUserTargetedLayer($UserTargetedLayer)

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a variable to the current environment.

	.Description
 	Adds a variable object to Automation Machine.
  
	.Parameter Variable
	Variable object.
	
	.Parameter Name
	The name of the variable to create.
	
	.Parameter FriendlyName
	The friendlyname for the variable, as displayed in the UI.
	
	.Parameter Type
	The type of the variable to create.
	
	.Parameter Value
	The value of the variable to create.
	
	.Parameter ComponentName
	The package or plugin name where to create this variable for.
	
	.Parameter Global
	Use Global switch if variable should be added to the global variable list. Default value - false.
		 
 	.Example
	$component = $AMEnvironment.Packages | Where-Object { $_.Name -eq "Adobe Reader X" }
	$v1 = New-Object AutomationMachine.Data.Variable($component.Id)
	$v1.Name = "ARVariablePublic"
	$v1.Type = [System.Type]::GetType("System.String")
	$v1.Value = "Public var value test"
	New-AMVariable -Variable $v1 -Global
	
	.Example
	New-AMVariable -Name "ARVariablePrivate" -FriendlyName "The name that is displayed in the GUI" -Type "System.String" -Value "TestValue" -ComponentName "Adobe Reader X"

#>
function New-AMVariable
{
	[CmdletBinding(DefaultParameterSetName="Name")]
	param 
	(
	
		[parameter(mandatory=$true,ValueFromPipeline=$false,ParameterSetName="Object")]
		[AutomationMachine.Data.Variable]
		$Variable,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Name,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$FriendlyName,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Type,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$Value,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[string]
		$ComponentName,
	
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Name")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Object")]
		[switch]
		$Global = $false
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		
		Switch ($PSCmdlet.ParameterSetName)
		{
			"Object"	{}
			"Name"		{
				$Package = Get-AMPackage -Name $ComponentName
				If ($Package -ne $null)
				{
					$Variable = New-Object AutomationMachine.Data.Variable($Package.id)
				}
				else
				{
					$Plugin = Get-AMPlugin -Name $ComponentName
					$Variable = New-Object AutomationMachine.Data.Variable($Plugin.id)
				}
				$Variable.Type = [System.Type]::GetType($Type)
				$Variable.Value = $Value
				$Variable.Name = $Name
				$Variable.FriendlyName = $FriendlyName
			}
		}
		
		if ($Global -eq $true) {
			$Variable.VariableScope = [AutomationMachine.Data.VariableScope]::Global
		}
		else {
			$Variable.VariableScope = [AutomationMachine.Data.VariableScope]::Local
			# read local variables if they has not been read before
			if ($Variable.ParentId -ne [Guid]::Empty) {
				$Component = $AMDataManager.Environment.GetComponent($Variable.ParentId)
				if (($Component -ne $null) -and (($Component.PrivateVariables -eq $null) -or ($Component.PrivateVariables.Count -eq 0))) {
					Read-AMPrivateVariables -Component $Component
				}
			}
		}
		$AMDataManager.AddVariable($Variable)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Adds a variable filter.

	.Description
 	Adds a variable filter object to Automation Machine.
  
	.Parameter VariableFilter
	Variable filter object.
	
	.Parameter Component
	The parent component of the variable.
		 
 	.Example
 	New-AMVariableFilter -VariableFilter $VariableFilter -Component $Component
#>
function New-AMVariableFilter
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
		
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.VariableFilter]
		$VariableFilter
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.AddVariableFilter($Component.Id, $VariableFilter)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified action item object.

	.Description
 	Deletes the specified action item object from the AutomationMachine share.
	
	.Parameter Component
	The component to which the action item belongs.
	
	.Parameter ActionItem
	Action item object.
	
 	.Example
 	Remove-AMActionItem -Component $Component -ActionItem $ActionItem
#>
function Remove-AMActionItem
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
		
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.ActionItem]
		$ActionItem
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteActionItem($Component.Id, $ActionItem.ActionSetId, $ActionItem.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified Collection object.

	.Description
 	Deletes the specified Collection object from the AutomationMachine share.
  
	.Parameter Collection
	Collection object.
	
 	.Example
	$Collection = Get-AMCollection -Name "My Collection"
 	Remove-AMCollection -Collection $Collection
#>
function Remove-AMCollection
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Collection]
		$Collection
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteCollection($Collection.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified computer.

	.Description
 	Deletes the specified Computer object from the AutomationMachine share.
  
	.Parameter Computer
	Computer object.
		 
 	.Example
	$computer = Get-AMComputer -Name "MyServer"
 	Remove-AMComputer -Computer $computer
#>
function Remove-AMComputer
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Computer]
		$Computer
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteComputer($Computer.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified configuration category.

	.Description
 	Deletes the specified configuration category object from the AutomationMachine share.
  
	.Parameter ConfigurationCategory
	Configuration category object.
		 
 	.Example
	$Category = Get-AMConfigurationCategory -Name "My Configuration Category"
 	Remove-AMConfigurationCategory -ConfigurationCategory $Category
#>
function Remove-AMConfigurationCategory
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.ConfigurationCategory]
		$ConfigurationCategory
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteConfigurationCategory($ConfigurationCategory.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the current environment.

	.Description
 	Deletes the current Environment object from the AutomationMachine share.
  
	.Parameter Environment
	Environment object.
		 
 	.Example
 	Remove-AMEnvironment
#>
function Remove-AMEnvironment
{
	[CmdletBinding()]
	param 
	(
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteEnvironment()
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified filter.

	.Description
 	Deletes the specified Filter object from the AutomationMachine share.
  
	.Parameter Filter
	Filter object.
		 
 	.Example
 	Remove-AMFilter -Filter $filter
#>
function Remove-AMFilter
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Filter]
		$Filter
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteFilter($Filter.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified layer.

	.Description
 	Deletes the specified layer object from the AutomationMachine share.
  
	.Parameter Layer
	Layer object.
		 
 	.Example
	$layer = Get-AMLayer -Name "desktop silo"
 	Remove-AMLayer -Layer $layer
#>
function Remove-AMLayer
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Layer]
		$Layer
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteLayer($Layer.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified package.

	.Description
 	Deletes the specified Package object from the AutomationMachine share.
  
	.Parameter Package
	Package object.
		 
 	.Example
 	Remove-AMPackage -Package $package
#>
function Remove-AMPackage
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Package]
		$Package
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeletePackage($Package.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified package category.

	.Description
 	Deletes the specified PackageCategory object from the AutomationMachine share.
  
	.Parameter PackageCategory
	PackageCategory object.
		 
 	.Example
	$PackageCategory = Get-AMPackageCategory -Name "Office Applications"
 	Remove-AMPackageCategory -PackageCategory $PackageCategory
#>
function Remove-AMPackageCategory
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.PackageCategory]
		$PackageCategory
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeletePackageCategory($PackageCategory.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified plugin.

	.Description
 	Deletes the specified Plugin object from the AutomationMachine share.
  
	.Parameter Plugin
	Plugin object.
		 
 	.Example
 	Remove-AMPlugin -Plugin $plugin
#>
function Remove-AMPlugin
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Plugin]
		$Plugin
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeletePlugin($Plugin.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified user targeted layer.

	.Description
 	Deletes the specified user targeted layer object from the AutomationMachine share.
  
	.Parameter UserTargetedLayer
	UserTargetedLayer object.
		 
 	.Example
	$userTargetedLayer = Get-AMUserTargetedLayer -Name "My-UTL"
 	Remove-AMUserTargetedLayer -UserTargetedLayer $userTargetedLayer
#>
function Remove-AMUserTargetedLayer
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.UserTargetedLayer]
		$UserTargetedLayer
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteUserTargetedLayer($UserTargetedLayer.Id)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified Variable object.

	.Description
 	Deletes the specified Variable object from the AutomationMachine share.
  
	.Parameter Variable
	Variable object.
	
 	.Example
 	Remove-AMVariable -Variable $Variable
#>
function Remove-AMVariable
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.IVariable]
		$Variable
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteVariable($Variable)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Deletes the specified VariableFilter object.

	.Description
 	Deletes the specified VariableFilter object from the AutomationMachine share.
	
	.Parameter Component
	The parent component of the variable.
	
	.Parameter VariableFilter
	Variable filter object.
		 
 	.Example
 	Remove-AMVariableFilter -VariableFilter $Variable -Component $Component
#>
function Remove-AMVariableFilter
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
		
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.VariableFilter]
		$VariableFilter
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$AMDataManager.DeleteVariableFilter($Component.Id, $VariableFilter)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}
<#
	.Synopsis
	Saves changes of the specified action item object.

	.Description
 	Saves changes of the specified configuration action item to AutomationMachine share.
  
	.Parameter Component
	The component to which the action item belongs.
	
	.Parameter ActionItem
	Action item object.
		 
 	.Example
	$component = Get-AMPackage -Name "Adobe Reader X"
 	Set-AMActionItem -Component $component -ActionItem $actionItem
#>
function Set-AMActionItem
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
		
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.ActionItem]
		$ActionItem
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$actionSet = $Component.ActionSets | Where-Object { $_.Id -eq $ActionItem.ActionSetId }
		$ai = $actionSet.ActionItems | Where-Object { $_.Id -eq $ActionItem.Id }
		if ($ai -ne $null) {
			$AMDataManager.EditActionItem($Component.Id, $ActionItem.ActionSetId, $ActionItem.Id)
		}
		else {
			New-AMActionItem -Component $Component -ActionItem $ActionItem
		}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the existing or creates a new collection object.

	.Description
 	Sets (adds or modifies) a collection object to AutomationMachine share.
  
	.Parameter Collection
	Collection object.
		 
 	.Example
	$collection = Get-AMCollection -Name "My Collection"
	$collection.Name = "Desktop Collection"
 	Set-AMCollection -Collection $collection
#>
function Set-AMCollection
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Collection]
		$Collection
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$coll = Get-AMCollection -Id $Collection.Id
		if ($coll -ne $null) {
			$AMDataManager.EditCollection($Collection.Id)
		}
		else {
			New-AMCollection -Collection $Collection
		}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified configuration category object.

	.Description
 	Saves changes of the specified configuration category object to AutomationMachine share.
  
	.Parameter ConfigurationCategory
	Configuration category object.
		 
 	.Example
	$Category = Get-AMConfigurationCategories -Name "CustomCategory"
	$Category.Name = "Custom Category"
 	Set-AMConfigurationCategory -ConfigurationCategory $Category
#>
function Set-AMConfigurationCategory
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.ConfigurationCategory]
		$ConfigurationCategory
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$ctg = Get-AMConfigurationCategory -Id $ConfigurationCategory.Id
		if ($ctg -ne $null) {
			$AMDataManager.EditConfigurationCategory($ConfigurationCategory.Id)
		}
		else {
			New-AMConfigurationCategory -ConfigurationCategory $ConfigurationCategory
		}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the existing or creates a new layer object.

	.Description
 	Sets (adds or modifies) a layer object to AutomationMachine share.
  
	.Parameter Layer
	Layer object.
		 
 	.Example
	$layer = Get-AMLayer -Name "desktop silo"
	$layer.Name = "Desktop Layer"
 	Set-AMLayer -Layer $layer
#>
function Set-AMLayer
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Layer]
		$Layer
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$lr = Get-AMLayer -Id $Layer.Id
		if ($lr -ne $null) {
			$AMDataManager.EditLayer($Layer.Id)
		}
		else {
			New-AMLayer -Layer $Layer
		}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Sets/assigns media to a package.

	.Description
 	Sets/assigns media to a package, or removes the currently assigned media.
  
	.Parameter Media
 	MediaInfo object to assign to the package.

    .Parameter Revision
    The revision of the media to assign to the package. If this is omitted, the first available revision will be used.

    .Parameter Package
    Package object to assign the media to.
    
	
 	.Example
    $Media = Get-AMMedia -Software "Windows Server" -Vendor "Microsoft" -Version "2012R2" -Language "2012R2"
    $Package = Get-AMPackage -Name "Example package"
    Set-AMMedia -Media $Media -Package $Package

    .Example   
    $Package = Get-AMPackage -Name "Example package"
    Get-AMMedia -Software "Windows Server" -Vendor "Microsoft" -Version "2012R2" -Language "2012R2" | Set-AMMedia -Package $Package -Revision 2

#>
function Set-AMMedia
{
	[CmdletBinding(DefaultParameterSetName="Default")]
	param
	(
		[parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true,Position=0)]
		[AutomationMachine.Data.MediaInfo]
		$Media,
        [parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false,Position=1)]
		[int]
		$Revision = 1,
        [parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$false,Position=2)]
		[AutomationMachine.Data.Package]
		$Package

	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

        
        $Revision = $Revision - 1
		If ($Package.MediaRevision -eq $null)
		{
			$Package.MediaRevision = New-Object AutomationMachine.Data.MediaRevision
		}
	    $Package.MediaRevision.MediaId = $Media.Id
	    $Package.MediaRevision.Revision = $Media.Revisions[$Revision]
        
        Edit-AMPackage -Package $Package
		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Sets service account for the current environment.

	.Description
 	Set-AMServiceAccount cmdlet sets and saves service account's credentials for the current environment.
  
	.Parameter Username
	User name of the service account.
	
	.Parameter Password
	Password of the service account.
		 
 	.Example
 	Set-AMServiceAccount -Username "SAUsername" -Password "SAPassword"
#>
function Set-AMServiceAccount
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[string]
		$Username,
		
		[parameter(mandatory=$true)]
		[string]
		$Password
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$ServiceAccount = New-Object AutomationMachine.Data.Types.Credentials($Username, $Password)
		$AMDataManager.Environment.ServiceAccount = $ServiceAccount
		$AMDataManager.EditServiceAccount()
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Sets a variable in the current environment.

	.Description
 	Sets (adds or modifies) a variable object in the current environment.
  
	.Parameter Variable
	Variable object.
	
	.Parameter Global
	The switch is only valid for new variables. It doesn't modify already created variable's globality. Use Global switch if variable should be added to the global variable list. Default value - false.
		 
 	.Example
	$Component = Get-AMPackage -Name "Adobe Reader X"
	$Variable = New-Object AutomationMachine.Data.Variable
	$Variable.Id = [System.Guid]::NewGuid()
	$Variable.ParentId = $Component.Id
	$Variable.Name = "MyVariable"
	$Variable.Type = [Type]::GetType("System.Int32")
	$Variable.Value = 55
 	Set-AMVariable -Variable $Variable -Component $Component
#>
function Set-AMVariable
{
	[CmdletBinding()]
	param 
	(
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Variable]
		$Variable
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


		$var = $AMDataManager.Environment.GetVariable($Variable.Id, $Variable.ParentId)
		if ($var -ne $null) {
			$AMDataManager.EditVariable($Variable)
		}
		else {
			if ($Variable.VariableScope -eq [AutomationMachine.Data.VariableScope]::Global) {
				New-AMVariable -Variable $Variable -Global
			}
			else {
				New-AMVariable -Variable $Variable
			}
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Saves changes of the specified VariableFilter object.

	.Description
 	Saves changes of the specified VariableFilter object to AutomationMachine share.
  
	.Parameter VariableFilter
	Variable filter object.
	
	.Parameter Component
	The parent component of the variable.
	
	.Parameter Environment
	The environment to which the parent of the variable belongs.
		 
 	.Example
 	Set-AMVariableFilter -VariableFilter $VariableFilter -Component $Component
#>
function Set-AMVariableFilter
{
	[CmdletBinding()]
	param 
	(
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.Component]
		$Component,
	
		[parameter(mandatory=$true)]
		[AutomationMachine.Data.VariableFilter]
		$VariableFilter
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$vf = $VariableFilter.Variable.VariableFilters | Where-Object { $_.Id -eq $VariableFilter.Id }
		if ($vf -ne $null) {
			$AMDataManager.EditVariableFilter($Component.Id, $VariableFilter)
		}
		else {
			New-AMVariableFilter -VariableFilter $VariableFilter -Component $Component
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Sets an override for the variable in the specified or current environment.
	
	.Description
	Sets (adds or modifies) an override for the variable in the specified or current environment.
	
	.Parameter OverriddenVariable
	OverriddenVariable object.
	
	.Parameter Scope
	A scope in which variable will be overridden (e.g., Collection, Computer).
	
	.Parameter ScopeElementId
	ID of the scope's element (e.g.: Collection ID, Computer ID, Package ID).
	
	.Parameter Element
	Element on which variable will be overridden (e.g.: Collection, Computer, Package, Plugin object).
	
	.Parameter Variable
	Variable which will be overridden.
	
	.Parameter Value
	Overridden value of the variable.
		 
	.Example
	$ElementId = $AMEnvironment.Collections | Where-Object { $_.Name -eq "Desktop Collection" } | % { $_.Id }
	$VariableId = New-Object AutomationMachine.Data.VariableId("516e3ed3-18e5-4622-a7fd-319009698a88", "7313eef5-9cb9-4811-92b2-98480a1cbdd3", $AMEnvironment)
	$OverriddenVariable = New-Object AutomationMachine.Data.OverriddenVariable
	$OverriddenVariable.VariableId = $VariableId
	$OverriddenVariable.Value = "C:\Programs"
	Set-AMVariableOverride -OverriddenVariable $OverriddenVariable -Scope Collection -ScopeElementId $ElementId
	
	.Example
	$Collection = Get-AMCollection -Name "Collection B"
	$Variable = Get-AMVariable -Name "ShutdownTimer"
	Set-AMVariableOverride -Element $Collection -Variable $Variable -Value 120
#>
function Set-AMVariableOverride
{
	[CmdletBinding(DefaultParameterSetName="Element")]
	param
	(
		[parameter(mandatory=$true,ParameterSetName="ElementId")]
		[AutomationMachine.Data.OverriddenVariable]
		$OverriddenVariable,
		
		[parameter(mandatory=$true,ParameterSetName="ElementId")]
		[AutomationMachine.Data.Scope]
		$Scope,
		
		[parameter(mandatory=$true,ParameterSetName="ElementId")]
		[System.Guid]
		$ScopeElementId,
		
		[parameter(mandatory=$true,ParameterSetName="Element")]
		[AutomationMachine.Data.Variable]
		$Variable,
		
		[parameter(mandatory=$true,ParameterSetName="Element")]
		[object]
		$Element,
		
		[parameter(mandatory=$true,ParameterSetName="Element")]
		[object]
		$Value
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		switch ($PSCmdlet.ParameterSetName) {
			"ElementId" {
				$AMDataManager.SetVariableOverride($OverriddenVariable, $Scope, $ScopeElementId)
				break
			}
			"Element" {
				$AMDataManager.SetVariableOverride($Element, $Variable, $Value)
				break
			}
		}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Tests the client host name.

	.Description
 	Tests if the client host name is like the supplied computername.
  
	.Parameter ClientHostname
 	The clienthostname to test for. Wildcards are supported
  
 	.Example
 	"testcomp*" | Test-AMClientHostname
 	
 	.Example
 	Test-AMClientHostname -ClientHostname "testcomputer"
#>
function Test-AMClientHostname
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$ClientHostname
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		return $env:CLIENTNAME -like $ClientHostname
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests if the computer is in a collection.

	.Description
 	Tests if the computer is in the collection specified. Wildcards are supported.
  
	.Parameter CollectionName
 	The CollectionName to test for.
	
 	.Example
 	"Desktop Sil*" | Test-AMCollection
 	
 	.Example
 	Test-AMCollection -CollectionName "Legacy Silo"
#>
function Test-AMCollection
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$CollectionName
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$Collection = Get-AMCollection -Current
		return $Collection.Name -like $CollectionName
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the collectiontype.

	.Description
 	Tests if the collection's collectiontyp is like the supplied collectiontype.
  
	.Parameter CollectionType
 	The collectiontype to test for. Wildcards are supported
  
 	.Example
 	"RDS*" | Test-AMCollectionType
 	
 	.Example
 	Test-AMCollectionType -CollectionType "Generic Server"
#>
function Test-AMCollectionType
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$CollectionType
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		$EvtMap = Get-AMEventMap -Current
		return $EvtMap.Name -like $CollectionType
		
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the computer domain.

	.Description
 	Tests if the computerdomain is  like the supplied computerdomain.
  
	.Parameter DomainName
 	The DomainName to test for. Wildcards are supported
  
 	.Example
 	"testdom*" | Test-AMComputerDomain
 	
 	.Example
 	Test-AMComputerDomain -DomainName "testdomain"
#>
function Test-AMComputerDomain
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$DomainName
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	
		return $(Get-AMComputerDomain) -like $DomainName

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests day of week.

	.Description
 	Tests if today is the day of week specified.
  
	.Parameter DayOfWeek
 	The dayofweek to test for.
  
 	.Example
 	"Monday" | Test-AMDayOfWeek
 	
 	.Example
 	Test-AMEnvVar -DayOfWeek "Tuesday"
#>
function Test-AMDayOfWeek
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$DayOfWeek
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		return (get-date | %{$_.DayOfWeek}) -eq $DayOfWeek
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the environment id.

	.Description
 	Tests if the environment id is like the supplied id.
  
	.Parameter EnvironmentId
 	The environment id to test for. Valid values are: Development, Test, Acceptance, Production
  
 	.Example
 	"af7fb8de-66fa*" | Test-AMEnvironmentId
 	
 	.Example
 	Test-AMEnvironmentId -EnvironmentId "af7fb8de-66fa-4691-9825-36baddde4336"
#>
function Test-AMEnvironmentId
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$EnvironmentId
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return $AMEnvironment.Id -like $EnvironmentId
		
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the environment name.

	.Description
 	Tests if the environment name is like the supplied name.
  
	.Parameter EnvironmentName
 	The environment name to test for. Wildcards are supported
  
 	.Example
 	"RDS*" | Test-AMEnvironmentName
 	
 	.Example
 	Test-AMEnvironmentName -EnvironmentName "RDS Test Environment"
#>
function Test-AMEnvironmentName
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$EnvironmentName
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return $AMEnvironment.Name -like $EnvironmentName
		
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the environment type.

	.Description
 	Tests if the environment type is like the supplied type.
  
	.Parameter EnvironmentType
 	The environment type to test for. Valid values are: Development, Test, Acceptance, Production
  
 	.Example
 	"Developm*" | Test-AMEnvironmentType
 	
 	.Example
 	Test-AMEnvironmentType -EnvironmentType "Test"
#>
function Test-AMEnvironmentType
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$EnvironmentType
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return $AMEnvironment.Type -like $EnvironmentType
		
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests an environment variable.

	.Description
 	Tests if the environment variable has a value like the supplied value.
  
	.Parameter EnvVar
 	The hostname to test for. Wildcards are supported
  
 	.Example 
 	"COMPUTERNAME:TESTCOMPUTER" | Test-AMEnvVar
 	
 	.Example
 	Test-AMEnvVar -EnvVar "COMPUTERNAME:TESTCOMPUTER"
#>
function Test-AMEnvVar
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$EnvVar
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		$var = $EnvVar.Split(":",2)
		return [System.Environment]::GetEnvironmentVariable($var[0]) -like $var[1]
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the event name.

	.Description
 	Tests if the event name is like the supplied name.
  
	.Parameter Event
 	The event name to test for.
  
 	.Example
 	"reboot" | Test-AMEvent
 	
 	.Example
 	Test-AMEvent -Event "logoff"
#>
function Test-AMEvent
{

	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Event
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return ($env:am_evt_name -eq $Event)		
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests a file or folder exists.

	.Description
 	Tests if the supplied file/folder exists.
  
	.Parameter Path
 	The path to test for. 
  
 	.Example
 	"C:\Windows" | Test-AMFileExist
 	
 	.Example
 	Test-AMFileExist -Path "C:\Windows\system32\notepad.exe"
#>
function Test-AMFileExist
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Path
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return Test-Path $Path
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the computername.

	.Description
 	Tests if the computername is like the supplied computername.
  
	.Parameter Hostname
 	The hostname to test for. Wildcards are supported
  
 	.Example
 	"testcomp*" | Test-AMHostname
 	
 	.Example
 	Test-AMHostname -Hostname "testcomputer"
#>
function Test-AMHostname
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Hostname
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return $env:COMPUTERNAME -like $Hostname
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the ip address

	.Description
 	Tests if the ip address of the computer matches the ip address that was supplied.
  
	.Parameter IPAddress
 	The IPAddress to test for. Both v4 and v6 addresses are supported
  
 	.Example
 	"192.168.0.1" | Test-AMIPAddress
 	
 	.Example
 	Test-AMIPAddress -IPAddress "2001:981:4352:1:6037:a0b9:8f5d:b6c1"
#>
function Test-AMIPAddress
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$IPAddress
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		if ($(Get-WMIObject Win32_NetworkAdapterConfiguration | where-object {$_.IPAddress -like "$ipaddress"}))
		{
			return $true
		} 
		else 
		{
			return $false
		}
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the group membership of a user/computer.

	.Description
 	Tests if the logged on user is member of a certain group, if script is run under service account, the computername is used.
  
	.Parameter Group
 	The groupname to test for. Wildcards are supported
  
 	.Example
 	"AM\Domain Users" | Test-AMMemberOf
 	
 	.Example
 	Test-AMMemberOf -Group "AM\Domain Users"
#>
function Test-AMMemberOf
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Group
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
            $AMEnvironment = $AMDataManager.ReadEnvironment($AMEnvironment.Id,$true)
			if (!$AMEnvironment.ServiceAccount) {$SA = $null} elseif ($AMEnvironment.ServiceAccount.Username) {$SA = $AMEnvironment.ServiceAccount.UserName} else {$SA = $null}
			if ($env:username -ne $SA)
			{
				return ([System.Security.Principal.WindowsPrincipal]([System.Security.Principal.WindowsIdentity]::GetCurrent())).isinrole($group.Replace("*\",""))
			}
			else
			{
				$domainDN = Get-AMDomainDN
				$rootEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$domainDN")
				$searcher = New-Object DirectoryServices.DirectorySearcher($rootEntry,"(&(objectClass=computer)(cn=$env:computername))")
				$myObject = ($searcher.FindOne()).GetDirectoryEntry()
								
				if ($myObject.memberOf | Where-Object {$_ -like "cn=$group,*"})
				{
					return $true
				}
				else
				{
					return $false
				}
						
			}
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests if the computername is odd or even.

	.Description
 	Tests if the computername is odd or even.
  
	.Parameter OddEven
 	The variant to test for. Supported values Odd and Even.
	
	.NOTES
	The last integer in the computername will be tested for odd or even. E.g. Computer21 will be evaluated as Odd, 2Computer will be evaluated as Even.
	  
 	.Example
 	"Odd" | Test-AMOddEven
 	
 	.Example
 	Test-AMOddEven -OddEven "Even"
#>
function Test-AMOddEven
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[ValidateSet("Odd","Even")]
		[string]
		$OddEven
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		$env:COMPUTERNAME.GetEnumerator() | Where-Object {[int]::TryParse($_,[ref]$Null)} | ForEach-Object {$i = $_}
		if (!(Test-Path Variable:i)) {return $false}
		[int]$Remainder = 0
		$Remainder = $i%2
		if ($Remainder -ne 0)
		{
			$OddEven2 = "Odd"
		}
		else
		{
			$OddEven2 = "Even"
		}
			
		return $OddEven.ToLower() -eq $OddEven2.ToLower()
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the OS architecture

	.Description
 	Tests the OS architecture, return true or false
  
	.Parameter OSArch
 	The OSArch to test for, only x64 and x86 are supported
  
 	.Example
 	"x86" | Test-AMOSArch
 	
 	.Example
 	Test-AMOSArch -OSArch "x64"
#>
function Test-AMOSArch
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[ValidateSet("x64","x86")]
		[string]
		$OSArch
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		if (Test-Path "env:programfiles(x86)") { $arch = "x64" } else { $arch = "x86" }

		return $arch -like $OSArch
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the OS language

	.Description
 	Tests if the OS language is set to the OSLang specified.
  
	.Parameter OSLang
 	The OS Language to test for.
  
 	.Example
 	1033 | Test-AMOSLang
 	
 	.Example
 	Test-AMOSLang -OSLang 1033
#>
function Test-AMOSLang
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$OSLang
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return (get-wmiobject win32_operatingsystem).OSLanguage -like $OSLang
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the OS name.

	.Description
 	Tests if the OS name matches the name specified.
  
	.Parameter OSName
 	The OSName to test for. 
 	
	.Example
 	Test-AMOSname "* Windows 8.1 *"
 	
 	.Example
 	Test-AMOSName -OSName "Microsoft Windows 8.*"
#>
function Test-AMOSName
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$OSName
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
        $name = (Get-WmiObject win32_operatingsystem).Name.Split("|")[0]
		return $name -like $OSName			
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the OS version.

	.Description
 	Tests if the OS version matches the version specified.
  
	.Parameter OSVersion
 	The OSVersion to test for. 
 	
	.Example
 	"6.1.*" | Test-AMOSVersion
 	
 	.Example
 	Test-AMOVersion -OSVersion "6.2.*"
#>
function Test-AMOSVersion
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$OSVersion
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return (Get-WmiObject win32_operatingsystem).Version -like $OSVersion			
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the OU membership of a computer.

	.Description
 	Tests if the computer is member of a certain OU.
  
	.Parameter OU
 	The Organizational Unit to test for.
  
 	.Example
 	"AM\Domain Controllers" | Test-AMOU
 	
 	.Example
 	Test-AMOU -OU "AM\Domain Controllers"
#>
function Test-AMOU
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$OU
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
			if ($OU -eq $null)
			{
				throw "Parameter cannot be empty"
			}
			else
			{
				try
				{
					$currentLDAP = Get-AMLDAPPath -Name $env:COMPUTERNAME
					$currentLDAP = [System.Text.RegularExpressions.Regex]::Replace($currentLDAP,"LDAP://","",[System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
					$ADTokens = $currentLDAP.Split(",").Trim()
					$ADTokensFilteredToOUTokens = $ADTokens | ? {$_.StartsWith("OU")} | % {$_.TrimStart("OU=")}
					$OUTokens = $OU.Split("\").Trim()
					
					foreach($token in $OUTokens)
					{
						if($ADTokensFilteredToOUTokens -notcontains $token)
						{
							return $false
						}
					}				
					return $true			
				}
				catch
				{
					return $false
				}
			}
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests if a registry key, property exists and if it's set to certain data.

	.Description
 	Tests if the registry key exists, if property exists and if property has a correct value
  
	.Parameter Path
    The registry key path to test for.
     
    .Parameter Property
    The registry key property to test for.
     
    .Parameter Value
 	The registry key property value to test for.
	
 	.Example
 	"HKLM:Software\Microsoft\Windows\CurrentVersion:CommonFilesDir:C:\Program Files\Common Files" | Test-AMRegistry
 	
 	.Example
	Test-AMRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' -Property 'CountryCode' -Value 'LT'

	.Example
	Test-AMRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' -Property 'CountryCode'
	
	.Example
	Test-AMRegistry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
#>
function Test-AMRegistry {
    param
    (
        [cmdLetbinding()]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]$Path,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]$Property,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNullorEmpty()]$Value
    )
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
    try {

        $KeyPath = Convert-AMRegistryPath -Path $Path
        [boolean]$RegistryExists = $false

        if (Test-Path -Path $KeyPath -PathType Container) {
            if ($Property) {
                if ($KeyProperty = Get-ItemProperty -Path $KeyPath -Name $Property -ErrorAction Ignore) {
                    if ($Value) {
                        if ((Compare-Object -ReferenceObject $Value -DifferenceObject $($KeyProperty.$Property)).Length -eq 0) {
                            $RegistryExists = $true
                        }                        
                    }
                    else {
                        $RegistryExists = $true
                    }
                }                
            }
            else {
                $RegistryExists = $true
            }                        
        }

        return $RegistryExists

    }
    catch [Exception] {
        return $false
    }
		
    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests if a registry key exists.

	.Description
 	Tests if a registry key specified exists.
  
	.Parameter RegPath
 	The Registry Path to test for.
	
 	.Example
 	"HKLM:Software\Microsoft" | Test-AMRegKeyExist
 	
 	.Example
 	Test-AMRegKeyExist "HKLM:Software\Microsoft"
#>
function Test-AMRegKeyExist
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$RegPath
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		$RegPath = Convert-AMRegistryPath -Path $RegPath
		return Test-Path $RegPath
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests if a registry value exists.

	.Description
 	Tests if a registry value specified exists.
  
	.Parameter RegPath
 	The Registry Path to test for.
	
 	.Example
 	"HKLM:Software\Microsoft:License" | Test-AMRegValExist
 	
 	.Example
 	Test-AMRegValExist "HKLM:Software\Microsoft:License"
#>
function Test-AMRegValExist {
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory = $false, ValueFromPipeline = $true, Position = 0)]
		[string]
		$RegPath
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try {
		$RegistryValue = $RegPath.Split(':') | Select-Object -Last 1
		
		$RegistryPathWithoutValue = $RegPath -replace ":$RegistryValue", ''
				
		$FullRegistryPath = Convert-AMRegistryPath -Path $RegistryPathWithoutValue
		
		if (Test-Path $FullRegistryPath) {
			$null -ne (Get-ItemProperty $FullRegistryPath).$RegistryValue
		}
		else {	
			return $false
		}
	}
	catch [Exception] {
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests if a registry value is set to certain data.

	.Description
 	Tests if the registry value specified has the data specified.
  
	.Parameter RegPath
 	The Registry Path to test for.
	
 	.Example
 	"HKLM:Software\Microsoft\Windows\CurrentVersion:CommonFilesDir:C:\Program Files\Common Files" | Test-AMRegValue
 	
 	.Example
	 Test-AMRegValue "HKLM:Software\Microsoft\Windows\CurrentVersion:CommonFilesDir:C:\Program Files\Common Files"

	.Example
 	$RegValues = 'C:\Code\LoginAM-Source\config'
	Test-AMRegValue -KeyPath "HKLM:SOFTWARE\Automation Machine" -ValueName "AMCentralPath" -ValueData $RegValues
	
	.Example
	$RegValues = @("ServiceControlManager","WinInit")
	Test-AMRegValue -KeyPath "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager" -ValueName "RunLevelExecute" -ValueData $RegValues
#>
function Test-AMRegValue {
    param
    (
        [cmdLetbinding(DefaultParameterSetName = 'default')]
        [parameter(ParameterSetName = 'default', mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]
        $RegPath,

        [parameter(ParameterSetName = 'extended', mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $KeyPath,

        [parameter(ParameterSetName = 'extended', mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $ValueName,

        [parameter(ParameterSetName = 'extended', mandatory = $false, ValueFromPipeline = $false)]
        [array]
        $ValueData
    )
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
    try {
        if ($RegPath) {
			$RegPath = Convert-AMRegistryPath -Path $RegPath
            $RegSplitResult = $RegPath.Split(':', 5)
			$RegistryPath = "$($RegSplitResult[0])::$($RegSplitResult[1])$($RegSplitResult[2])"

            if (Test-Path $RegistryPath) {
                $RegSplitResult[4] -like (Get-ItemProperty $RegistryPath).$($RegSplitResult[3])
            }
            else {	
                return $false
            }
        }
        else {
			$KeyPath = Convert-AMRegistryPath -Path $KeyPath
            if (Test-Path $KeyPath) {
                @(Compare-Object $ValueData $((Get-ItemProperty $KeyPath).$ValueName)).Length -eq 0
            }
            else {
                return $false
            }
        }
    }
    catch [Exception] {
        return $false
    }
		
    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the service startmode

	.Description
 	Tests if the servicestartmode is set to the servicestartmode specified.
  
	.Parameter ServiceStartMode
 	The ServiceStartMode to test for.
  
 	.Example
 	"Spooler:auto" | Test-AMServiceStartMode
 	
 	.Example
 	Test-AMServiceStartMode -ServiceStartMode "spooler:disabled"
#>
function Test-AMServiceStartMode
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$ServiceStartMode
	)

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		$service = $ServiceStartMode.Split(':',2)
			
		$ServiceExists = get-service -name "$($service[0])" -ea silentlycontinue
		If ($ServiceExists -ne $null)
		{

			$ret = (Get-WmiObject win32_service -filter "name='$($ServiceExists.Name)'").StartMode

			return $ret -like $service[1]
		}
		else
		{
			return $false
		}
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the service status

	.Description
 	Tests if the servicestatus is set to the servicestatus specified.
  
	.Parameter ServiceStatus
 	The ServiceStatus to test for.
  
 	.Example
 	"Spooler:running" | Test-AMServiceStatus
 	
 	.Example
 	Test-AMServiceStatus -ServiceStatus "spooler:stopped"
#>
function Test-AMServiceStatus
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$ServiceStatus
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		$service = $servicestatus.Split(':',2)
		# check if service exists
		$ServiceExists = get-service -name "$($service[0])" -ErrorAction SilentlyContinue
		if ($ServiceExists -ne $null)
		{
			$ret = (get-service "$($service[0])").Status
			if ($ret -like $service[1])
			{
				return $true
			} 
			else 
			{
				return $false
			}
		}
		else
		{
			return $false
		}
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the service pack version

	.Description
 	Tests if the SP version is the same as the version specified.
  
	.Parameter SPVersion
 	The SP version to test for.
  
 	.Example
 	2 | Test-AMSPVersion
 	
 	.Example
 	Test-AMSPVersion -SPVersion 2
#>
function Test-AMSPVersion
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$SPVersion
	)
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return (get-wmiobject win32_operatingsystem).ServicePackMajorVersion -like $SPVersion
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the UI language

	.Description
 	Tests if the UI language is set to the UILang specified.
  
	.Parameter UILang
 	The UI Language to test for.
  
 	.Example
 	1033 | Test-AMUILang
 	
 	.Example
 	Test-AMUILang -UILang 1033
#>
function Test-AMUILang
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[int]
		$UILang
	)

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return $(Get-UICulture).LCID -like "$UILang"
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests the username

	.Description
 	Tests if the logged on username is like the supplied username.
  
	.Parameter Username
 	The username to test for. Wildcards are supported
  
 	.Example
 	"testus*" | Test-AMUsername
 	
 	.Example
 	Test-AMUsername -Username "testuser"
#>
function Test-AMUsername
{
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string]
		$Username
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		return $env:username -like $Username
	}
	catch [Exception]
	{
		return $false
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Gets high availability settings for the RD Connection Broker server in a Remote Desktop deployment.

	.Description
	The Get-RDConnectionBrokerHighAvailability cmdlet gets high availability settings for the Remote Desktop Connection
	Broker (RD Connection Broker) server in a Remote Desktop deployment. The cmdlet displays the following settings:

	-- ActiveManagementServer. Current active management server in the highly available RD Connection Broker server list.
	-- ConnectionBroker. List of RD Connection Broker servers.
	-- ClientAccessName. Client access name for the group of RD Connection Broker servers.
	-- DatabaseConnectionString. Database connection string of the central database that stores the configuration.
	-- DatabaseFilePath. File path for the database specified by the database connection string.

	.Parameter ConnectionBroker
	Specifies the RD Connection Broker server for a Remote Desktop deployment. If you do not specify a value, the
	cmdlet uses the fully qualified domain name (FQDN) of the local computer.

	.Parameter Retry
	If connection fails the cmdlet retries to connect the specified amount of times.

	.Parameter RetryIntervalSeconds
	Amount of seconds to wait between retry attempts.

	.Example
	$HA = Get-AMRDConnectionBrokerHighAvailability -ConnectionBroker $Connbroker -Retry 3 -RetryIntervalSeconds 60
#>
function Get-AMRDConnectionBrokerHighAvailability {
    
    [CmdletBinding()]
	param 
	(
        [Parameter(Mandatory=$true)]
        [string] $ConnectionBroker,

        [Parameter(Mandatory=$false)]
        [int] $Retry = 1,

        [Parameter(Mandatory=$false)]
        [int] $RetryIntervalSeconds = 1
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    $HighAvailability = $null
    $CheckAvailability = ((Get-RDServer -ConnectionBroker $ConnectionBroker | Where-Object {$_.Roles -like "*broker*"} | Measure-Object).Count) -gt 1
    if ($CheckAvailability -eq $true)
    {
        $retryCount = 0
        $maxRetryCount = $Retry
        do {
            $HighAvailability = Get-RDConnectionBrokerHighAvailability -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue
            if ($HighAvailability -eq $null) {
                $retryCount++
                Write-Warning "Trying to get high availability settings for $ConnectionBroker. Attempt $retryCount of $maxRetryCount."
                if ($retryCount -ge $maxRetryCount) {
                    break
                }
                else {
                    Start-Sleep -Seconds $RetryIntervalSeconds
                }
            }
        }
        while ($HighAvailability -eq $null)
    }

    return $HighAvailability

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

    
}

<#
.SYNOPSIS
Gets RemoteApp programs in a Remote Desktop deployment.

.DESCRIPTION
The Get-AMRDRemoteApp cmdlet gets RemoteApp programs in a Remote Desktop deployment.
You can specify a collection name, an alias, or one or more display names.

.PARAMETER Alias
Specifies an alias for a RemoteApp program.

.PARAMETER ConnectionBroker
Specifies the Remote Desktop Connection Broker (RD Connection Broker) server for a Remote Desktop deployment.
If you do not specify a value, the cmdlet uses the fully qualified domain name (FQDN) of the local computer.

.PARAMETER CollectionName
Specifies the name of a personal virtual desktop collection or session collection.

.EXAMPLE
Get-AMRDRemoteApp -CollectionName "My RDS Collection"
#>
function Get-AMRDRemoteApp {
    [CmdletBinding()]
    param(
        [parameter(mandatory=$true)]
        [string] $CollectionName,

        [parameter(mandatory=$false)]
        [string] $Alias,

        [parameter(mandatory=$false)]
        [string] $ConnectionBroker
    )

    $Result = $null

    $RemoteDesktopModuleName = "RemoteDesktop"
    $IsRemoteDesktopModuleAvailable = $false

    # Check if RemoteDesktop module is not loaded yet
    if ((Get-Module -Name $RemoteDesktopModuleName) -ne $null) {
        $IsRemoteDesktopModuleAvailable = $true
    }
    # Check if RemoteDesktop module is available and load it
    elseif ((Get-Module -ListAvailable -Name $RemoteDesktopModuleName) -ne $null) {
        Import-Module $RemoteDesktopModuleName
        $IsRemoteDesktopModuleAvailable = $true
    }

    # Get-RDRemoteApp function exists, probably the OS is Windows >= 2016
    if ((Test-Path Function:\Get-RDRemoteApp) -eq $true) {
        $Result = Get-RDRemoteApp -Alias $Alias -ConnectionBroker $RDCB -CollectionName $CollectionName
    }
    # Get-RemoteApp function exists, probably the OS is Windows < 2016
    elseif ((Test-Path Function:\Get-RemoteApp) -eq $true) {
        $Result = Get-RemoteApp -Alias $Alias -ConnectionBroker $ConnectionBroker -Collection $CollectionName
    }
    # None of the functions are available and RemoteDesktop module is not available and the result is null
    elseif ($IsRemoteDesktopModuleAvailable -eq $false) {
        Write-AMWarning "RemoteDesktop PowerShell module is not available. Please install it and try again."
    }
    # Should never happen, but just in case
    else {
        Write-AMWarning "RemoteDesktop PowerShell module is available, but none of Get-RDRemoteApp or Get-RemoteApp functions exist."
    }

    return $Result
}

<#
    .Synopsis
    Gets a list of RD Session Host servers in a session collection.

	.Description
    The Get-AMRDSessionHost cmdlet gets a list of Remote Desktop Session Host (RD Session Host) servers in a session
    collection. RD Session Host is a Remote Desktop Services role service that lets users share Windows-based programs
    or the full Windows desktop. Users can connect to an RD Session Host server to run programs, save files, and use
    network resources on that server.

    .Parameter SessionHost
    Specifies the name of RD Session Host server.

	.Parameter ConnectionBroker
    Specifies the Remote Desktop Connection Broker (RD  Connection Broker) server for this Remote Desktop deployment.

	.Example
	$SessionHost = Get-AMRDSessionHost -SessionHost $SessionHostName -ConnectionBroker $ConnectionBroker
#>
function Get-AMRDSessionHost {
    
    [CmdletBinding()]
	param 
	(
        [Parameter(Mandatory=$true)]
        [string] $SessionHost,

        [Parameter(Mandatory=$true)]
        [string] $ConnectionBroker
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    $CollectionAlias = (Get-WMIObject -Namespace root\cimv2\terminalservices -Class Win32_TSSessionDirectory -Authentication PacketPrivacy -Impersonation Impersonate).SessionDirectoryClusterName
    # RD Session collection name
    $CollectionName = (Get-WMIObject -Namespace root\cimv2\rdms -class Win32_RDSHCollection -Computername $ConnectionBroker -Authentication PacketPrivacy -Impersonation Impersonate | Where-Object {$_.Alias -eq $CollectionAlias}).Name

    $ConfiguredSessionHosts = Get-RDSessionHost -CollectionName $CollectionName -ConnectionBroker $ConnectionBroker -ErrorAction SilentlyContinue

    return $ConfiguredSessionHosts | Where-Object {$_.SessionHost -like $SessionHost}

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

    
}

<#
	.Synopsis
	Creates a new RemoteApp.

	.Description
 	Creates a new RemoteApp in Windows RDS 2012 R2
  
	.Parameter DisplayName
 	The displayname of the RemoteApp to create.
	
	.Parameter Alias
	The alias of the RemoteApp to create, if not alias is supplied, the basename of the program is used.
	
	.Parameter FilePath
	The path to the program to publish
	
	.Parameter ShowInWebAccess
	Specifies whether or not the RemoteApp is visible in WebAccess
	
	.Parameter Folder
	The folder where to put the RemoteApp in WebAccess
	
	.Parameter Arguments
	The commandline arugments for the program
	
	.Parameter IconPath
	The location of the icon file, if not provided the default icon for the program will be used
	
	.Parameter IconIndex
	The index of the icon in the icon file.
	
	.Parameter UserGroups
	Array of usergroups to add to the RemoteApp
	
	.Parameter PublishFileTypes
	Determines if filetypes are published for this remoteapp.

	.Parameter Collection
	The name of the collection where to put this RemoteApp in.
	
	.NOTES
	Only supported on Windows Server 2012R2 RD Session Hosts
	
 	.Example
 	New-AMRemoteApp -DisplayName Calculator -FilePath C:\windows\system32\calc.exe -ShowInWebAccess $false
	
	.Example
 	New-AMRemoteApp -DisplayName Calculator -FilePath C:\windows\system32\calc.exe -ShowInWebAccess $false -UserGroups @("Domain Users","Domain Admins") -FileExtensionMode "Automatic"
	
	.Example
 	New-AMRemoteApp -DisplayName Calculator -FilePath C:\windows\system32\calc.exe -ShowInWebAccess $false -UserGroups @("Domain Users","Domain Admins") -FileExtensionMode "Manual" -FileExtensions @(".txt",".log")
	
#>
function New-AMRemoteApp
{
	[cmdLetbinding()]
	param
	(	
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=0)]
		[string]
		$DisplayName,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=1)]
		[string]
		$Alias,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=2)]
		[string]
		$FilePath,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=3)]
		[boolean]
		$ShowInWebAccess = $false,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=4)]
		[string]
		$Folder,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=5)]
		[string]
		$Arguments,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=6)]
		[string]
		$IconPath,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=7)]
		[string]
		$IconIndex = 0,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=8)]
		[string[]]
		$UserGroups,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=9)]		
		[Boolean]
		$PublishFileTypes = $true,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=10)]
		[string]
		$Collection,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=11)]
		[string]
		$ArgumentPermissions
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

			# Initialization
            Write-AMInfo "Initializing RemoteApp creation"
			If (!(Get-Module RemoteDesktop)) {Import-Module RemoteDesktop}
			# Get connectionbroker and CollectionName			
			$RDCB = (Get-WMIObject -Namespace root\cimv2\terminalservices -Class Win32_TSSessionDirectory).SessionDirectoryLocation
			Write-Verbose "Collection broker: $RDCB"
			$ValidCollection = Get-RDSessionCollection -ConnectionBroker $RDCB -CollectionName $Collection
			Write-Verbose "Collection $Collection was found"
			# Check if filepath exists
			If (!(Test-Path $FilePath)) {throw "$FilePath is not a valid path, unable to publish RemoteApp"}
			
			# Construct the proper commandline
			$CommandLineEx = @{}
			$CommandLineEx.Add("ConnectionBroker", $RDCB)
            $CommandLineEx.Add("CollectionName", $Collection)
			
			$CommandLineEx.Add("FilePath", $FilePath)
			$CommandLineEx.Add("Alias", $Alias)
			$CommandLineEx.Add("DisplayName",$DisplayName)
			$CommandLineEx.Add("ShowInWebAccess",$ShowInWebAccess)
			
			If (!([string]::IsNullOrEmpty($Folder)))
			{
				$CommandLineEx.Add("FolderName", $Folder)
			}
			
			$CommandLineSetting = $ArgumentPermissions # DoNotAllow,Required or Allow is possible. When arguments are specified, it should be set to Required
			If (!([string]::IsNullOrEmpty($Arguments)))
			{
				$CommandLineSetting = "Require"
				$CommandLineEx.Add("RequiredCommandLine", $Arguments)				
			}
			$CommandLineEx.Add("CommandLineSetting", $CommandLineSetting)
			
			if (!([string]::IsNullOrEmpty($UserGroups)))
			{
				$CommandLineEx.Add("UserGroups", $UserGroups)
			}
			if (!([string]::IsNullOrEmpty($IconPath)))
			{
				$CommandLineEx.Add("IconPath",$IconPath)
				$CommandLineEx.Add("IconIndex",$IconIndex)
			}
			Write-AMInfo "Creating RemoteApp $DisplayName"
			
			# Create the RemoteApp
			$Result = Get-AMRDRemoteApp -ConnectionBroker $RDCB -CollectionName $Collection -Alias $Alias
			if ($Result -isnot [Object])
			{
				$Result = New-RDRemoteApp @CommandLineEx
			}
			else
			{
				Write-AMInfo "Another server has already created this RemoteApp, skipping creation..."
			}
			
			#Set file extensions
			If ($PublishFileTypes -eq $False)
			{
				Write-AMInfo "Checking FileType associations for $Alias"
				$FileTypes = Get-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -ConnectionBroker $RDCB
				if ($($FileTypes).IsPublished -Contains $True) {
					$FileTypes | ForEach-Object {
						Write-AMInfo "Disabling FileType Associations for $Alias"
						Set-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -FileExtension $_.FileExtension -IsPublished $False -ConnectionBroker $RDCB
					}
				}
			}
						
			If ($PublishFileTypes -eq $True)
			{
				#Get file extensions for path and add them
				Write-AMInfo "Checking FileType Associations for $Alias"
				$FileTypes = Get-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -ConnectionBroker $RDCB
				if ($($FileTypes).IsPublished -Contains $False) {
					$FileTypes | ForEach-Object {
						Write-AMInfo "Enabling FileType Associations for $Alias"
						Set-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -FileExtension $_.FileExtension -IsPublished $True -ConnectionBroker $RDCB
					}
				}
			}
		
			
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Configures the specified RD Session Host servers in a session collection.

	.Description
    The Set-AMRDSessionHost cmdlet configures the specified Remote Desktop Session Host (RD Session Host) server in 
    a session collection by specifying whether the server can accept new connections. RD Session Host is a Remote
    Desktop Services role service that lets users share Windows-based programs or the full Windows desktop. Users can
    connect to a RD Session Host server to run programs, save files, and use network resources on that server.

    .Parameter SessionHost
    Specifies the name of RD Session Host server that you configure.

	.Parameter ConnectionBroker
    Specifies the Remote Desktop Connection Broker (RD Connection Broker) server for this Remote Desktop deployment.
    
    .Parameter NewConnectionAllowed
    Determines whether the RD Session Host server specified by the SessionHost parameter can accept new connections.
    The acceptable values for this parameter are:  Yes, NotUntilReboot, or No.

	.Parameter Retry
	If configuration fails the cmdlet retries to configure RD Session Host the specified amount of times.

	.Parameter RetryIntervalSeconds
	Amount of seconds to wait between retry attempts.

	.Example
	$ConfiguredSessionHost = Set-AMRDSessionHost -SessionHost $SessionHost-ConnectionBroker $ConnectionBroker -NewConnectionAllowed "Yes" -Retry 3 -RetryIntervalSeconds 10
#>
function Set-AMRDSessionHost {
    
    [CmdletBinding()]
	param 
	(
        [Parameter(Mandatory=$true)]
        [string] $SessionHost,

        [Parameter(Mandatory=$true)]
        [string] $ConnectionBroker,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Yes", "NotUntilReboot", "No")]
        [string] $NewConnectionAllowed,

        [Parameter(Mandatory=$false)]
        [int] $Retry = 1,

        [Parameter(Mandatory=$false)]
        [int] $RetryIntervalSeconds = 1
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    #Write-AmInfo "Setting NewConnectionAllowed to $NewConnectionAllowed for $SessionHost (Connection Broker: $ConnectionBroker)"
    $ConfiguredSessionHost = $null
    $retryCount = 0
    $maxRetryCount = $Retry
    do {
        try {
            Set-RDSessionHost -SessionHost $SessionHost -ConnectionBroker $ConnectionBroker -NewConnectionAllowed $NewConnectionAllowed
            Start-Sleep -Seconds 3 
        }
        catch {
            Write-Warning $_.Exception.Message
        }
        $ConfiguredSessionHost = Get-AMRDSessionHost -SessionHost $SessionHost -ConnectionBroker $ConnectionBroker
        if ($ConfiguredSessionHost -eq $null -or $ConfiguredSessionHost.NewConnectionAllowed -ne $NewConnectionAllowed) {
            $retryCount++
            #Write-Warning "Trying to set NewConnectionAllowed to $NewConnectionAllowed for $SessionHost (Connection Broker: $ConnectionBroker). Attempt $retryCount of $maxRetryCount."
            Write-Warning "Setting logon mode has failed, retrying.... Attempt $retryCount of $maxRetryCount."
            if ($retryCount -ge $maxRetryCount) {
                #Write-AMError "Configurig RD Session Host `"$SessionHost`" failed."
                Write-AMError "Setting logon mode has failed"
                break
            }
            else {
                Start-Sleep -Seconds $RetryIntervalSeconds
            }
        }
    }
    while ($ConfiguredSessionHost -eq $null -or $ConfiguredSessionHost.NewConnectionAllowed -ne $NewConnectionAllowed)

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

    
}

<#
	.Synopsis
	Sets/updates a RemoteApp.

	.Description
 	Sets/updates a RemoteApp in Windows RDS 2012 R2
  
	.Parameter DisplayName
 	The displayname of the RemoteApp to create.
	
	.Parameter Alias
	The alias of the RemoteApp to create, if not alias is supplied, the basename of the program is used.
	
	.Parameter FilePath
	The path to the program to publish
	
	.Parameter ShowInWebAccess
	Specifies whether or not the RemoteApp is visible in WebAccess
	
	.Parameter Folder
	The folder where to put the RemoteApp in WebAccess
	
	.Parameter Arguments
	The commandline arugments for the program
	
	.Parameter IconPath
	The location of the icon file, if not provided the default icon for the program will be used
	
	.Parameter IconIndex
	The index of the icon in the icon file.
	
	.Parameter UserGroups
	Array of usergroups to add to the RemoteApp
	
	.Parameter PublishFileTypes
	Determines if filetypes are published for this remoteapp.

	.Parameter Collection
	The name of the collection where to put this RemoteApp in.
	
	.NOTES
	Only supported on Windows Server 2012R2 RD Session Hosts
	
 	.Example
 	Set-AMRemoteApp -DisplayName Calculator -FilePath C:\windows\system32\calc.exe -ShowInWebAccess $false
	
	.Example
 	Set-AMRemoteApp -DisplayName Calculator -FilePath C:\windows\system32\calc.exe -ShowInWebAccess $false -UserGroups @("Domain Users","Domain Admins") -FileExtensionMode "Automatic"
	
	.Example
 	Set-AMRemoteApp -DisplayName Calculator -FilePath C:\windows\system32\calc.exe -ShowInWebAccess $false -UserGroups @("Domain Users","Domain Admins") -FileExtensionMode "Manual" -FileExtensions @(".txt",".log")
	
#>
function Set-AMRemoteApp
{
	[cmdLetbinding()]
	param
	(	
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=0)]
		[string]
		$DisplayName,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=1)]
		[string]
		$Alias,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=2)]
		[string]
		$FilePath,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=3)]
		[boolean]
		$ShowInWebAccess = $false,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=4)]
		[string]
		$Folder,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=5)]
		[string]
		$Arguments,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=6)]
		[string]
		$IconPath,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=7)]
		[string]
		$IconIndex = 0,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=8)]
		[string[]]
		$UserGroups,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=9)]		
		[Boolean]
		$PublishFileTypes = $true,
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=10)]
		[string]
		$Collection,
		[parameter(mandatory=$false,ValueFromPipeline=$false,Position=11)]
		[string]
		$ArgumentPermissions
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

			# Initialization
            Write-AMInfo "Initializing RemoteApp update"
			If (!(Get-Module RemoteDesktop)) {Import-Module RemoteDesktop}
			# Get connectionbroker and CollectionName			
			$RDCB = (Get-WMIObject -Namespace root\cimv2\terminalservices -Class Win32_TSSessionDirectory).SessionDirectoryLocation
			Write-Verbose "Collection broker: $RDCB"
			$ValidCollection = Get-RDSessionCollection -ConnectionBroker $RDCB -CollectionName $Collection
			Write-Verbose "Collection $Collection was found"
			# Check if filepath exists
			If (!(Test-Path $FilePath)) {throw "$FilePath is not a valid path, unable to publish RemoteApp"}
			
			# Construct the proper commandline
            $CommandLineEx = @{}
			$CommandLineEx.Add("ConnectionBroker", $RDCB)
            $CommandLineEx.Add("CollectionName", $Collection)
			
			$CommandLineEx.Add("FilePath", $FilePath)
			$CommandLineEx.Add("Alias", $Alias)
			$CommandLineEx.Add("DisplayName",$DisplayName)
			$CommandLineEx.Add("ShowInWebAccess",$ShowInWebAccess)
			
			If (!([string]::IsNullOrEmpty($Folder)))
			{
				$CommandLineEx.Add("FolderName", $Folder)
			}
			
			$CommandLineSetting = $ArgumentPermissions # DoNotAllow,Required or Allow is possible. When arguments are specified, it should be set to Required
			If (!([string]::IsNullOrEmpty($Arguments)))
			{
				$CommandLineSetting = "Require"
				$CommandLineEx.Add("RequiredCommandLine", $Arguments)				
			}
			$CommandLineEx.Add("CommandLineSetting", $CommandLineSetting)
			
			if (!([string]::IsNullOrEmpty($IconPath)))
			{
				$CommandLineEx.Add("IconPath",$IconPath)
				$CommandLineEx.Add("IconIndex",$IconIndex)
			}
			if (!([string]::IsNullOrEmpty($UserGroups)))
			{
				$CommandLineEx.Add("UserGroups", $UserGroups)
			}
			Write-AMInfo "Updating RemoteApp $DisplayName"
			# Create the RemoteApp
			$Result = Set-RDRemoteApp @CommandLineEx
			
			#Set file extensions
			If ($PublishFileTypes -eq $False)
			{
				Write-AMInfo "Checking FileType associations for $Alias"
				$FileTypes = Get-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -ConnectionBroker $RDCB
				if ($($FileTypes).IsPublished -Contains $True) {
					$FileTypes | ForEach-Object {
						Write-AMInfo "Disabling FileType Associations for $Alias"
						Set-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -FileExtension $_.FileExtension -IsPublished $False -ConnectionBroker $RDCB
					}
				}
			}
						
			If ($PublishFileTypes -eq $True)
			{
				#Get file extensions for path and add them
				Write-AMInfo "Checking FileType Associations for $Alias"
				$FileTypes = Get-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -ConnectionBroker $RDCB
				if ($($FileTypes).IsPublished -Contains $False) {
					$FileTypes | ForEach-Object {
						Write-AMInfo "Enabling FileType Associations for $Alias"
						Set-RDFileTypeAssociation -CollectionName $Collection -AppAlias $Alias -FileExtension $_.FileExtension -IsPublished $True -ConnectionBroker $RDCB
					}
				}
			}
		
			
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Loads an assembly wihout locking the file on the filesystem
 	
	.Description
	Loads an assembly without locking the file on the filesystem
	
	.Parameter Path
 	File to load
	
	.Example
 	Add-AMAssembly -Path c:\folder\someassembly.dll
#>
function Add-AMAssembly
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true)]
		[System.IO.FileInfo]
		$Path
	)
	
	$file = $Path.FullName
	<#$fileStream = ([System.IO.FileInfo] (Get-Item $file)).OpenRead()
	$assemblyBytes = new-object byte[] $fileStream.Length
	$fileStream.Read($assemblyBytes, 0, $fileStream.Length) | Out-Null
	$fileStream.Close()
	[System.Reflection.Assembly]::Load($assemblyBytes)#>
	$assemblyBytes = [System.IO.File]::ReadAllBytes($file)
	[System.Reflection.Assembly]::Load($assemblyBytes)
}

<#
	.Synopsis
	Compares 2 files.

	.Description
 	Compares 2 files using an MD5 hash
  	
	.Parameter ReferenceFile
 	File used as a reference for comparison
	
	.Parameter DifferenceFile
 	Specifies the file that is compared to the reference file.
	
	.Example
 	Compare-AMFiles -ReferenceFile "C:\file1.txt" -DifferenceFile "C:\file2.txt"
	
	.Example 
	"C:\file1.txt" | Compare-AMFiles -DifferenceFile "C:\File2.txt"
#>
function Compare-AMFiles
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$ReferenceFile,
		
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$DifferenceFile
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

					

		$F1 = Get-Item $ReferenceFile
		$F2 = Get-Item $DifferenceFile
	
		$file1MD5 = Get-AMFingerPrint -InputFile $F1.FullName -Algorithm MD5
		$file2MD5 = Get-AMFingerPrint -InputFile $F2.FullName -Algorithm MD5
			
		if ([string]::Compare($file1MD5, $file2MD5, $true) -eq 0) {
			return $true
		}
		return $false	

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Compress a folder

	.Description
 	Compresses a folder to a zip file.
  	
	.Parameter Path
 	Folder to be compressed
	
	.Parameter Destination
 	Destination ZIP file
	
	.Example
 	Compress-AMFolder -Path "C:\tmp" -Destination "h:\tmp.zip"
#>
function Compress-AMFolder {

	[CmdletBinding()]
    param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[String]
		$Path,
		
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[String]
		$Destination
    )
    
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		Write-AMInfo "Compressing $($Path) to $($Destination)"
		# Ensure sourcefolder exists
		if (!(Test-Path $Path)) {throw "$($Path) does not exist"}
		# Remove destination file if it exists (.NET zip library's CreateFromDirectory() method throws exception when the destination file already exists)
		if (Test-Path $Destination -PathType Leaf) {
			Remove-Item -Path $Destination -Force
		}
		else {
			#Ensure destination folder exists
			$DestinationFolder = Split-Path $Destination -Leaf
			if (!(Test-Path $DestinationFolder)) {[void] (New-Item -ItemType Directory -Path $DestinationFolder -Force)}
		}
		$Zip = New-Object Ionic.Zip.ZipFile
		$Zip.AddDirectory($Path)
		$Zip.Save($Destination)


	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


}

<#
	.Synopsis
	Converts a short registry key hive format to a full PowerShell format.

	.Description
	 Converts a short registry key hive format to a full PowerShell format.
	 Supported separators for a registry hive: :\\, :\, :, \\, \
  	
	.Parameter Path
 	Path of the registry key
	
	.Example 
	Convert-AMRegistryPath -Path 'HKCR:\CLSID\{D63B10C5-BB46-4990-A94F-E40B9D520160}'
	
	.Example
	Convert-AMRegistryPath -Path 'HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip'

	.Example

	'HKLM:SOFTWARE\Automation Machine\Status:Maintenance' | Convert-AMRegistryPath
	
#>
function Convert-AMRegistryPath {
	[CmdletBinding()]
	param
	(
		[parameter(mandatory = $true, ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$Path
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
	# Saving input path, if something goes wrong just return the original
	$InputPath = $Path

	try {

		# Trying to get as many cases as I can think of
		if ($Path -match '^HKLM:\\\\|^HKCU:\\\|^HKCR:\\\\|^HKU:\\\\|^HKCC:\\\\|^HKPD:\\\\') {
			$Path = $Path -replace '^HKLM:\\\\', 'HKEY_LOCAL_MACHINE\'
			$Path = $Path -replace '^HKCR:\\\\', 'HKEY_CLASSES_ROOT\'
			$Path = $Path -replace '^HKCU:\\\\', 'HKEY_CURRENT_USER\'
			$Path = $Path -replace '^HKU:\\\\', 'HKEY_USERS\'
			$Path = $Path -replace '^HKCC:\\\\', 'HKEY_CURRENT_CONFIG\'
			$Path = $Path -replace '^HKPD:\\\\', 'HKEY_PERFORMANCE_DATA\'
		}
		elseif ($Path -match '^HKLM:\\|^HKCU:\\|^HKCR:\\|^HKU:\\|^HKCC:\\|^HKPD:\\') {
			$Path = $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
			$Path = $Path -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
			$Path = $Path -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
			$Path = $Path -replace '^HKU:\\', 'HKEY_USERS\'
			$Path = $Path -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
			$Path = $Path -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\'
		}
		elseif ($Path -match '^HKLM:|^HKCU:|^HKCR:|^HKU:|^HKCC:|^HKPD:') {
			$Path = $Path -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\'
			$Path = $Path -replace '^HKCR:', 'HKEY_CLASSES_ROOT\'
			$Path = $Path -replace '^HKCU:', 'HKEY_CURRENT_USER\'
			$Path = $Path -replace '^HKU:', 'HKEY_USERS\'
			$Path = $Path -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\'
			$Path = $Path -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\'
		}
		elseif ($Path -match '^HKLM\\\\|^HKCU\\\\|^HKCR\\\\|^HKU\\\\|^HKCC\\\\|^HKPD\\\\') {
			$Path = $Path -replace '^HKLM\\\\', 'HKEY_LOCAL_MACHINE\'
			$Path = $Path -replace '^HKCR\\\\', 'HKEY_CLASSES_ROOT\'
			$Path = $Path -replace '^HKCU\\\\', 'HKEY_CURRENT_USER\'
			$Path = $Path -replace '^HKU\\\\', 'HKEY_USERS\'
			$Path = $Path -replace '^HKCC\\\\', 'HKEY_CURRENT_CONFIG\'
			$Path = $Path -replace '^HKPD\\\\', 'HKEY_PERFORMANCE_DATA\'
		}
		elseif ($Path -match '^HKLM\\|^HKCU\\|^HKCR\\|^HKU\\|^HKCC\\|^HKPD\\') {
			$Path = $Path -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
			$Path = $Path -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
			$Path = $Path -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
			$Path = $Path -replace '^HKU\\', 'HKEY_USERS\'
			$Path = $Path -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
			$Path = $Path -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
		}
		# Add 'Registry::' at the beginning of the path if it's not present	
		if ($Path -notmatch '^Registry::') {
			$Path = "Registry::$Path" 
		}

		# Checking for the correct registry key path format, if it's wrong, just return the original one
		if ($Path -match '^Registry::HKEY_LOCAL_MACHINE|^Registry::HKEY_CLASSES_ROOT|^Registry::HKEY_CURRENT_USER|^Registry::HKEY_USERS|^Registry::HKEY_CURRENT_CONFIG|^Registry::HKEY_PERFORMANCE_DATA') {
			return $Path
		}
		else {
			return $InputPath
		}

	}
	catch {

		Write-AMWarning "Something went wrong in formatting the registry key path, using the original key path"
		return $InputPath

	}

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


}

<#
	.Synopsis
	Converts an unicode string
	
	.Description
 	Converts an unicode string from or to base64
	
	.Parameter String
	The string to convert
	
	.Parameter ToBase64
	Switch parameter indicating the string should be converted to base64
	
	.Parameter FromBase64
	Switch parameter indicating the string should be converted from base64
	
	.Example
	Convert-AMString -ToBase64 -String "Automation Machine"
	.Example
	Convert-AMString -FromBase64 -String "QXV0b21hdGlvbiBNYWNoaW5l"

#>
function Convert-AMString
{
	[CmdletBinding()]
	param
	(		
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$String,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$ToBase64,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$FromBase64
		
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

				

		If ($ToBase64.IsPresent -eq $true -and $FromBase64.IsPresent -eq $true)
		{
			Write-Error "Can't convert tobase64 and frombase64 at the same time"
		}
			
		If ($ToBase64.IsPresent -eq $true -and $FromBase64.IsPresent -eq $false)
		{
			$bytes  = [System.Text.Encoding]::Unicode.GetBytes($string);
	   		$encoded = [System.Convert]::ToBase64String($bytes);
	   		return $encoded;
		}
		If ($ToBase64.IsPresent -eq $false -and $FromBase64.IsPresent -eq $true)
		{
			$bytes  = [System.Convert]::FromBase64String($string);
			$decoded = [System.Text.Encoding]::Unicode.GetString($bytes);
			return $decoded;
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Expands environment variables in strings.

	.Description
 	Expands environment variables in string. Environment variables can be escaped using doubled % signs.
  	
	.Parameter string
 	Input string
	
	.Parameter NoEscape
	Switch parameter that specifies that < > character should not be escaped to % %.
		
	.Example
 	"This is my homedrive: %HOMEDRIVE%" | Expand-AMEnvironmentVariables
	produces the string "This is my homedrive: C:"
	
	.Example 
	"The environment variable <HOMEDRIVE> contains the value %HOMEDRIVE%" | Expand-AMEnvironmentVariables
	produces the string "The environment variable %HOMEDRIVE% contains the value C:"
	
	.Example
	"%AA% is not a real variable. But <homedrive><homepath>\<username> should be resolved to %homedrive%%homepath%\%username%"
	
#>
function Expand-AMEnvironmentVariables 
{
    [CmdletBinding()]
	param
	(
		[parameter(mandatory=$false,ValueFromPipeline=$true)]
		[string]
		$String,
		[parameter(mandatory=$false)]
		[switch]
		$NoEscape
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		# DDA Aug 1, 2013: Needs to be recursive to resolve variables within variables.
		do
		{
			[string] $OriginalString = $string
			$string = [System.Environment]::ExpandEnvironmentVariables($OriginalString)
				
		} while ($OriginalString -ne $string)
			
		# HHO Sep 11, 2013: Replaced by regex to make sure single characters are not replaced
		#$string.replace("<","%").replace(">","%")
		If (-not ($NoEscape))
		{
			$RegEx = New-Object System.Text.RegularExpressions.Regex("<[a-zA-Z0-9 ]+>")
			ForEach ($Match in $RegEx.Matches($string))
			{
				$string = $string.Remove($Match.Index,$Match.Length)
				$string = $string.Insert($Match.Index,$Match.Value.Replace("<","%").Replace(">","%"))				
			}
		}
		$string
			
		# DDA Aug 1, 2013: Return statement does not work as expected in PowerShell. It is not needed here.
		# return [System.Environment]::ExpandEnvironmentVariables($string).Replace("<","%").Replace(">","%")
			

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Decompress a zip file

	.Description
 	Decrompresses as zip file to a folder
  	
	.Parameter Path
 	Path to zip file to be decompressed
	
	.Parameter Destination
 	Path to destintation folder
	
	.Parameter Force
	Switch parameter to indicate that existing files can be overwritten.
	
	.Example
 	Expand-AMZipFile -Path "h:\tmp.zip" -Destination "C:\tmp" -Overwrite
#>
function Expand-AMZipFile
{
	[CmdletBinding()]
    param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[String]
		$Path,
		
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[String]
		$Destination,
		
		[alias("Overwrite")]
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$Force
    )
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


		Write-AMInfo "Extracting $($Path) to $($Destination)"
		
		If (-not (Test-Path $Path)) {throw "$Path does not exist, cannot extract"}
		try {
			$zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
			foreach ($entry in $zip.Entries) {
				$entryDestination = Join-Path $Destination $entry.FullName
				if ($entry.FullName.EndsWith("/")) { # directory
					if ((Test-Path -Path $entryDestination) -eq $false) {
						[void] (New-Item -Path $entryDestination -ItemType Directory -Force)
					}
				}
				else { # file
					if (((Test-Path -Path $entryDestination) -eq $false) -or $Force) {
						$parentDir = Split-Path $entryDestination
						if ((Test-Path -Path $parentDir) -eq $false) {
							[void] (New-Item -Path $parentDir -ItemType Directory -Force)
						}
						[System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryDestination, $true)
					}
				}
			}
		}
		catch {
			throw $_
		}
		finally {
			if ($zip -ne $null) {
				$zip.Dispose()
			}
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')
	
}
<#
.SYNOPSIS
Gets file encoding.

.DESCRIPTION
The Get-AMFileEncoding cmdlet determines encoding by looking at Byte Order Mark (BOM).

.Parameter Path
Specifies the path to a file. Get-AMFileEncoding gets the encoding of the file.

.EXAMPLE
Get-AMFileEncoding -Path "c:\temp\test.txt"
#>
function Get-AMFileEncoding {
    [CmdletBinding()] 
    param (
        [Parameter(Mandatory = $True)] 
        [string] $Path
    )

    $Bytes = [byte[]] (Get-Content -Encoding Byte -ReadCount 4 -TotalCount 4 -Path $Path)

    switch -regex ("{0:x2}{1:x2}{2:x2}{3:x2}" -f $Bytes[0],$Bytes[1],$Bytes[2],$Bytes[3]) {
        "^efbbbf" { return "UTF8" }
        "^fffe" { return "Unicode" }
        "^feff" { return "BigEndianUnicode" }
        "^feff0000" { return "UTF32" }
        "^0000feff" { return "BigEndianUTF32" }
        "^2b2f76" { return "UTF7" }
        default { return "Ascii" }
    }
}

<#
	.Synopsis
	Calculates a hash fingerprint of the input object

	.Description
 	Calculates a hash fingerprint of the input object. Supports strings and files.
    
	.NOTES
	The hash fingerprint is returned as a string containing HEX values.
	
	.Parameter InputString
	String value to calculate the hash fingerprint of.

	.Parameter InputFile
	File to calculate the hash fingerprint of.

	.Parameter Sample
	If specified, only the first 4096 bytes of each file are read.
	
	.Parameter Algorithm
	The algorithm to use to calculate the hash fingerprint. Possible values are: MD5, SHA1, SHA256, SHA384 or SHA512. MD5 will be used by default when this parameter is omitted.
		
	.INPUTS
	System.String
	System.IO.FileInfo
	These object types can also be piped into Get-AMFingerPrint
	
	.OUTPUTS
	System.String
	
 	.Example
 	Get-AMFingerPrint -InputString "Hello World"
	Calculates the MD5 Hash of the string "Hello World"
	
	.Example
	get-item c:\tmp\somefile.bin | Get-AMFingerPrint -Sample -Algorithm SHA256
	Samples the first 4096 bytes of c:\tmp\somefile.bin and calculates a SHA256 hash.
	
	.Example
	Get-AMFingerPrint -InputFile c:\tmp\somelargefile.bin
	Calculates the MD5 hash of the full file.
	
	.Example
	"c:\tmp\somefile.bin" | Get-AMFingerPrint
	Calculates a MD5 Hash of the STRING "c:\tmp\somefile.bin"
 		
	.LINK
	http://wikipedia.org/wiki/MD5
	
	.LINK
	http://en.wikipedia.org/wiki/Secure_Hash_Algorithm	
	
#>
function Get-AMFingerPrint {
    [CmdletBinding(DefaultParameterSetName = "string")]
    param
    (		
        [parameter(mandatory = $true, Position = 0, ValueFromPipeline = $false, ParameterSetName = "string")]
        [string]
        $InputString,
		
        [parameter(mandatory = $true, Position = 0, ValueFromPipeline = $false, ParameterSetName = "file")]
        [System.IO.FileInfo]
        $InputFile,
			
        [parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "file")]
        [switch]
        $Sample,
		
        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [string]
        $Algorithm = "MD5"
		
    )
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')
			

    $HashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    [string] $result = [string]::Empty
			
    switch ($PsCmdlet.ParameterSetName) {
        "string" {
					
            $HashByteArray = $HashAlgorithm.ComputeHash([Char[]]$InputString)
            foreach ($byte in $HashByteArray) { $result += "{0:x2}" -f $byte }
        }
        "file" {
            $InStream = [System.IO.File]::OpenRead($InputFile.FullName)

            $BlockSize = $InputFile.Length
            if ($Sample) {
                if ($BlockSize -ge 1MB) {
                    $BlockSize = 1MB
                }
            }
					
            $buffer = New-Object Byte[] $BlockSize 
            [void] $InStream.Read($buffer, 0, $BlockSize)
            $InStream.Close()

            [string] $result = [string]::Empty
            $HashByteArray = $HashAlgorithm.ComputeHash($buffer, 0, $BlockSize)
            foreach ($byte in $HashByteArray) { $result += "{0:x2}" -f $byte }
        }
    }
    $HashAlgorithm = $null

    $result

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Gets a mutex.

	.Description
 	Gets a mutex for this computer, determines if it can process something that should only be processed on a single host.
  
	.Parameter Name
 	Name of the mutex to get.
	
	.Parameter TimeOut
	Timout to set for the mutex
	
	.Parameter Path
	Path where the mutex file will be stored
	
	.Parameter Force
	Forcefully get the mutex, basically breaking the functionality and returning true
	
	.Parameter IncludeInstanceID
	Determines if the mutex includes the $Host instanceID, or that it's only mutexed on computername.
	
	.Parameter Wait
	The amount of seconds to wait before releasing the mutex
  
	.NOTES
	Distributed filesystems are NOT supported
 
 	.Example
 	Server1 | Get-AMOperatingSystemArchitecture

#>
function Get-AMMutex {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param
    (
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string] $name,
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [int] $TimeOut = 10,
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [string] $Path = "$($AMCentralPath)\$($AMEnvironment.id)\monitoring\mutex",
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [int] $Wait = 0,
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false, Position = 4)]
        [switch] $Force,
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false, Position = 5)]
        [switch] $IncludeInstanceID
    )
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

    $StartTime = [int64] ((Get-Date).Ticks / 10000000)

    # Convert the name to an MD5 hash to make sure we do not get any 
    # filesystem issues caused by the name of the Mutex
    $Name = Get-AMFingerPrint $name.ToUpper()

    if (-not $IncludeInstanceID) {
        $MyID = $env:computername
    }
    else {
        $MyID = "$($env:COMPUTERNAME)_$($host.instanceid)"
    }

    $MutexFileName = "$Path\$Name"

    #Check if the Mutex folder exists.
    if (-not (Test-Path $Path)) { [void] (New-Item $Path -ErrorAction SilentlyContinue -ItemType Directory) }
    if (-not (Test-Path $Path)) { 
        return $false
    }

    [Boolean] $ReturnValue = $false
    [Boolean] $Retry = $true
    [int] $RetryCount = 0
    :MainLoop while ($true) {
        :Escape while ($Retry -eq $true) {
            try {
                #Is the mutex mine or older than the timeoutvalue?
                if (Test-Path $MutexFileName) {
                    [string[]] $MutexInfo = [string[]] (Get-Content $MutexFileName -erroraction stop | % { $_.Split(";") })
                }
                else {
                    Set-Content -Path $MutexFileName -Value "$MyID;$TimeOut" -erroraction stop
                    return $true
                }
						
                #If the Mutex file is empty or corrupted, recreate it.
                if (($MutexInfo -isnot [object]) -or ($MutexInfo.Count -ne 2)) {
                    $MutexInfo = ("$MyID;$TimeOut").Split(";")
                }
						
                $FileAge = [Int64] ((((Get-Date).ToUniversalTime().Ticks - (Get-Item -Path $MutexFileName -ErrorAction Stop ).LastWriteTimeUtc.Ticks)) / 10000000)
						
                if (($MutexInfo[0] -eq $MyID) -or ([int] ($FileAge) -gt [int] $MutexInfo[1]) -or ($Force -eq $true)) {
                    #Update the mutex
                    Set-Content -Path $MutexFileName -Value "$MyID;$TimeOut" -erroraction stop
							
                    #Did I really get it?
                    [string[]] $MutexInfo = [string[]] (Get-Content $MutexFileName -erroraction stop | % { $_.Split(";") })
							
                    $Retry = $false
                    if ($MutexInfo[0] -eq $MyID) {
                        $ReturnValue = $true
                        break escape
                    }
                    else {
                        $ReturnValue = $false
                        break escape
                    }
                }
                else {
                    $ReturnValue = $false
                    break escape
                }
            }
            catch [Exception] {
                $RetryCount++
						
                if ($RetryCount -gt 100) {
                    $ReturnValue = $false
                    break escape
                }
                else {
                    $Retry = $true
                }
            }
        }

        if (($ReturnValue -eq $true) -or (([int64] ((Get-Date).Ticks / 10000000)) -ge ($StartTime + $Wait))) {
            return $ReturnValue
            break MainLoop
        }
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Get the current or previous transcript path.

	.Description
 	Get the name of the current (or last) transcription file used in the current session. Requires powershell v2.0. 
  
	.NOTES
	returns null if you have not yet used transcription in the current session
	if transcribing, it contains the current transcription file path
	if you have previously transcribed and now stopped, it returns the filepath of previous transciption string
 
 	.Example
 	Get-AMTranscriptPath
 	
#>
function Get-AMTranscriptPath
{
	[cmdLetbinding()]
	param
	(	
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
		try 
		{
			$externalHost = $host.gettype().getproperty("ExternalHost",[reflection.bindingflags]"nonpublic,instance").getvalue($host, @())
			$externalhost.gettype().getfield("transcriptFileName", "nonpublic,instance").getvalue($externalhost)
			
		} 
		catch 
		{
		  Write-AMwarning "This host does not support transcription."
		}		
		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
	
}

<#
    .Synopsis
    Creates a persistent connection to a local or remote computer.

    .Description
    The New-AMPSSession cmdlet creates a Windows PowerShell session (PSSession) on a local or remote computer. When you create a PSSession, Windows PowerShell establishes a persistent connection to the remote computer.

    .Parameter ComputerName
    Creates a persistent connection (PSSession) to the specified computer. If you enter multiple computer names, New-PSSession creates multiple PSSessions, one for each computer. The default is the local computer.

    .Parameter Retry
    If connection fails the cmdlet retries to connect the specified amount of times.

    .Parameter RetryIntervalSeconds
    Amount of seconds to wait between retry attempts.

    .Example
    $Session = New-AMPSSession -ComputerName $ConnBrokerNode -Retry 3 -RetryIntervalSeconds 60
#>
function New-AMPSSession {
    
    [CmdletBinding()]
	param 
	(
        [Parameter(Mandatory=$true)]
        [string[]] $ComputerName,

        [Parameter(Mandatory=$false)]
        [int] $Retry = 1,

        [Parameter(Mandatory=$false)]
        [int] $RetryIntervalSeconds = 1
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    $Session = $null
    $retryCount = 0
    $maxRetryCount = $Retry
    do {
        $Session = New-PSSession -Computername $ComputerName -ErrorAction SilentlyContinue
        if ($Session -eq $null) {
            $retryCount++
            Write-Warning "Trying to connect to $ComputerName. Attempt $retryCount of $maxRetryCount."
            if ($retryCount -ge $maxRetryCount) {
                break
            }
            else {
                Start-Sleep -Seconds $RetryIntervalSeconds
            }
        }
    }
    while ($Session -eq $null)

    return $Session

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

    
}

<#
	.Synopsis
	Returns a random string that can be used as either a folder name or a file name.

	.Description
 	Returns a random, unique for the spacified path string that can be used as either a folder name or a file name.
	
	.Parameter Path
	A path where the function should check for uniqueness of the generated name.
  	 
 	.Example
 	New-AMRandomItemName -Path C:\MyFolder
#>
function New-AMRandomItemName
{
	[CmdletBinding()]
	param 
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$false)]
		[string] $Path
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


		$Name = [System.IO.Path]::GetRandomFileName()
		$FullPath = Join-Path $Path $Name
		if (Test-Path $FullPath) {
			return New-AMRandomItemName -Path $Path
		}
		return $Name
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Secures the packages in the cache folder

	.Description
 	Secures the local cache folder. Sets ReadAndExecute rights for the package primary group and fullcontrol rights for the service account.
     
 	.Example
 	Set-AMCacheSecurity

#>
function Set-AMCacheSecurity
{
	[cmdLetbinding()]
	param
	(
		
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

			
			If (!(Test-AMElevation))
			{
				Write-AMWarning "Process is not running elevated, cannot secure cache folders"
			}
			ElseIf ((Get-AMPlugin -Id "896667bf-44d2-4d4d-aeb3-4ece60dfe264") -eq $null)
			{
				Write-AMInfo "The security plugin is not available in this environment, skipping securing of cache folder"
			}
			else
			{
				Write-AMInfo "Securing cache folders"
				 if (-not (Test-Path Variable:am_aborting))          {Set-Variable -Name am_aborting -Value $false -Scope Global}
				$am_col = Get-AMCollection -Current
				if ($am_col -eq $null)
				{
					$global:am_aborting = $true
				}	
				
				if ($global:am_aborting -ne $true)
				{
					# Get the pre/suffix
					Set-Variable -name am_col_gprefix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000014" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)
					Set-Variable -Name am_col_gsuffix -Value ([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000018" -ParentId "896667bf-44d2-4d4d-aeb3-4ece60dfe264" -CollectionId $am_col.Id).Value | Expand-AMEnvironmentVariables)

					ForEach ($Package in Get-AMPackage)
					{
						Write-Verbose "Securing cache folder for $($Package.Name)"
						[System.Environment]::SetEnvironmentVariable("am_pkg_name",$Package.Name,[System.EnvironmentVariableTarget]::Process)
						Set-Variable -Name am_pkg_pgroup -Value([string] (Get-AMVariable -Id "00000000-0000-0000-0000-000000000017" -ParentId "0008cfe0-532e-462f-99ba-4b5b16cf1754" -CollectionId $am_col.Id -ComponentId $Package.Id).Value | Expand-AMEnvironmentVariables)
						Set-Variable -Name am_pkg_pgroupfull -Value ($am_col_gprefix + $am_pkg_pgroup + $am_col_gsuffix | Expand-AMEnvironmentVariables)
						
						If ((Get-AMLDAPPath $am_pkg_pgroupfull) -eq $null)
						{
								Write-Verbose "Could not find security group $am_pkg_pgroupfull, unable to secure package in cache"
						}
						Else
						{
							Set-AMPermissions -PrincipalName $am_pkg_pgroupfull -Path $Package.Path -Recurse -Type Allow -Permissions "ReadAndExecute"
						}
						Write-Verbose "Adding service account fullcontrol to $($Package.Path)"
						# Add service account to acl
						$ACL = Get-Acl $Package.Path
						$SID = Get-AMSID -Name $AMEnvironment.ServiceAccount.UserName
						$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SID,"FullControl",$([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),[System.Security.AccessControl.PropagationFlags]::None,"Allow")
						$ACL.AddAccessRule($accessRule)
						$ACL | Set-Acl -Path $Package.Path					
					}
				}
			}
			
	
		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Sets AM Environment variables on the system

	.Description
 	Sets the AM variables as environment variables on the system,user or process level
	
	.Parameter Collection
	If a collection specified then overidden variables of it will be used to replace global variables.
	
	.Parameter Computer
	If a computer specified then overidden variables of it will be used to replace global variables.
	
	.Parameter Component
	If a component (package or plugin) specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ActionItem
	If an action item specified then overidden variables of it will be used to replace global variables.
	
	.Parameter CollectionId
	ID of a collection. If a collection specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ComputerId
	ID of a computer. If a computer specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ComponentId
	ID of a component (package or plugin). If a component specified then overidden variables of it will be used to replace global variables.
	
	.Parameter ActionSetId
	ID of an action set to which action item belongs.
	
	.Parameter ActionItemId
	ID of an action item. If an action item specified then overidden variables of it will be used to replace global variables.  

	.Parameter Scope
	The environmentvariable scope to use: User,System or Process
  
 	.Example
	Set-AMEnvironmentVariables
	This command sets all public variables of the current environment.
	
	.Example
	Set-AMEnvironmentVariables -CollectionId "019cd113-456b-42f2-bb76-a28d040b0c18" -ComputerId "92c58e1f-23b5-471e-a980-460c5ac95b9f" -ComponentId "ca5e4850-9cc5-4edd-bcdf-23671c71dfea"
	This command sets the variables for specific collectionid, computerid and componentId
	
	.Example
	$Component = Get-AMPackage -Name "Adobe Reader X"
	C:\PS>Set-AMEnvironmentVariables -Component $Component
	
	.Example
	$Computer = Get-AMComputer -name "Computername"
	$Package = Get-AMPackage -Name "Adobe Reader X"
	C:\PS>Set-AMEnvironmentvariables -ComputerId $Computer.id -ColletionId $Computer.collectionId -ComponentId $Package.id
	
#>
function Set-AMEnvironmentVariables
{
	[CmdletBinding(DefaultParameterSetName="Default")]
	param
	(
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.Collection]
		$Collection = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.Computer]
		$Computer = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.Component]
		$Component = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[AutomationMachine.Data.ActionItem]
		$ActionItem = $null,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$CollectionId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ComputerId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ComponentId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ActionSetId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[System.Guid]
		$ActionItemId = [System.Guid]::Empty,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Default")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="Element")]
		[parameter(mandatory=$false,ValueFromPipeline=$false,ParameterSetName="ElementId")]
		[ValidateSet("Process","Machine","User")]
		[string]
		$Scope = "Process"
		

	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		switch ($PSCmdlet.ParameterSetName) {
			"Element" {
				$PluginIds = Get-AMPlugin  | % {$_.Id}
				$GlobalVariables = Get-AMVariable -Collection $Collection -Computer $Computer -Component $Component -ActionItem $ActionItem | ? {($_.ParentId -eq $Component.Id) -or ($PluginIds.Contains($_.ParentId))}
				$Pkg = Get-AMPackage -Id $Component.Id
			}
			"ElementId" {
				if (($ActionItemId -ne [Guid]::Empty) -and ($ActionSetId -eq [Guid]::Empty)) {
					Write-Host "Action Set ID is not specified for Action Item ID" -ForegroundColor Yellow
				}
				$PluginIds = Get-AMPlugin  | % {$_.Id}
				$GlobalVariables = Get-AMVariable -CollectionId $CollectionId -ComputerId $ComputerId -ComponentId $ComponentId -ActionSetId $ActionSetId -ActionItemId $ActionItemId | ? {($_.ParentId -eq $ComponentId) -or ($PluginIds.Contains($_.ParentId))}
				$Pkg = Get-AMPackage -Id $ComponentId	
			}
			"Default" {
				$GlobalVariables = Get-AMVariable
			}
		}
		
		
			
		# Process vars
		ForEach ($Var in $GlobalVariables)
		{
			# special handling for am_pkg_media variable
			if ($var.Id -eq "00000000-0000-0000-0000-000000000003")
			{
				# Check if media is assigned to package
				If ($Pkg.MediaRevision -ne $null)
				{
					$Val = $AMDataManager.GetPackageMediaRevisionPath($pkg.MediaRevision).Replace($AMDataManager.AMFileShare,$env:am_files) | Expand-AMEnvironmentVariables
					[System.Environment]::SetEnvironmentVariable($($Var.Name),$Val,$Scope)
					# if the var is overridden on package level, then we should use the overriden value as media path
					If ($var.Entity -is [AutomationMachine.Data.OverriddenVariable])
					{
						If ($var.Scope -eq "Package")
						{
							[System.Environment]::SetEnvironmentVariable($($Var.Name),$($Var.Value.Path),$Scope)
						}
					}
				}
				else
				{
					[System.Environment]::SetEnvironmentVariable($($Var.Name),$($Var.Value.Path),$Scope)
				}
				
			}
			else
			{			
				$val = ""

				$excludedVars = New-Object System.Collections.Generic.List[System.Guid]
                $excludedVars.Add($AmWellKnown::Plugins.Maintenance.ReportingMailSmtpCredentialsVariable.Id)
                $excludedVars.Add($AmWellKnown::Plugins.SccmConnector.SccmServerCredentialsVariable.Id)
                $excludedVars.Add($AmWellKnown::Plugins.Hypervisor.CredentialsVariable.Id)
                $excludedVars.Add($AmWellKnown::Plugins.Hypervisor.LocalAdminCredentialsVariable.Id)
                $excludedVars.Add($AmWellKnown::Plugins.Hypervisor.AdCredentialsConfigVariable.Id)
                $excludedVars.Add($AmWellKnown::Plugins.ActiveDirectory.ServiceAccountVariable.Id)
				
				Switch ($Var.Type.ToString())
				{
					"AutomationMachine.Data.Types.File" {$val = $var.Value.path}
					"AutomationMachine.Data.Types.Folder" {$val = $var.value.path}
					"AutomationMachine.Data.Types.ImportedFile" {$val = Get-AMImportedFilePath $var}
					"AutomationMachine.Data.Types.ImportedFolder" {$val = $AMEnvironment.GetImportedFolderPath($var.value)}
					"AutomationMachine.Data.Types.Credentials" {
						if (-not $excludedVars.Contains($var.Id)) {
                            $val = $($var.Value.Username + ";" + $var.Value.Password)
                        } 
					}
					"AutomationMachine.Data.Types.List" {$val = $var.Value.Value }
					"AutomationMachine.Data.Types.AMPassword" {$val = $var.Value.Password}
					"System.String" {$val = $var.value}
					"System.Int32" {$val = $var.value.ToString() }
					"System.Boolean" {$val = $var.value.ToString().ToLower() }
				}
				[System.Environment]::SetEnvironmentVariable($($Var.Name),$val,$Scope)
			}
		}
		
			

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Splits a file into chunks.

	.Description
 	Splits a file into chunks.
  
	.Parameter Path
 	Path to the file to split.
	
	.Parameter Chunksize
 	The size of chunks to split the file into. If this parameter is not supplied it defaults to 1Kb
 
 	.Example
 	Split-AMFile -Path D:\File.reg -ChunkSize 4Kb
#>
Function Split-AMFile {
    [CmdletBinding()]
    param
    (
        [parameter(ValueFromPipeline = $false, Mandatory = $true)]
        [System.IO.FileInfo]
        $Path,
		
        [parameter(ValueFromPipeline = $false, Mandatory = $false)]
        [int]
        $ChunkSize = 1
    )

    begin {
        Write-Warning "DataChunk Type not yet in assembly"
        $ChunkSize = $ChunkSize * 1Kb
    }
    process {


        $MD5 = [System.Security.Cryptography.MD5]::Create()
        [System.IO.FileStream] $InStream = $Path.OpenRead()
        [int64] $Offset = 0
        [int64] $Index = 0
        do {
			
            $DataChunk = New-Object PSObject
            $DataChunk | Add-Member -MemberType NoteProperty -Name FileName -Value $Path.FullName
            $DataChunk | Add-Member -MemberType NoteProperty -Name FileSize -Value $Path.Length
            $DataChunk | Add-Member -MemberType NoteProperty -Name LastChunk -Value $false
            $DataChunk | Add-Member -MemberType NoteProperty -Name ChunkSize -Value $ChunkSize
            $DataChunk | Add-Member -MemberType NoteProperty -Name ChunkCount -Value $([Math]::Round($Path.Length / $ChunkSize) + 1)
            $DataChunk | Add-Member -MemberType NoteProperty -Name ChunkIndex -Value $Index
            $DataChunk | Add-Member -MemberType ScriptProperty -Name Length -Value { $this.Data.Length }
            $DataChunk.PSObject.TypeNames.Insert(0, 'DataChunk')
			
            if ($Path.Length - $Offset -lt $ChunkSize) {
                $ChunkSize = $Path.Length - $Offset
                $DataChunk.LastChunk = $true
            }
            $Bytes = New-Object Byte[] $ChunkSize
			
            Write-Progress -Activity "Calculate MD5 Fingerprint"`
                -Status ("Processing file {0}" -f $DataChunk.FileName)`
                -CurrentOperation ("Crunching chunk {0} of {1}" -f $DataChunk.ChunkIndex, $DataChunk.ChunkCount)`
                -PercentComplete $(($DataChunk.ChunkIndex / $DataChunk.ChunkCount) * 100)
			
            [void] $InStream.Read($Bytes, 0, $ChunkSize)
            $Offset += $ChunkSize
            $Index++
            if ($DataChunk.LastChunk) {
                [void] $MD5.TransformFinalBlock($Bytes, 0, $DataChunk.Length)
            }
            else {
                [void] $MD5.TransformBlock($Bytes, 0, $ChunkSize, $Bytes, 0)
            }
					
        } while (-not $DataChunk.LastChunk)
		
        $result = ""
        foreach ($Byte in $MD5.Hash) {
            $result += "{0:X2}" -f $Byte
        }
        #$MD5.
        $result
		
        $InStream.Close()

    }
    end {
        $Offset = $null
    }
}
<#
	.Synopsis
	Checks if the process is running elevated.
	
	.Description
 	Checks if the process is running under elevated credentials, return true or false.
  
	
 	.Example
 	Test-AMElevation
 	
 	
#>
function Test-AMElevation
{
	[cmdLetbinding()]
	param
	(
	
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	
		Return $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Creates a new or updates an existing application in VMware view.

	.Description
 	Creates a new or updates an existing in VMware view.
  
	.Parameter ConnectionServer
 	Name,fqdn or ip of the connectionserver to connect to.

    .Parameter Name
    Name of the application to create/update

    .Parameter DisplayName
    The displayname for the application to create/update

    .Parameter Path
    Path of the application executable to publish

    .Parameter IconPath
    Path of an alternate ico file to use as icon, default gets icon from application exe.

    .Parameter Principal
    The name of the security principal to assign to the published application, can be group or user name.
  
	.NOTES
	Requires LDIFDE to be present on the computer where command is executed from
 
 	.Example
 	Set-AMViewApplication -Name "Notepad" -Path "C:\windows\system32\notepad.exe" -Principal "Domain Users" -ConnectionServer ViewServer.lab.local

#>
function Set-AMViewApplication {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param
    (		
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $Name,
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [string]
        $DisplayName = $Name,
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $false, Position = 2)]
        [string]
        $Path,
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [string]
        $IconPath = $Path,
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $false, Position = 4)]
        [string]
        $Principal,
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $false, Position = 5)]
        [string]
        $ConnectionServer
    )
    
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

        
        

    If (-not (Test-Path $Path)) {
        throw "$Path was not found, unable to publish application"
    }
    If (-not (Test-Path  "$env:windir\system32\ldifde.exe")) {
        Write-AMWarning "$env:windir\system32\LDIFDE.exe was not found, unable to publish application"
    }
    else {
        $PrincipalLDAP = Get-AMLDAPPath $Principal
        If ($null -eq $PrincipalLDAP) {
            throw "Unable to find group or user: $principal"
        }
            
        $Node = (Get-Item "HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\Node Manager" -ea SilentlyContinue)
        If ($null -eq $Node) {
            Write-AMWarning "Unable to find Agent Node information on this machine, unable to publish application"
        }
        else {
            $DirEntry = Get-AMDirectoryEntry $PrincipalLDAP
            $DomainFQDN = ""
            $DirEntry.Path.Split(",") | ? { $_.StartsWith("DC=") } | % { $DomainFQDN += $_.Replace("DC=", ".") }
            $DomainFQDN = $DomainFQDN.TrimStart(".")
            $PrincipalSID = (Get-AMSID -Name $Principal).Value           
            $Base64SID = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("<SID=$PrincipalSID>"))
            $ServerPoolDN = $Node.GetValue("Server Pool DN")
            $Item = Get-Item $Path
            If ($Item.VersionInfo) {
                $Version = $Item.VersionInfo.ProductVersion
            }
            Else {
                $Version = 1
            }
            $Publisher = "Published by Automation Machine"
            # Create new stringbuilder object
            $LDIF = New-Object System.Text.StringBuilder
            $LDIFEnd = New-Object System.Text.StringBuilder
            # Icon handling
                
            If ($IconPath.EndsWith("*.ico")) {
                Add-Type -AssemblyName System.Drawing
                try {
                    $Icon = [System.Drawing.Icon]($IconPath)
                }
                catch {
                    Write-AMWarning "$IconPath is an invalid icon file"
                }
            }
            else {
                try {
                    $Icon = ([AutomationMachine.Utilities.IO.IconExtractor.IconExtractor]($IconPath)).GetIcon(0)
                }
                catch {
                    Write-AMWarning "Unable to get icon from $IconPath"
                }
            }
            If (Test-Path variable:Icon) {
                # Split icon to get the high res icons from the file
                $Icons = [AutomationMachine.Utilities.IO.IconExtractor.IconUtil]::Split($Icon)
                # Get 32-bit icons
                $Icons = $icons | ? { [AutomationMachine.Utilities.IO.IconExtractor.IconUtil]::GetBitCount($_) -eq 32 }
                ForEach ($i in $Icons) {
                    $memStream = New-Object System.IO.MemoryStream
                    $bmp = [AutomationMachine.Utilities.IO.IconExtractor.IconUtil]::ToBitmap($i)
                    $bmp.Save($memStream, [System.Drawing.Imaging.ImageFormat]::Png)
                    $bytes = $memStream.ToArray()
                    $base64 = [System.Convert]::ToBase64String($bytes)
                    $Hash = Get-AMFingerprint -Algorithm MD5 -InputString $base64
                    $IconGUID = [Guid]::NewGuid().ToString()
                    [void] $LDIF.AppendLine("dn: CN=$IconGUID,OU=Application Icons,DC=vdi,DC=vmware,DC=int")
                    [void] $LDIF.AppendLine("changetype: add")
                    [void] $LDIF.AppendLine("objectClass: pae-ApplicationIcon")
                    [void] $LDIF.AppendLine("cn: $IconGUID")
                    [void] $LDIF.AppendLine("pae-IconHeight: $($i.Height)")
                    [void] $LDIF.AppendLine("pae-IconData:: $base64")
                    [void] $LDIF.AppendLine("pae-IconHash: $Hash")
                    [void] $LDIF.AppendLine("pae-IconWidth: $($i.Width)")
                    [void] $LDIF.AppendLine()
                        
                    [void] $LDIFEnd.AppendLine()
                    [void] $LDIFEnd.AppendLine("dn: CN=$Name,OU=Applications,DC=vdi,DC=vmware,DC=int")
                    [void] $LDIFEnd.AppendLine("changetype: modify")
                    [void] $LDIFEnd.AppendLine("add: pae-IconDN")
                    [void] $LDIFEnd.AppendLine("pae-IconDN: CN=$IconGUID,OU=Application Icons,DC=vdi,DC=vmware,DC=int")
                    [void] $LDIFEnd.AppendLine("-")
                }
            }
            else {
                Write-AMWarning "Publishing application without icon"
            }

            [void] $LDIF.AppendLine("dn: cn=_vdmexport,ou=groups,dc=vdi,dc=vmware,dc=int")
            [void] $LDIF.AppendLine("changetype: add")
            [void] $LDIF.AppendLine("objectClass: group")
            [void] $LDIF.AppendLine()
            [void] $LDIF.AppendLine("dn: cn=_vdmexport,ou=groups,dc=vdi,dc=vmware,dc=int")
            [void] $LDIF.AppendLine("changetype: modify")
            [void] $LDIF.AppendLine("add: member")
            [void] $LDIF.AppendLine("member:: $Base64SID")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine()
            [void] $LDIF.AppendLine("dn: cn=_vdmexport,ou=groups,dc=vdi,dc=vmware,dc=int")
            [void] $LDIF.AppendLine("changetype: delete")
            [void] $LDIF.AppendLine()
            [void] $LDIF.AppendLine("dn: CN=$PrincipalSID,CN=ForeignSecurityPrincipals,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("changetype: modify")
            [void] $LDIF.AppendLine("replace: objectClass")
            [void] $LDIF.AppendLine("objectClass: foreignSecurityPrincipal")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine("replace: description")
            [void] $LDIF.AppendLine("description: CN=$($DirEntry.cn)")
            [void] $LDIF.AppendLine("description: DOMAIN=$DomainFQDN")
            [void] $LDIF.AppendLine("description: DISTINGUISHEDNAME=$($DirEntry.distinguishedName)")
            [void] $LDIF.AppendLine("description: SN=$($DirEntry.sn)")
            [void] $LDIF.AppendLine("description: EMAIL=$($DirEntry.mail[0])")
            [void] $LDIF.AppendLine("description: GIVENNAME=$($DirEntry.givenName)")
            [void] $LDIF.AppendLine("description: DISPLAYNAME=$DomainFQDN\$($DirEntry.cn)")            
            [void] $LDIF.AppendLine("description: $(($DirEntry.objectClass | Select -Last 1).ToUpper())=$($DirEntry.cn)")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine()
            [void] $LDIF.AppendLine("dn: CN=$Name,OU=Applications,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("changetype: add")
            [void] $LDIF.AppendLine("objectClass: pae-Entity")
            [void] $LDIF.AppendLine("objectClass: pae-App")
            [void] $LDIF.AppendLine("objectClass: pae-WinApp")
            [void] $LDIF.AppendLine("objectClass: pae-ThinWinApp")
            [void] $LDIF.AppendLine("objectClass: pae-RDSApplication")
            [void] $LDIF.AppendLine("cn: $Name")
            [void] $LDIF.AppendLine("pae-Version: $Version")
            [void] $LDIF.AppendLine("pae-Disabled: 0")
            [void] $LDIF.AppendLine("pae-DisplayName: $DisplayName")
            [void] $LDIF.AppendLine("pae-AdminFolderDN: OU=Groups,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("pae-Publisher: $Publisher")
            [void] $LDIF.AppendLine("pae-ApplicationExecutablePath: $Path")
            [void] $LDIF.AppendLine()
            [void] $LDIF.AppendLine("dn: CN=$Name,OU=Applications,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("changetype: modify")
            [void] $LDIF.AppendLine("replace: objectClass")
            [void] $LDIF.AppendLine("objectClass: pae-Entity")
            [void] $LDIF.AppendLine("objectClass: pae-App")
            [void] $LDIF.AppendLine("objectClass: pae-WinApp")
            [void] $LDIF.AppendLine("objectClass: pae-ThinWinApp")
            [void] $LDIF.AppendLine("objectClass: pae-RDSApplication")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine("replace: pae-Version")
            [void] $LDIF.AppendLine("pae-Version: $Version")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine("replace: pae-Disabled")
            [void] $LDIF.AppendLine("pae-Disabled: 0")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine("replace: pae-DisplayName")
            [void] $LDIF.AppendLine("pae-DisplayName: $DisplayName")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine("replace: pae-AdminFolderDN")
            [void] $LDIF.AppendLine("pae-AdminFolderDN: OU=Groups,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine("replace: pae-Publisher")
            [void] $LDIF.AppendLine("pae-Publisher: $Publisher")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine("replace: pae-ApplicationExecutablePath")
            [void] $LDIF.AppendLine("pae-ApplicationExecutablePath: $Path")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine()
            [void] $LDIF.AppendLine("dn: CN=$Name,OU=Applications,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("changetype: modify")
            [void] $LDIF.AppendLine("add: member")
            [void] $LDIF.AppendLine("member: CN=$PrincipalSID,CN=ForeignSecurityPrincipals,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("-")
            [void] $LDIF.AppendLine()
            [void] $LDIF.AppendLine("dn: CN=$Name,OU=Applications,DC=vdi,DC=vmware,DC=int")
            [void] $LDIF.AppendLine("changetype: modify")
            [void] $LDIF.AppendLine("add: pae-Servers")
            [void] $LDIF.AppendLine("pae-Servers: $ServerPoolDN")
            [void] $LDIF.AppendLine("-")
                
                
            [void] $LDIF.Append($LDIFEnd.ToString())
                 
            Set-Content -Value $LDIF -Path $env:temp\LDIF.ldf
            [void] (& "$env:windir\system32\ldifde.exe" -i -f $env:temp\LDIF.ldf -s $ConnectionServer -z)
            If ($LASTEXITCODE -ne 0) {
                throw "Unable to publish application, use ldifde -i -f $env:temp\LDIF.ldf -s $ConnectionServer -z to troubleshoot LDF file"
            }
                
        }                   
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Appends a string to an existing registry value.
	
	.Description
 	Appends a string to an existing registry value. Creates a new value if it not yet exists.
  
	.Parameter Path
 	The registry key where the value resides.
	
	.Parameter Name
	The value we wish to append to
	
	.Parameter Value
	The string value to append to the registryvalue.
  
	.Example
 	Add-AMRegistryString -Path "HKCU:\Automation Machine" -Name "RegistryValue" -Value ";test" 	
 	
#>
function Add-AMRegistryString {
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
		[string]
		$Path,
		[parameter(mandatory = $true, ValueFromPipeline = $false, Position = 1)]
		[string]
		$Name,
		[parameter(mandatory = $true, ValueFromPipeline = $false, Position = 2)]
		[string]
		$Value		
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	$Path = Convert-AMRegistryPath -Path $Path
		
	if (Test-Path $Path) {
		$Append = (Get-ItemProperty -Path $Path).$Name
			
		If ($null -eq $Append) {
			Set-ItemProperty -Path $Path -Name $Name -Value $Value
		}
		else {
			If ($Append -is [System.String] ) {
				Set-ItemProperty -Path $Path -Name $Name -Value "$Append$Value"
			}
			elseif ($Append -is [System.String[]]) {
				$NewVal = $Append + $Value
				Set-ItemProperty -Path $Path -Name $Name -Value $NewVal
					
			}
			else {
				Write-AMWarning "Registry value is not a string type, could not add string"
			}	
		}
	} else {
		Write-AMWarning "The path to append registry string doesn't exist"
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Map a drive letter to an UNC path.

	.Description
 	Map a drive letter to an UNC path. If username and password are not specified, the current credentails will be used.
  
	.Parameter DriveLetter
 	Drive letter to map the UNC path to.
	
	.Parameter UNCPath
 	UNC Path to connect to. (i.e. \\Server\Share)
	
	.Parameter Username
	Optional Username to use (i.e. MyDomain\MyUsername)
	
	.Parameter Password
	Mandatory if username was specified.
 
 	.Example
 	Connect-AMDrive -Driveletter h: -UNCPath \\fileserver\share
#>
function Connect-AMDrive
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true)]
		[string]
		$DriveLetter,

		[parameter(mandatory=$true)]
		[string]
		$UNCPath,
		
		[parameter(mandatory=$false)]
		[string]
		$Username,
		
		[parameter(mandatory=$false)]
		[string]
		$Password
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	if (!$driveLetter.EndsWith(":")) {$driveletter += ":"}
				

		if (-not([string]::IsNullOrEmpty($username))) {
			$net = New-Object -ComObject WScript.Network		
			$net.MapNetworkDrive($driveletter, $uncPath, $true, $Username, $Password)
		}
		else {
			$net = New-Object -ComObject WScript.Network
			$net.MapNetworkDrive($driveletter, $uncPath)
		}
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Map a network printer.

	.Description
 	Map a network printer
  	
	.Parameter UNCPath
 	UNC Path to connect to. (i.e. \\Server\Share)
	 
 	.Example
 	Connect-AMPrinter -UNCPath "\\fileserver\HP LaserJet"
	
	.Example 
	"\\fileserver\HP Laserjet" | Connect-Printer
#>
function Connect-AMPrinter
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$UNCPath
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

					

		$net = New-Object -ComObject WScript.Network
		$net.AddWindowsPrinterConnection($UNCPath)	
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Disconnects a mapped drive.

	.Description
 	Disconnects a mapped drive.
  
	.Parameter DriveLetter
 	Drive letter to disconnect
 
 	.Example
 	Disconnect-AMDrive -DriveLetter h:
#>
function Disconnect-AMDrive
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true)]
		[string]
		$DriveLetter
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	if (!$driveLetter.EndsWith(":")) {$driveletter += ":"}
				

		$net = New-Object -ComObject WScript.Network
		$net.RemoveNetworkDrive($DriveLetter)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Disconnect a network printer.

	.Description
 	Disconnect a network printer
  	
	.Parameter UNCPath
 	UNC Path of the printer. (i.e. \\fileserver\HP LaserJet)
	
	.Parameter Force
 	Switch parameter indicating whether to force the removal of the mapped printer. If provided, the printer connection is removed whether or not a user is connected.
	
	.Parameter UpdateProfile
 	Switch parameter indicating whether to save the change in the user's profile. If provided, the printer connection is removed from the user profile.	 

	.Example
 	Disonnect-AMPrinter -UNCPath "\\fileserver\HP LaserJet"
	
	.Example 
	"\\fileserver\HP Laserjet" | Disonnect-AMPrinter
#>
function Disconnect-AMPrinter
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$UNCPath,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$Force,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[Switch]
		$UpdateProfile
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

					

		$net = New-Object -ComObject WScript.Network
		$net.RemovePrinterConnection($UNCPath,$Force.IsPresent,$UpdateProfile.IsPresent)	
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Get the domainname for the computer.

	.Description
 	Gets the domainname for the computer, return $null if the computer is not a member of the domain
 
 	.Example
 	Get-AMComputerDomain

#>
function Get-AMComputerDomain
{
	[cmdLetbinding()]
	param
	(
		
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

			$DomainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
			If ([string]::IsNullOrEmpty($DomainName))
			{
				return $null
			}
			else
			{
				return $DomainName
			}
		
		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Gets a list of users that are currently logged on.

	.Description
 	Gets a list of users that are currently logged on. Return $null if no logged on users detected
  
	.Parameter Computername
	The name of the computer to get the sessions for, defaults to current computer name
	
	.Parameter IncludeConsole
 	Switch parameter. When provided it will include console sessions in the list of users.
	
	.Parameter IncludeSystem
 	Switch parameter. When provided it will include system sessions in the list of users. E.g. listen sessions and services sessions.
		
 
 	.Example
 	Get-AMLoggedOnUsers

	.Example
	Get-AMLoggedOnUsers -IncludeConsole -IncludeSystem
#>
function Get-AMLoggedOnUsers {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param
    (
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $ComputerName = $env:computername,		
	
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false)]
        [switch]
        $IncludeConsole,
		
        [parameter(ParameterSetName = "Default", mandatory = $false, ValueFromPipeline = $false)]
        [switch]
        $IncludeSystem
    )
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
    $SessionList = [AutomationMachine.Utilities.Windows.TerminalServices.WtsManager]::ListSessions($computername)
		
    $Sessions = New-object System.Collections.ArrayList
		
    ForEach ($Session in $SessionList) {
        $SessionObj = New-Object PSObject
        $SessionObj | Add-Member -Type NoteProperty -Name "SessionID" -Value $Session.Split()[0]
        $SessionObj | Add-Member -Type NoteProperty -Name "State" -Value $Session.Split()[1]
        $SessionObj | Add-Member -Type NoteProperty -Name "WinStationName" -Value $Session.Split()[2]
        $SessionObj | Add-Member -Type NoteProperty -Name "Username" -Value $Session.Split()[3]

        [void] $Sessions.Add($SessionObj)			
    }
    If (($IncludeConsole) -and ($IncludeSystem)) {			
        return $Sessions
    }
    Elseif ((-not $IncludeConsole) -and ($IncludeSystem)) {			
        return $Sessions | Where-Object { $_.WinStationName -ne "Console" }
    }
    elseif (($IncludeConsole) -and (-not $IncludeSystem)) {			
        return $Sessions | Where-Object { $_.WinstationName -ne "Services" -and $_.State -ne "Listen" }
    }
    else {
        return $Sessions | Where-Object { $_.WinstationName -ne "Services" -and $_.State -ne "Listen" -and $_.WinStationName -ne "Console" }
    }	
		
    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Get the computer architecture.

	.Description
 	Gets the computer architecture (x86 or x64) using WMI. The current username and password are used to connect.
  
	.Parameter Computer
 	Name of the computer to connect to.
  
	.NOTES
	Distributed filesystems are NOT supported
 
 	.Example
 	Server1 | Get-AMOperatingSystemArchitecture
 	
 	.Example
 	Get-AMOperatingSystemArchitecture -Computer Server1
#>
function Get-AMOperatingSystemArchitecture
{
	[CmdletBinding()]
	param
	(	
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Computer = $env:computername
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		$Arch = Get-WmiObject win32_processor -computername $computer | Where-Object {$_.deviceid -eq "CPU0"} | ForEach-Object {$_.AddressWidth}
		switch ($Arch)
		{
			32	{return "x86"}
			64	{return "x64"}
			default {throw "Could not determine os architecture"}
		}
			
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Checks if the computer requires a reboot.

	.Description
	 Checks if the computer requires a reboot by checking windows update, file pending operations and component based servicing, 
	 pending computer rename, and various other registries
 
 	.Example
 	Get-AMPendingReboot
#>
function Get-AMPendingReboot {

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    $RebootRequired = $false
    
    Set-Variable -Name am_cbs_reboot_pending_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.CBSRebootPendingVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_cbs_reboot_progress_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.CBSRebootProgressVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_cbs_packages_pending_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.CBSPackagesPendingVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_wu_reboot_required_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.WURebootRequiredVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_wu_post_reboot_reporting_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.WUPostRebootReportingVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_wu_services_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.WUServicesVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_server_manager_reboot_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.ServerManagerRebootVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_volatile_update_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.VolatileUpdateVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_computer_rename_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.ComputerRenameVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force
    Set-Variable -Name am_sccm_reboot_check -value ([boolean] (Get-AMVariable -Id $AmWellKnown::Plugins.GeneralSettings.SCCMRebootVariable.Id -ParentId $AmWellKnown::Plugins.GeneralSettings.Id).Value) -Force

    $RegistryPaths = New-Object System.Collections.Generic.List[string]

    # Component Based Servicing
    if ($am_cbs_reboot_pending_check) {
        $RegistryPaths.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    }
    if ($am_cbs_reboot_progress_check) {
        $RegistryPaths.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress')
    }
    if ($am_cbs_packages_pending_check) {
        $RegistryPaths.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending')
    }
    # Windows Update
    if ($am_wu_reboot_required_check) {
        $RegistryPaths.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    }
    if ($am_wu_post_reboot_reporting_check) {
        $RegistryPaths.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting')
    }
    # Server Manager
    if ($am_server_manager_reboot_check) {
        $RegistryPaths.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps')
    }

    foreach ($Path in $RegistryPaths) {
        if (Get-Item -LiteralPath $Path -ErrorAction Ignore) {
            $RebootRequired = $true
            Write-AMInfo "Registry Key [$Path] exists"
        }
    }

    # Checking for pending file renames, value should not be null
    $PropertyNames = @('PendingFileRenameOperations', 'PendingFileRenameOperations2')
    $FileRenameRegPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\'

    foreach ($PropertyName in $PropertyNames) {
        if (($PFROValue = Get-ItemProperty -LiteralPath $FileRenameRegPath -Name $PropertyName -ErrorAction Ignore) -and $PFROValue.($PropertyName)) {
            $RebootRequired = $true
            Write-AMInfo "`"$PropertyName`" registry exists with value(s) `"$($PFROValue.PendingFileRenameOperations)`""
        }
    }

    # Checking if key exists first, using "ErrorAction Ignore" will incorrectly return $true
    if ($am_volatile_update_check) {
        $UpdateVolatileRegPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Updates'
        if (Test-Path -LiteralPath $UpdateVolatileRegPath -PathType Container) {
            if ((Get-ItemProperty -LiteralPath $UpdateVolatileRegPath -Name 'UpdateExeVolatile' -ErrorAction Ignore | Select-Object -ExpandProperty UpdateExeVolatile) -ne 0) {
                $RebootRequired = $true
                Write-AMInfo "`"$UpdateVolatileRegPath\UpdateExeVolatile`" registry value is not `"0`""
            }
        }
    }

    # Checking for pending computer rename operation
    # Checking if key exists first, if not each will return $null
    # Check should return true if both values exist and are not the same
    if ($am_computer_rename_check) {
        $ActiveComputerNameRegPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
        $ComputerNameRegPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
		
        if (Test-Path -LiteralPath $ActiveComputerNameRegPath -PathType Container) {
            $ActiveComputerName = Get-ItemProperty -LiteralPath $ActiveComputerNameRegPath -Name 'ComputerName' -ErrorAction Ignore | Select-Object -ExpandProperty ComputerName
        }
        if (Test-Path -LiteralPath $ComputerNameRegPath -PathType Container) {
            $ComputerName = Get-ItemProperty -LiteralPath $ComputerNameRegPath -Name 'ComputerName' -ErrorAction Ignore | Select-Object -ExpandProperty ComputerName
        }
        if (($ActiveComputerName -and $ComputerName) -and ($ActiveComputerName -ne $ComputerName)) {
            $RebootRequired = $true
            Write-AMInfo "Active computer name `"$ActiveComputerName`" does not match `"$ComputerName`", computer rename operation pending"
        }
    }
		

    if (Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'DVDRebootSignal' -ErrorAction Ignore) {
        $RebootRequired = $true
        Write-AMInfo "`"Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`" has property `"DVDRebootSignal`""
    }
    if (Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon' -Name 'JoinDomain' -ErrorAction Ignore) {
        $RebootRequired = $true
        Write-AMInfo "`"Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon`" has property `"JoinDomain`""
    }
    if (Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon' -Name 'AvoidSpnSet' -ErrorAction Ignore) {
        $RebootRequired = $true
        Write-AMInfo "`"Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon`" has property `"AvoidSpnSet`""
    }

    if ($am_wu_services_check) {
        if (Get-ChildItem -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending' -ErrorAction Ignore) {
            $RebootRequired = $true
            Write-AMInfo "Windows Update have services pending"
        } 
    }
		
    # Detect SCCM pending reboot, could also check for these registry keys manually, but it seems like Cim method does it for ya:
    # "HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData"
    # "HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Updates Management\Handler\UpdatesRebootStatus"
    # "HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Updates Deployment\RebootFlag"
    # "HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\RebootFlag"
    if ($am_sccm_reboot_check) {
        try {
            $SCCMRebootPending = (Invoke-CimMethod -Namespace root/ccm/ClientSDK -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Ignore).RebootPending
            if ($SCCMRebootPending -eq 'True') {
                $RebootRequired = $true
                Write-AMInfo "SCCM reboot is pending"
            }
        }
        catch {
            # Empty catch, no SCCM client to test this so, just in case this fails
        }
    }

    if (Test-AMRegistry -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Automation Machine' -Property 'RebootNeeded' -Value 'True') {
        $RebootRequired = $true
        Write-AMInfo 'HKLM:\SOFTWARE\Automation Machine\RebootNeeded is true'
    }

    if (($AMDataManager.RebootNeeded -eq $true) -or ($global:am_rebooting -eq $true)) {
        $RebootRequired = $true
        Write-AMInfo '$AMDataManager.RebootNeeded or $am_rebooting is true'
    }

    if ($RebootRequired) {
        Write-AMInfo 'Windows reboot is required'
    }
		
    return $RebootRequired
		
    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}
<#
.SYNOPSIS
Gets a scheduled task folder's COM object.

.DESCRIPTION
The Get-AMScheduledTask Gets a scheduled task folder's COM object.

.PARAMETER Path
Specifies a path in Task Scheduler namespace.

.EXAMPLE
Get-AMScheduledTask -Folder "Automation Machine"
#>
function Get-AMScheduledTaskFolder {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]
        [string] $Path = "\"
    )

    $ScheduleService = New-Object -ComObject "Schedule.Service"
    $ScheduleService.Connect()
    try {
        $TaskFolder = $ScheduleService.GetFolder($Path)
    }
    catch {
        $TaskFolder = $null
    }

    return $TaskFolder
}

<#
	.Synopsis
	Gets target of a symbolic link.

	.Description
 	Gets target path of a symbolic link.
	
	.Parameter Path
	Specifies the path of the symbolic link.
  	 
 	.Example
 	Get-AMSymbolicLinkTarget -Path "d:\AM\Cache\CurrentCache"
#>
function Get-AMSymbolicLinkTarget
{
	[CmdletBinding()]
	param 
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$false)]
		[string] $Path
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		if (-not (Test-Path $Path)) {
			throw "Specified path does not exist: `"$Path`""
		}
		return [AutomationMachine.Utilities.IO.SymbolicLink]::GetSymbolicLinkTarget($Path)
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Imports a certificate

	.Description
 	Imports a certificate from a file or gets the certificate used on a website and imports that.
  	
	.Parameter Type
 	The type of certificate to import. Valid values are Web or File
	
	.Parameter Path
 	The path for the certificate file
	
	.Parameter Password
	The password needed to import a certificate (if needed).
	
	.Parameter StoreName
	The name of the certificate store to import to. See the supplied link for valid values.
	
	.Parameter StoreRoot
	The StoreRoot to import the certificate into. Valid values are CurrentUser or LocalMachine.
	
	.NOTES
	When using StoreRoot LocalMachine the user invoking this cmdlet needs to be a local admin and powershell should be running elevated when UAC is enabled.
	
	.LINK
	http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.storename.aspx
	
	.Example
 	Import-AMCertificate -Type Web -Path https://website -StoreName TrustedPeople -StoreRoot LocalMachine
	
	.Example 
	Import-AMCertificate -Type File -Path C:\Certificate.cer -StoreName Root -StoreRoot CurrentUser
	
	.Example
	Import-AMCertificate -Type File -Path C:\Certificate.pfx -Password "somepassword" -StoreName TrustedPublisher -StoreRoot LocalMachine
#>
function Import-AMCertificate
{

	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Path,
		
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[ValidateSet("Web","File")]
		[string]
		$Type,
		
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Password,
		
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$StoreName,
		
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[ValidateSet("LocalMachine","CurrentUser")]
		[string]
		$StoreRoot	
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

					


		# Get the certificate from File or from the website
		Switch ($Type) {
			"File"	
			{
				If (Test-Path $Path)
				{
					$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
					If ([string]::IsNullOrEmpty($Password)) {$Certificate.Import($Path)}
					If (-not [string]::IsNullOrEmpty($Password)) {$Certificate.Import($Path,$Password,"Exportable,PersistKeySet")}   
				}
			}
			"Web"	
			{
				Try
				{
					# Create a webrequest
					[Uri]$Uri = $Path
					$Request = [System.Net.HttpWebRequest]::Create($($uri.scheme + "://" + $uri.host))
					# Ask for a response from the website, this will populate the Certificate property in $Req.ServicePoint, but will also throw an error because the of the trust relation ship. We catch this in the catch statement.
					$Request.GetResponse()
					$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
					$Certificate.Import($Request.ServicePoint.Certificate.Export("cert"))
				}
				Catch [System.Net.WebException] 
				{
					If ($_.Exception.Message -eq "The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel.")
					{
						$Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
						$Certificate.Import($Request.ServicePoint.Certificate.Export("cert"))
					}
				}
			}
		}
			
		$Store = new-object System.Security.Cryptography.X509Certificates.X509Store($StoreName,$StoreRoot)    
		$Store.Open("MaxAllowed")    
		$Store.Add($Certificate)    
		$Store.Close()    
			
			
			
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Import a registry file (.reg).

	.Description
 	Imports a registry file using regedit.exe /s. Make sure you GPO allows registry tools to run from the commandline. Function return $True is succesful and return $False if not. 
  
	.Parameter Path
 	Location of the .reg file.
	
	.Parameter ExpandEnvVars
	Switch parameter that controls if environment variables are expanded.
  
	.NOTES
	Regrettably, reg.exe cannot be used because reg.exe doesn't work if registry editing is not allowed. Reg.exe incorrectly interprets the group policy settings causing it to fail even when command line tools are allowed to import files. Regedit.exe does not provide any error codes.
 
 	.Example
 	"c:\tmp\settings.reg" | Import-AMRegFile
 	
 	.Example
 	Import-AMRegFile -path "c:\tmp\settings.reg"
#>
function Import-AMRegFile
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Path,
		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[switch]
		$ExpandEnvVars
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

						

		Write-AMInfo "Importing registry file: $($Path)"
		
		
		If ($ExpandEnvVars)
		{
			
			$Content = [System.IO.File]::ReadAllText($Path) # Get-Content has issues with line breaks (`n instead of `r`n)
			# Replace all double \\ to single \, so all filepaths are back to "non-escaped" form
			$Content = $Content.Replace("\\","\")
			# Expand the env vars that are present in the regfile
			$Content = $Content | Expand-AMEnvironmentVariables -NoEscape 
			$ExpandedContent = ""
			ForEach ($line in $Content.Split("`n"))
			{
				# Replace all file\unc paths back to "escaped" form (e.g. C:\\windows\\system32, \\\\server\\share
				if (![System.Text.RegularExpressions.RegEx]::IsMatch($line,"^\[.*\]", [System.Text.RegularExpressions.RegexOptions]::Singleline))
				{
					$line = [System.Text.RegularExpressions.Regex]::Replace($line,"\\","\\")
					$line = [System.Text.RegularExpressions.Regex]::Replace($line,"\\","\")
				}
				$ExpandedContent += $line
				$ExpandedContent += [Environment]::NewLine
			}

			$TempFile = "$($am_workfolder)\$([guid]::newGuid()).reg"
			Set-Content -Value $ExpandedContent -Path $TempFile
			Start-AMProcess -Path "regedit.exe" -Arguments "/s `"$TempFile`""
			Remove-Item -Path $TempFile -Force
		}
		else
		{
			& regedit /s $Path
		}
		Write-AMInfo "Successfully imported registry file: $($Path)"

			
	
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Installs an MSI installer file

	.Description
	Wrapper function for msiexec.exe to install MSI files
	
	.Parameter Path
	Path to the installer file
  	
	.Parameter Properties
 	List of optional properties that need to be passed to the installer
	
	.Parameter Transforms
	List of optional transform files
	
	.Parameter LogFile
	Where to place the MSI log file. Defaults to user's temp folder (msiexec_00000000-0000-0000-0000-000000000000.log)
		
	.Example
 	Install-AMMSI -Path c:\temp\7z920.msi -Properties "TARGETDIR=c:\apps\7zip ALLUSERS=1" -Transforms c:\temp\transform1.mst,c:\temp\transform2.mst

#>
function Install-AMMSIfile {
    [CmdletBinding()]
    param
    (		
        [parameter(mandatory = $true)]
        [System.IO.FileInfo]
        $Path,
		
        [parameter(mandatory = $false)]
        [string]
        $Properties,
		
        [parameter(mandatory = $False)]
        [System.IO.FileInfo[]]
        $Transforms = @(),
		
        [parameter(mandatory = $False)]
        [System.IO.FileInfo]
        $LogFile = "$($env:temp)\msiexec_$([Guid]::NewGuid().ToString()).log",
		
        [parameter(mandatory = $false)]
        [string]
        $ExpectedReturnCodes = "0 3010"
	
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

			
    [System.Diagnostics.Process] $Process = New-Object System.Diagnostics.Process
    [System.Diagnostics.ProcessStartInfo] $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
			
    # Parse transforms files
			
    [string] $TransformsString = ""
    if ($Transforms.Count -gt 0) {
        $TransformsString = "TRANSFORMS="
        foreach ($Transform in $Transforms) {
            $TransformsString += "`"" + $Transform.FullName + "`";"
        }
        $TransformsString = $TransformsString.TrimEnd(";")
    }
			
    $StartInfo.FileName = "msiexec.exe"
    $StartInfo.Arguments = "/i `"$($Path.FullName)`" $TransformsString $Properties /passive REBOOT=`"ReallySuppress`" /log `"$($LogFile.FullName)`""
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $false
    $StartInfo.RedirectStandardError = $false
    $StartInfo.RedirectStandardInput = $false
			
    $Process.StartInfo = $StartInfo
    [void] $Process.Start()
			
    $ProcessID = $Process.Id
    if ([string]::IsNullOrEmpty($ProcessID)) {
        throw "Process launch of msiexec.exe failed for unknown reasons"
    }
    else {
        Write-AMInfo "Started process with id $ProcessID (msiexec.exe)"
        Write-AMInfo "Command: msiexec.exe $($StartInfo.Arguments)"
    }
			
    [void] $Process.WaitForExit()
    Write-AMInfo "Process with id $ProcessID (msiexec.exe) exited with ExitCode $($Process.ExitCode)"
			
    <# HHO: Disabling output of logfile to console
		if (Test-Path $LogFile)
		{
			Write-Host "******************************************* START MSI LOGFILE OUTPUT *******************************************`n"
			Get-Content -Path $LogFile | Out-Host
			Write-Host "`n******************************************** END MSI LOGFILE OUTPUT ********************************************"
		}
		#>
				
    #List of misiexec return codes: http://support.microsoft.com/kb/229683
		
    If (!$($ExpectedReturnCodes.Split().Contains($Process.ExitCode.ToString()))) {
        switch ($Process.ExitCode) {
            0 {
                Write-AMInfo "MSIEXEC: $($Path) installed successfully."
            }
            1601 {
                Throw "MSIEXEC: Installation failed: The Windows Installer service could not be accessed. Contact your support personnel to verify that the Windows Installer service is properly registered."
            }
            1602 {
                Throw "MSIEXEC: User cancel installation."
            }
            1603 {
                Throw "MSIEXEC: Fatal error during installation."
            }
            1604 {
                throw "MSIEXEC: Installation suspended, incomplete."
            }
            1605 {
                throw "MSIEXEC: This action is only valid for products that are currently installed."
            }
            1606 {
                throw "MSIEXEC: Feature ID not registered."
            }
            1607 {
                throw "MSIEXEC: Component ID not registered."
            }
            1608 {
                throw "MSIEXEC: Unknown property."
            }
            1609 {
                throw "MSIEXEC: Handle is in an invalid state."
            }
            1610 {
                throw "MSIEXEC: The configuration data for this product is corrupt. Contact your support personnel."
            }
            1611 {
                throw "MSIEXEC: Component qualifier not present."
            }
            1612 {
                throw "MSIEXEC: The installation source for this product is not available. Verify that the source exists and that you can access it."
            }
            1613 {
                throw "MSIEXEC: This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
            }
            1614 {
                throw "MSIEXEC: Product is uninstalled."
            }
            1615 {
                throw "MSIEXEC: SQL query syntax invalid or unsupported."
            }
            1616 {
                throw "MSIEXEC: Record field does not exist."
            }
            1618 {
                throw "MSIEXEC: Another installation is already in progress. Complete that installation before proceeding with this install."
            }
            1619 {
                throw "MSIEXEC: This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package."
            }
            1620 {
                throw "MSIEXEC: This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package."
            }
            1621 {
                throw "MSIEXEC: There was an error starting the Windows Installer service user interface. Contact your support personnel."
            }
            1622 {
                throw "MSIEXEC: Error opening installation log file. Verify that the specified log file location exists and is writable."
            }
            1623 {
                throw "MSIEXEC: This language of this installation package is not supported by your system."
            }
            1625 {
                throw "MSIEXEC: This installation is forbidden by system policy. Contact your system administrator."
            }
            1626 {
                throw "MSIEXEC: Function could not be executed."
            }
            1627 {
                throw "MSIEXEC: Function failed during execution."
            }
            1628 {
                throw "MSIEXEC: Invalid or unknown table specified."
            }
            1629 {
                throw "MSIEXEC: Data supplied is of wrong type."
            }
            1630 {
                throw "MSIEXEC: Data of this type is not supported."
            }
            1631 {
                throw "MSIEXEC: The Windows Installer service failed to start. Contact your support personnel."
            }
            1632 {
                throw "MSIEXEC: The temp folder is either full or inaccessible. Verify that the temp folder exists and that you can write to it."
            }
            1633 {
                throw "MSIEXEC: This installation package is not supported on this platform. Contact your application vendor."
            }
            1634 {
                throw "MSIEXEC: Component not used on this machine."
            }
            1624 {
                throw "MSIEXEC: Error applying transforms. Verify that the specified transform paths are valid."
            }
            1635 {
                throw "MSIEXEC: This patch package could not be opened. Verify that the patch package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer patch package."
            }
            1636 {
                throw "MSIEXEC: This patch package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer patch package."
            }
            1637 {
                throw "MSIEXEC: This patch package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
            }
            1638 {
                throw "MSIEXEC: Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel."
            }
            1639 {
                throw "MSIEXEC: Invalid command line argument. Consult the Windows Installer SDK for detailed command line help."
            }
            3010 {
                
    $AMDataManager.RebootNeeded = $true

            }
            default {
                throw "Unknown return code from msiexec.exe: $($Process.ExitCode)"
            }
        }
    }
    else {
        Write-AMInfo "MSIEXEC: installed successfully with expected return code: $($Process.ExitCode)"
        if ($Process.Exitcode -eq 3010) {
            
    $AMDataManager.RebootNeeded = $true

        }		
        if ($Process.ExitCode -eq 0) {
            Write-AMInfo "MSIEXEC: $($Path) installed successfully."
        }	
    }		

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Invokes a chocolatey package

	.Description
    Invokes a chocolatey package. 
    Can install/uninstall/update a package
  	
	.Parameter Action
    Action to perform with a package. Can be Install, Uninstall and Upgrade

    .Parameter Package
    Package name
     
    .Parameter Version
    Version of a package, leave empty for the latest version
     
    .Parameter Force
    Specify if force parameter is passed to chocolatey runtime for a specific action
     
    .Parameter Timeout
    The time in seconds to allow a chocolatey action to finish before timing out. Leave empty for default
     
    .Parameter InstallerArguments
    Install arguments to pass to the native installer in the package. Leave empty for default.
     
    .Parameter PackageParameters
    Parameters to pass to the package
     
    .Parameter AdditionalArguments
    Any additional arguments for Chocolatey
     
    .Parameter SuccessCodes
 	List of return codes (separated by space) that signals if executable has executed correctly.
	
	.Example 
	Invoke-AMChocolateyPackage -Action Install -Package vscode
	
	.Example
	Invoke-AMChocolateyPackage -Action Upgrade -Package vscode

	.Example

	Invoke-AMChocolateyPackage -Action Install -Package vscode -Timeout 300
	
#>
function Invoke-AMChocolateyPackage {
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Action = "Install",
        [parameter(mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Package,
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [string]$Version,
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Boolean]$Force = $false,        
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [string]$Timeout,        
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [string]$InstallerArguments,
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [string]$PackageParameters,           
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [string]$AdditionalArguments,        
        [parameter(mandatory = $false, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SuccessCodes = "0 3010"
    )
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
    $ChocoInstalled = $false
    if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
        $ChocoInstalled = $true
    }

    if ($ChocoInstalled -eq $true) {
        $Command = "& choco $Action $Package -y"

        if ($Version) {
            $Command = "$Command --version=`"$Version`""
        }
        if ($Force) {
            $Command = "$Command --force"
        }
        if ($Timeout) {
            $Command = "$Command --execution-timeout=$Timeout"
        }
        if ($InstallerArguments) {
            $Command = "$Command --install-arguments=`"$InstallerArguments`""
        }
        if ($PackageParameters) {
            $Command = "$Command --package-parameters=`"$PackageParameters`""
        }
        if ($AdditionalArguments) {
            $Command = "$Command AdditionalArguments"
        }

        $ChocoLogFilePath = "$am_logpath\Choco_$Action`_$Package`_$(Get-Date -f yyyyMMddHHmmss)-$(Get-Random).log"
        Write-AMInfo "Invoking Chocolatey package [$Package], package action [$Action]"

        try {
            Write-AMInfo "Executing command: [$Command]"
            Invoke-Expression $command -OutVariable ConsoleOutput | Tee-Object -FilePath $ChocoLogFilePath
            If (!$($SuccessCodes.Split().Contains($LASTEXITCODE.ToString()))) {
                throw "Chocolatey exited with code $LASTEXITCODE, and it's not expected success code $($SuccessCodes)"
            } 
            else {
                Write-AMInfo "Chocolatey process finished with Exit Code $LASTEXITCODE"	
            }
        }
        catch [Exception] {
            Write-AMWarning "There was a problem running Chocolatey package"					
            throw $_
        }
        finally {
            Write-AMInfo "Chocolatey console output log file: $ChocoLogFilePath"
        }
    }
    else {
        throw "Chocolatey is not installed or can't be found on the system"
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


}
<#
	.Synopsis
	Launches a custom script

	.Description
 	Launches a custom script and optionally wait for it or it's children to exit.
  	
	.Parameter Path
 	Path to the custom script to launch.
	
	.Parameter Arguments
 	Arguments to pass to the custom script.
	
	.Parameter ExpectedReturnCodes
 	String of codes that are expected to return from the external process. If the return code does not return the expected return code, the script will throw the output of the external process as an exception. Works only if the NoWait has NOT been used.
		
	.Example
	Invoke-AMCustomScript -Path D:\Test.cmd -ExpectedReturnCodes "0 3010"
	
	.Example
	Invoke-AMCustomScript -Path D:\test.ps1 -Arguments "-ExampleArgument ArgumentValue"
	
#>
function Invoke-AMCustomScript 
{
    [CmdletBinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false)]
		[string]
		$Path,

        [parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$Arguments,

        [parameter(mandatory=$false,ValueFromPipeline=$false)]
		[string]
		$ExpectedReturncodes = "0 3010"		
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{		
		$Extension = $Path.Split(".") | Select-Object -Last 1
		$return = ""
		# Determine what kind of script it is
		Write-AMInfo "Executing $($Path)"
		$OriginalForeColor = $Host.UI.RawUI.ForegroundColor
		$Host.UI.RawUI.ForegroundColor = [ConsoleColor]::White
		Write-Host "********************************** START CUSTOM SCRIPT OUTPUT ***************************************************`n"
		Switch ($Extension)
		{
			"cmd" {
				$result = Invoke-Expression "$env:windir\system32\cmd.exe /q /c `"$($Path)`" $($Arguments)"
				write-host $result
				if ($LASTEXITCODE -eq 3010)
				{
					
    $AMDataManager.RebootNeeded = $true

					$global:am_rebooting = $true
				}
				If (!$($SuccessCodes.Split().Contains($LASTEXITCODE.ToString())))
				{
					throw "Script did not exit with expected success code $($SuccessCodes)"
				}
				break;
			}
			"ps1" {
				$Return = Invoke-Expression "& '$Path' $Arguments"
				#$Return = . $($Path) $($Arguments) --> this one issues with multiple arguments
				If ($return -eq "reboot")
				{
					
    $AMDataManager.RebootNeeded = $true

					$global:am_rebooting = $true
				}
				break;
			}
			"vbs" {
				$result = Invoke-Expression "$env:windir\system32\cscript.exe //nologo `"$($Path)`" $($Arguments)"
				write-host $result
				if ($LASTEXITCODE -eq 3010)
				{
					
    $AMDataManager.RebootNeeded = $true

					$global:am_rebooting = $true
				}
				If (!$($SuccessCodes.Split().Contains($LASTEXITCODE.ToString())))
				{
					throw "Script did not exit with expected success code $($SuccessCodes)"
				}
				break;
			}
			default {
				throw "Unknown script type $Extension"
			}
		}
		Write-Host "`n********************************** END CUSTOM SCRIPT OUTPUT *****************************************************"
		$Host.UI.RawUI.ForegroundColor = $OriginalForeColor
		#Return execution to filesystem provider to prevent strange errors that might occur.
		Set-Location $env:TEMP 
			
	}
	catch [Exception]
	{
		# Check if we need to restore consolecolor, if exception was caught during execution of external script, we need to restore the orignal foregroundcolor, and print the end custom script to host
		Write-Host "`n********************************** END CUSTOM SCRIPT OUTPUT *****************************************************"					
		If (Test-Path variable:\OriginalForeColor)
		{
				
			If ($Host.UI.RawUI.ForegroundColor -ne $OriginalForeColor)
			{
				$Host.UI.RawUI.ForegroundColor = $OriginalForeColor
			}
				
		}
		# Return execution to filesystem provider to prevent strange errors that might occur.
		Set-Location $env:TEMP 
		throw $_
	}
								
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
	

<#
	.SYNOPSIS
	Return the results of a SQL query or operation
	
	.Description
 	Return the results of a SQL query or operation
	
	.Parameter DataSource
	The data source to use in the connection
	
	.Parameter Database
	The database within the data source

	.Parameter SqlCommand
	The SQL statement(s) to invoke against the database
	
	.Parameter Timeout
	The timeout, in seconds, to wait for the query to complete

	.Parameter Credential
	The credential to use in the connection, if any
	
	
	.EXAMPLE
	Invoke-AMSqlCommand.ps1 -Sql "SELECT TOP 10 * FROM Orders"
	Invokes a command using Windows authentication

	.EXAMPLE

	PS >$cred = Get-Credential
	PS >Invoke-AMSqlCommand.ps1 -Sql "SELECT TOP 10 * FROM Orders" -Cred $cred
	Invokes a command using SQL Authentication

	.EXAMPLE

	PS >$server = "MYSERVER"
	PS >$database = "MDaster"
	PS >$sql = "UPDATE Orders SET EmployeeID = 6 WHERE OrderID = 10248"
	PS >Invoke-AMSqlCommand $server $database $sql
	Invokes a command that performs an update

	.EXAMPLE

	PS >$sql = "EXEC SalesByCategory 'Beverages'"
	PS >Invoke-AMSqlCommand -Sql $sql
	Invokes a stored procedure

	.EXAMPLE

	Invoke-AMSqlCommand (Resolve-Path access_test.mdb) -Sql "SELECT * FROM Users"
	Access an Access database

	.EXAMPLE

	Invoke-AMSqlCommand (Resolve-Path xls_test.xls) -Sql 'SELECT * FROM [Sheet1$]'
	Access an Excel file

#>
function Invoke-AMSQLCommand
{
	[CmdletBinding(DefaultParameterSetName="Default")]
	param
	(
		# The data source to use in the connection
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false,Position=0)]
		[string] $DataSource = ".\SQLEXPRESS",
		## The database within the data source
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false,Position=1)]
		[string] $Database = "Northwind",

		## The SQL statement(s) to invoke against the database
		[parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true,Position=2)]
		[string[]] $SqlCommand,

		## The timeout, in seconds, to wait for the query to complete
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false,Position=3)]
		[int] $Timeout = 60,

		## The credential to use in the connection, if any.
		[parameter(ParameterSetName="Default",mandatory=$false,ValueFromPipeline=$false,Position=4)]
		$Credential
	)
	
		
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

			## Prepare the authentication information. By default, we pick
			## Windows authentication
			$authentication = "Integrated Security=SSPI;"

			## If the user supplies a credential, then they want SQL
			## authentication
			if($credential)
			{
				$credential = Get-Credential $credential
				$plainCred = $credential.GetNetworkCredential()
				$authentication =
					("uid={0};pwd={1};" -f $plainCred.Username,$plainCred.Password)
			}

			## Prepare the connection string out of the information they
			## provide
			$connectionString = "Provider=sqloledb; " +
								"Data Source=$dataSource; " +
								"Initial Catalog=$database; " +
								"$authentication; "

			## If they specify an Access database or Excel file as the connection
			## source, modify the connection string to connect to that data source
			if($dataSource -match '\.xls$|\.mdb$')
			{
				$connectionString = "Provider=Microsoft.Jet.OLEDB.4.0; " +
					"Data Source=$dataSource; "

				if($dataSource -match '\.xls$')
				{
					$connectionString += 'Extended Properties="Excel 8.0;"; '

					## Generate an error if they didn't specify the sheet name properly
					if($sqlCommand -notmatch '\[.+\$\]')
					{
						$err = 'Sheet names should be surrounded by square brackets, ' +
							'and have a dollar sign at the end: [Sheet1$]'
						Write-Error $err
						return
					}
				}
			}

			## Connect to the data source and open it
			$connection = New-Object System.Data.OleDb.OleDbConnection $connectionString
			$connection.Open()

			foreach($commandString in $sqlCommand)
			{
				$command = New-Object Data.OleDb.OleDbCommand $commandString,$connection
				$command.CommandTimeout = $timeout

				## Fetch the results, and close the connection
				$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $command
				$dataset = New-Object System.Data.DataSet
				[void] $adapter.Fill($dataSet)

				## Return all of the rows from their query
				$dataSet.Tables | Select-Object -Expand Rows
			}
			$connection.Close()

		
		
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

	
}

<#
	.Synopsis
	Creates a new share.

	.Description
 	Creates a new share, or removes and recreates an existing share and gives everyone full control on share level.
  
	.Parameter Name
 	The name of the share to create.
	
	.Parameter Path
	The path to the folder to share.
	
	.Parameter Description
	The description to set for the share
	
	.Parameter MaxConnections
	The max connections to set for the share, default is 16777216
	
	.Parameter Cache
	The cache settings to set for the share. Valid values are: Manual, None, Documents and Programs. Default is None.
 
 	.Example
 	New-AMShare -Path D:\TestFolder -Name TestShare -Description "This is a testshare" -MaxConnections 3 -Cache Documents

#>
function New-AMShare {
    param
    (
        [cmdLetbinding()]
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $Name,
		
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 1)]
        [string]
        $Path,
		
        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [string]
        $Description,
		
        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [int]
        $MaxConnections = 16777216,
		
        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 4)]
        [string]
        $Cache = "None"
    )
	
    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    if (test-path $Path) {  
        # Check if share name already exists
        if ($null -ne (Get-WmiObject -Class Win32_Share -Filter "Name='$Name'")) {
            $ExistingShare = Get-WmiObject -Class Win32_Share -Filter "Name='$Name'"
					
            $ExistingSharePath = $ExistingShare.Path
            Write-AMInfo "Share already existed with path: $($ExistingSharePath), removing"		
            [void] $ExistingShare.Delete()
        }
				
        $WMIObject = [wmiClass]"Win32_Share"
			
        $Trustee = ([wmiclass]'Win32_trustee').psbase.CreateInstance()
        $Trustee.SIDString = "S-1-1-0" #SID for everyone
			
        # Accessmask values
        # Fullcontrol = 2032127
        # Change = 1245631
        # Read = 1179785
			
        #Create access-list
        $ACE = ([wmiclass]'Win32_ACE').psbase.CreateInstance()
        $ACE.AccessMask = 2032127 
        $ACE.AceFlags = 3
        $ACE.AceType = 0
        $ACE.Trustee = $Trustee

        #Securitydescriptor containting access
        $SD = ([wmiclass]'Win32_SecurityDescriptor').psbase.CreateInstance()
        $SD.ControlFlags = 4
        $SD.DACL = $ace
        $SD.group = $trustee
        $SD.owner = $trustee
			
        $CreateResult = ($WMIObject.Create("$Path", "$Name", 0, $MaxConnections, "$Description", "", $sd)).ReturnValue 
        if ($CreateResult -ne 0) {
            switch ($CreateResult) {
                2 { $ErrMsg = "Access Denied" }
                8 { $ErrMsg = "Unknown Failure" }
                9 { $ErrMsg = "Invalid Name" }
                10 { $ErrMsg = "Invalid Level" }
                21 { $ErrMsg = "Invalid Parameter" }
                22 { $ErrMsg = "Duplicate Share" }
                23 { $ErrMsg = "Redirected Path" }
                24 { $ErrMsg = "Unknown Device or Directory" }
                25 { $ErrMsg = "Net Name Not Found" }
                default { $ErrMsg = "$($CreateResult): Unknown error code" }
            }
					
            throw $ErrMsg
        }
        else {
            # Set cache
            $Net = "%windir%\system32\net.exe" | Expand-AMEnvironmentVariables
            Start-AMProcess -Path $Net -Arguments "share `"$Name`" /CACHE:$Cache" -NoWait	
        }
    }
    else {
        throw "$($Path) does not exist, cannot share a non existing folder"
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Creates a windows application shortcut (.lnk)

	.Description
	Create a windows application shortcut (.lnk) using the WScript.Shell COM object

	.Parameter Name
	Name of the Shortcut.

	.Parameter Path
	Path of the shortcut on the filesystem

	.Parameter Target
	Target of the shortcut (i.e. c:\program files\internet explorer\iexplore.exe)

	.Parameter Arguments
	Optional argumuments to pass to the target of the shortcut

	.Parameter Description
	Description of the shortcuts. This description is shown when usere hovers their mouse over the shortcut. The default is empty.

	.Parameter IconPath
	The file where the shortcut's icon should be taken from. By default, the icon will be taken from the target.

	.Parameter IconIndex
	The icon index that should be taken from the file specified in the IconLocation parameter. By default the first(index=0) icon is used.

	.Parameter Workingdirectory
	Specifies the workingdirectory of the target. By default the parent directory of the target is used.

	.Parameter Windowstyle
	How should the window of the target be displayed. Options are Normal, Maximized or Minimized. Default is Normal.

	.Example
 	New-AMShortcut -Name MyExplorer.lnk -Path c:\tmp -target "C:\Program Files\Internet Explorer\iexplore.exe"

	.Example
 	New-AMShortcut -Path MyExplorer -arguments "http://www.loginconsultants.com" c:\tmp -target "C:\Program Files\Internet Explorer\iexplore.exe" -IconLocation "C:\Program Files\Internet Explorer\iexplore.exe" -IconIndex 1

#>
function New-AMShortcut {
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $true, ValueFromPipeline = $false)]
        [string]
        $Name,

        [parameter(mandatory = $true, ValueFromPipeline = $false)]
        [System.IO.DirectoryInfo]
        $Path,

        [parameter(mandatory = $true, ValueFromPipeline = $false)]
        [System.IO.FileInfo]
        $Target,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $arguments = [string]::Empty,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $description = [string]::Empty,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [System.IO.FileInfo]
        $IconPath = $Target,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [int]
        $IconIndex = 0,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [System.IO.DirectoryInfo]
        $Workingdirectory = $(Split-Path $Target),

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [AutomationMachine.Plugins.Windows.WindowStyle]
        $windowstyle = [AutomationMachine.Plugins.Windows.WindowStyle]::Normal

    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    #Write-Warning "ToDo in New-AMShortCut: Implement target type in AutomationMachine.Data.Types"

    $wsh = New-Object -ComObject WScript.Shell

    # Check for file extension
    if (-not $Name.EndsWith(".lnk")) {
        $Name = [string]::Join(".", @($Name, "lnk"))
    }

    #Remove existing lnk file
    $FullLnkPath = [string]::Join("\", @($Path, $Name))
    if (Test-Path $FullLnkPath) {
        Remove-Item -Path $FullLnkPath -Force
    }

    #Create Path if needed
    if (-not (Test-Path -Path $Path)) {
        [void] (New-Item -Path $Path -ItemType Directory -Force)
    }

    $lnk = $wsh.Createshortcut($FullLnkPath)
    $lnk.targetpath = $Target

    if (-not [string]::IsNullOrEmpty($Arguments)) {
        $lnk.Arguments = $Arguments
    }
    if (-not [string]::IsNullOrEmpty($Description)) {
        $lnk.Description = $Description.Trim()
    }
    if (-not [string]::IsNullOrEmpty($IconPath)) {
        $lnk.IconLocation = [string]::Join(",", @($IconPath, [System.Convert]::ToString($IconIndex)))
    }
    if (-not [string]::IsNullOrEmpty($WindowStyle)) {
        $lnk.WindowStyle = $WindowStyle
    }
    if (-not [string]::IsNullOrEmpty($WorkingDirectory)) {
        $lnk.WorkingDirectory = $WorkingDirectory
    }

    $lnk.Save()

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Creates a symbolic link.

	.Description
 	Creates a symbolic link, hard link, or directory junction.
	
	.Parameter Link
	Specifies the name of the symbolic link that is being created.
	
	.Parameter Target
	Specifies the path (relative or absolute) that the new symbolic link refers to.
	
	.Parameter Symbolic
	Creates a directory symbolic link.
	
	.Parameter Hard
	Creates a hard link instead of a symbolic link.
	
	.Parameter Junction
	Creates a directory junction.
  	 
 	.Example
 	New-AMSymbolicLink -Link "d:\AM\Cache\CurrentCache" -Target "d:\AM\Cache\riuuky1r.kju" -Junction
#>
function New-AMSymbolicLink
{
	[CmdletBinding(DefaultParameterSetName="Junction")]
	param 
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$false)]
		[string] $Link,
		
		[parameter(Mandatory=$true,ValueFromPipeline=$false)]
		[string] $Target,
		
		[parameter(ParameterSetName = "Symbolic",Mandatory=$true,ValueFromPipeline=$false)]
		[switch] $Symbolic,
		
		[parameter(ParameterSetName = "Hard",Mandatory=$true,ValueFromPipeline=$false)]
		[switch] $Hard,
		
		[parameter(ParameterSetName = "Junction",Mandatory=$true,ValueFromPipeline=$false)]
		[switch] $Junction
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		# Ensure target exists.
		if (-not(Test-Path $Target)) {
			throw "Target does not exist.`nTarget: $Target"
		}
 
		# Ensure link does not exist.
		if (Test-Path $Link) {
			throw "A file or directory already exists at the link path.`nLink: $Link"
		}
 
		$isDirectory = (Get-Item $Target).PSIsContainer
		$mklinkArg = ""
 			
		if (($PSCmdlet.ParameterSetName -eq "Symbolic") -and $isDirectory) {
			$mkLinkArg = "/D"
		}
			 
		if ($PSCmdlet.ParameterSetName -eq "Junction") {
			# Ensure we are linking a directory. (Junctions don't work for files.)
			if (-not($isDirectory)) {
				throw "The target is a file. Junctions cannot be created for files.`nTarget: $Target"
			}
				 
			$mklinkArg = "/J"
		}
			 
		if ($PSCmdlet.ParameterSetName -eq "Hard") {
			# Ensure we are linking a file. (Hard links don't work for directories.)
			if ($isDirectory) {
				throw "The target is a directory. Hard links cannot be created for directories.`nTarget: $Target"
			}
			 	
			$mkLinkArg = "/H"
		}
			 
		# Capture the MKLINK output so we can return it properly.
		# Includes a redirect of STDERR to STDOUT so we can capture it as well.
		$output = cmd /c mklink $mkLinkArg "$Link" "$Target" 2>&1
			 
		if ($lastExitCode -ne 0) {
			throw "MKLINK failed. Exit code: $lastExitCode`n$output"
		}
		else {
			Write-Output $output
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Creates a windows application shortcut (.lnk)

	.Description
	Create a windows application shortcut (.lnk) using the WScript.Shell COM object

	.Parameter Name
	Name of the Shortcut.

	.Parameter Path
	Path of the shortcut on the filesystem

	.Parameter TargetUrl
	TargetUrl of the shortcut (i.e. http://www.yoururl.com)

	.Parameter Description
	Description of the shortcuts. This description is shown when usere hovers their mouse over the shortcut. The default is empty.

	.Parameter IconPath
	The file where the shortcut's icon should be taken from. By default, the icon will be taken from the target.

	.Parameter IconIndex
	The icon index that should be taken from the file specified in the IconLocation parameter. By default the first(index=0) icon is used.

	.Example
 	New-AMWebShortcut -Name MyExplorer.lnk -Path c:\tmp -TargetUrl "http://www.yoururl.com"

#>
function New-AMWebShortcut {
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $true, ValueFromPipeline = $false)]
        [string]
        $Name,

        [parameter(mandatory = $true, ValueFromPipeline = $false)]
        [System.IO.DirectoryInfo]
        $Path,

        [parameter(mandatory = $true, ValueFromPipeline = $false)]
        [string]
        $TargetUrl = [string]::Empty,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [string]
        $description = [string]::Empty,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [System.IO.FileInfo]
        $IconPath,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        [int]
        $IconIndex = 0
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')



    $wsh = New-Object -ComObject WScript.Shell

    # Check for file extension
    if (-not $Name.EndsWith(".lnk")) {
        $Name = [string]::Join(".", @($Name, "lnk"))
    }

    #Remove existing lnk file
    $FullLnkPath = [string]::Join("\", @($Path, $Name))
    if (Test-Path $FullLnkPath) {
        Remove-Item -Path $FullLnkPath -Force
    }

    #Create Path if needed
    if (-not (Test-Path -Path $Path)) {
        [void] (New-Item -Path $Path -ItemType Directory -Force)
    }

    $lnk = $wsh.Createshortcut($FullLnkPath)
    $lnk.targetpath = $TargetUrl

    if (-not [string]::IsNullOrEmpty($Description)) {
        $lnk.Description = $Description.Trim()
    }
    if (-not [string]::IsNullOrEmpty($IconPath)) {
        $lnk.IconLocation = [string]::Join(",", @($IconPath, [System.Convert]::ToString($IconIndex)))
    }

    $lnk.Save()

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Registers an extension with an application.

	.Description
 	Registers an extension with an application.

	.Parameter Extension
 	The extension to register with the application

	.Parameter Application
	The full path to the application to register the extension with.

	.Parameter Description
	Optional. A description for the extension

	.Parameter Icon
	Optional. The icon to register with the extension.

	.Parameter ProgID
	Optional. The ProgID to register with the application.

	.Parameter LocalMachine
	Optional. Switch parameter indicating the file type should be registered on LocalMachine level instead of user level. Needs local admin rights.

	.NOTES
	LocalMachine parameter needs local administrator rights to be able to register the filetype.

 	.Example
 	Register-AMFileType -Extension ".jpga" -Application "C:\Program Files (x86)\IrfanView\i_view32.exe" -Description "IrfanView JPG file" -Icon "C:\Program Files (x86)\IrfanView\i_view32.exe,0"

	.Example
	Register-AMFileType -Extension ".jpga" -Application "C:\Program Files (x86)\IrfanView\i_view32.exe" -Description "IrfanView JPG file" -Icon "C:\Program Files (x86)\IrfanView\i_view32.exe,0" -LocalMachine

	.Example
	Register-AMFileType -Extension ".jpga" -ProgID "IrfanView_JPGA" -Application "C:\Program Files (x86)\IrfanView\i_view32.exe"


#>
function Register-AMFileType {
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $true)]
        [string]
        $Extension,

        [parameter(mandatory = $true)]
        [string]
        $Application,

        [parameter(mandatory = $false)]
        [string]
        $Description,

        [parameter(mandatory = $false)]
        [string]
        $Icon,

        [parameter(mandatory = $false)]
        [string]
        $ProgID,

        [parameter(mandatory = $false)]
        [switch]
        $LocalMachine
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    if ($localMachine) {
        $regPrefix = "Registry::HKEY_LOCAL_MACHINE\Software\Classes\"
    }
    else {
        $regPrefix = "Registry::HKEY_CURRENT_USER\Software\Classes\"
    }

    $regPathHKU = "Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\"
    $regPathHKUExt = Join-Path -Path "Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\" -ChildPath $extension
    $regPathHKUExtChoice = Join-Path -Path $regPathHKU -ChildPath 'UserChoice'

    # create ProgId entry in the registry
    if ([string]::IsNullOrEmpty($progId)) {
        $progId = "AutomationMachine" + $extension
    }

    $ProgIDPath = Join-Path -Path $regPrefix -ChildPath $progId
    $ProgIDCommandPath = Join-Path -Path $ProgIDPath -ChildPath '\shell\open\command'
    $ProgIDIconPath = Join-Path -Path $ProgIDPath -ChildPath '\DefaultIcon'

    if (-not(Test-Path $ProgIDPath)) {
        Write-AMInfo "$ProgIDPath does not exist, creating with description: $description"
        New-Item -Path $ProgIDPath -ItemType String -Value $description -Force
        New-Item $ProgIDCommandPath -Value "`"$application`" `"%1`"" -Force
    }
    else {
        Set-ItemProperty -Path $ProgIDPath -Name '(default)' -Value $description -Force
        if (-not(Test-Path $ProgIDCommandPath)) {
            New-Item $($regPrefix + $progId + "\shell\open\command") -ItemType String -Force
        }
        Set-ItemProperty $ProgIDCommandPath -Name "(default)" -Value "`"$application`" `"%1`"" -Force        
    }

    if (-not([string]::IsNullOrEmpty($icon))) {
        if (-not(Test-Path $ProgIDIconPath)) {
            New-Item $ProgIDIconPath -Value $icon -Force
        }
        else {
            Set-ItemProperty $ProgIDIconPath -Name "(default)" -Value "$icon" -Force
        }
    }

    # create filetype association with ProgId
    $ExtensionPath = Join-Path -Path $regPrefix -ChildPath $extension
    $ExtensionOpenWithPath = Join-Path -Path $ExtensionPath -ChildPath 'OpenWithProgids'

    if (-not(Test-Path $ExtensionOpenWithPath)) {
        New-Item -Path $ExtensionPath -Name 'OpenWithProgids' -Force
        New-ItemProperty -Path $ExtensionOpenWithPath -Name $progId -Value '' -Type String -Force
    }

    if (-not(Test-AMRegistry -Path $ExtensionPath -Property $progId)) {
        New-ItemProperty -Path $ExtensionPath -Name $progId -Type String -Value '' -Force
    }
    if (-not(Test-AMRegistry -Path $ExtensionOpenWithPath -Property $progId)) {
        New-ItemProperty -Path $ExtensionOpenWithPath -Name $progId -Type String -Value '' -Force
    }
    Set-ItemProperty -Path $ExtensionPath -Name '(default)' -Value $progId -Force
    
    $LoggedOnSids = (Get-ChildItem -Path 'Registry::HKEY_USERS' | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' }).PSChildName 
    Write-AMInfo "Found $($LoggedOnSids.Count) logged on user SIDs" 

    foreach ($sid in $LoggedOnSids) { 
    
        $regPathHKU = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\"
        $regPathHKUExt = Join-Path -Path $regPathHKU -ChildPath $extension
        $regPathHKUExtChoice = Join-Path -Path $regPathHKU -ChildPath 'UserChoice'
        $regPathHKUProgID = Join-Path -Path $regPathHKUExt -ChildPath 'OpenWithProgids'
        $regPathHKUOpenWith = Join-Path -Path $regPathHKUExt -ChildPath 'OpenWithList'
            
        if (Test-Path $regPathHKUExtChoice) {
            [void] { 
                $ParentACL = Get-Acl -Path $regPathHKUExt
                $UserChoiceACL = Get-Acl -Path $regPathHKUExtChoice
                $UserChoiceACL.SetAccessRuleProtection($false, $true)
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($ParentACL.Owner, 'FullControl', 'Allow')
                $UserChoiceACL.SetAccessRule($rule)
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($ParentACL.Owner, 'SetValue', 'Deny')
                $UserChoiceACL.RemoveAccessRule($rule)
                Set-Acl -Path $regPathHKUExtChoice -AclObject $UserChoiceACL
                Write-AMInfo 'Removed protection from FTA User Choice registry key for the user on SID: $sid'
                Remove-Item -Path $regPathHKUExtChoice -Recurse -Force 
            }
        }

        if (-not (Test-Path $regPathHKUProgID)) {
            New-Item -Path $regPathHKUExt -Name 'OpenWithProgids' -Force            
        } 
        if (-not(Test-AMRegistry -Path $regPathHKUProgID -Property $progId)) {
            New-ItemProperty -Path $regPathHKUProgID -Name $progId -Type Unknown -Value ([byte[]]@()) -Force
        }

        $ExeFile = $Application.Split('\')[-1]

        if (-not (Test-Path $regPathHKUOpenWith)) {
            New-Item -Path $regPathHKUExt -Name 'OpenWithList' -Force
            New-ItemProperty -Path $regPathHKUOpenWith -Name 'a' -Type String -Value $ExeFile -Force
            New-ItemProperty -Path $regPathHKUOpenWith -Name 'MRUList' -Type String -Value 'a' -Force           
        }
        else {
            $OpenWithPrograms = Get-ItemProperty -Path $regPathHKUOpenWith | Select-Object -Property * -ExcludeProperty MRUList, PSPath, PSParentPath, PSChildName, PSProvider

            (97..(97 + 25)).ForEach( {
                    if ($($OpenWithPrograms.[char]$_) -and (Test-AMRegistry -Path $regPathHKUOpenWith -Property $([char]$_) -Value $ExeFile)) {      
                        if (Test-AMRegistry -Path $regPathHKUOpenWith -Property 'MRUList') {
                            Set-ItemProperty -Path $regPathHKUOpenWith -Name 'MRUList' -Value $(([char]$_) + (Get-ItemPropertyValue -Path $regPathHKUOpenWith -Name 'MRUList')) -Force
                        }
                        else {
                            New-ItemProperty -Path $regPathHKUOpenWith -Name 'MRUList' -Type String -Value $([char]$_) -Force 
                        }
                        break
                    }
                    elseif (-not ($OpenWithPrograms.[char]$_)) {
                        New-ItemProperty -Path $regPathHKUOpenWith -Name $([char]$_) -Type String -Value $ExeFile -Force
                        if (Test-AMRegistry -Path $regPathHKUOpenWith -Property 'MRUList') {
                            Set-ItemProperty -Path $regPathHKUOpenWith -Name 'MRUList' -Value $(([char]$_) + (Get-ItemPropertyValue -Path $regPathHKUOpenWith -Name 'MRUList')) -Force
                        }
                        else {
                            New-ItemProperty -Path $regPathHKUOpenWith -Name 'MRUList' -Type String -Value $([char]$_) -Force 
                        }
                        break
                    }    
                })
        }
    
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Registers a scheduled task on the computer

	.Description
 	Registers a scheduled task on the computer.

	.Parameter TaskName
 	Name of the task to register.

	.Parameter Command
	The command to schedule

	.Parameter Arguments
	Arguments for the command

	.Parameter WorkingDir
	WorkingDir for the command

	.Parameter Credentials
	The credentials to run the scheduled task with

	.Parameter HighestPrivilege
	Switch parameter to indicate task should run with highestprivilege

	.Parameter RunOnlyWhenLoggedOn
	Switch parameter to indicate task should only run when user is logged on

	.Parameter Trigger
	The trigger to register for this task, valid values are Startup,Logon,Once,Weekly,Daily,Event

	.Parameter At
	The time to schedule the task, only needed for Once,Weekly and Daily triggers

	.Parameter DaysInterval
	The interval in days to register for the task, only valid for Daily trigger. Default this is set to 1, to run every day

	.Parameter DaysOfWeek
	The DaysOfWeek to run the task, only valid for Weekly trigger.

	.Parameter WeeksInterval
	The interval in weeks to register for the task, only valid for Weekly trigger. Default this is set to 1 , to run every week.

	.Parameter EventLog
	The eventlog to use for the Event trigger.

	.Parameter EventID
	The EventID to use for the Event trigger.

	.Example
 	$Cred = New-Object AutomationMachine.Data.Types.Credentials
	$Cred.Username = "username"
	$Cred.Password = "somepassword"
	Register-AMScheduledTask -TaskName "TestName" -Command "c:\windows\system32\windowspowershell\v1.0\powershell.exe" -arguments "-file 'c:\path to script.ps1'" -WorkingDir "C:\windows" -Credentials $Cred -RunOnlyWhenLoggedOn -Trigger Daily -At "12:00"

	This example creates a scheduled task that runs every day, only when the user is logged on

 	.Example
 	$Cred = New-Object AutomationMachine.Data.Types.Credentials
	$Cred.Username = "username"
	$Cred.Password = "somepassword"
	Register-AMScheduledTask -TaskName "TestName" -Command "c:\windows\system32\windowspowershell\v1.0\powershell.exe" -arguments "-file 'c:\path to script.ps1'" -WorkingDir "C:\windows" -Credentials $Cred -HighestPrivilege -Trigger Daily -At "12:00" -DaysInterval 2

	This example creates a scheduled task that runs every other day with highest privileges.

 	.Example
 	$Cred = New-Object AutomationMachine.Data.Types.Credentials
	$Cred.Username = "username"
	$Cred.Password = "somepassword"
	Register-AMScheduledTask -TaskName "TestName" -Command "c:\windows\system32\windowspowershell\v1.0\powershell.exe" -arguments "-file 'c:\path to script.ps1'" -WorkingDir "C:\windows" -Credentials $Cred -Trigger Weekly -At "12:00" -DaysofWeek "Monday,Tuesday,Wednesday"

	This example creates a scheduled task that runs every week on Monday,Tuesday an Wednesday

 	.Example
 	$Cred = New-Object AutomationMachine.Data.Types.Credentials
	$Cred.Username = "username"
	$Cred.Password = "somepassword"
	Register-AMScheduledTask -TaskName "TestName" -Command "c:\windows\system32\windowspowershell\v1.0\powershell.exe" -arguments "-file 'c:\path to script.ps1'" -WorkingDir "C:\windows" -Credentials $Cred -Trigger Weekly -At "12:00" -DaysofWeek "Monday,Tuesday,Wednesday" -WeeksInterval 2

	This example creates a scheduled task that runs every other week on Monday,Tuesday an Wednesday

 	.Example
 	$Cred = New-Object AutomationMachine.Data.Types.Credentials
	$Cred.Username = "username"
	$Cred.Password = "somepassword"
	Register-AMScheduledTask -TaskName "TestName" -Command "c:\windows\system32\windowspowershell\v1.0\powershell.exe" -arguments "-file `"c:\path to script.ps1`"" -WorkingDir "C:\windows" -Credentials $Cred -HighestPrivilege -Trigger Startup

	This example create a scheduled task that runs at startup with highestprivileges

	.Example
 	$Cred = New-Object AutomationMachine.Data.Types.Credentials
	$Cred.Username = "username"
	$Cred.Password = "somepassword"
	Register-AMScheduledTask -TaskName "TestName" -Command "c:\windows\system32\windowspowershell\v1.0\powershell.exe" -arguments "-file `"c:\path to script.ps1`"" -WorkingDir "C:\windows" -Credentials $Cred -Trigger Logon

	This example create a scheduled task that runs at user logon

#>
function Register-AMScheduledTask {

    param
    (
        [CmdletBinding()]

        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $TaskName,

        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 1)]
        [string]
        $Command,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 2)]
        [string]
        $Arguments,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [string]
        $WorkingDir,

        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 4)]
        [AutomationMachine.Data.Types.Credentials]
        $Credentials,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 5)]
        [switch]
        $HighestPrivilege,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 6)]
        [switch]
        $RunOnlyWhenLoggedOn,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 7)]
        [ValidateSet("Startup", "Logon", "Once", "Weekly", "Daily", "Event")]
        [string]
        $Trigger,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 8)]
        [string]
        $At,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 9)]
        [int]
        $DaysInterval = 1,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 10)]
        [string]
        $DaysOfWeek = "Monday,Tuesday,Wednesday,Thursday,Friday,Saturday,Sunday",

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 11)]
        [int]
        $WeeksInterval = 1,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 12)]
        [int]
        $EventID,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 13)]
        [string]
        $EventLog,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        $RepetitionInterval,

        [parameter(mandatory = $false, ValueFromPipeline = $false)]
        $RepetitionDuration
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    
    if ($(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) -ne $true) {
        throw "Not an administrator, cannot continue"
    }


    #set up a connection to scheduled tasks management
    $ScheduleService = New-Object -ComObject "Schedule.Service"
    $ScheduleService.Connect()

    #get Automation Machine's scheduled tasks folder
    $TaskFolder = $ScheduleService.GetFolder("\") # root folder
    #	Try { $TaskFolder = $TaskFolder.GetFolder("Automation Machine")	}
    #	Catch { $TaskFolder = $TaskFolder.CreateFolder("Automation Machine") }

    # Let's check if scheduled task already exists, and remove if it does
    $TaskToDelete = $TaskFolder.GetTasks(1) | Where-Object { $_.Name -eq "$TaskName" } | Select-Object -First 1
    If ($TaskToDelete) {
        $TaskFolder.DeleteTask($TaskToDelete.Name, 0)
    }

    $Task = $ScheduleService.NewTask(0)
    # Check if we need to run with highest privilege
    If ($HighestPrivilege) {
        $Task.Principal.RunLevel = 1
    }
    else {
        $Task.Principal.RunLevel = 0
    }
    $Task.Settings.RunOnlyIfIdle = $false
    $Task.Settings.IdleSettings.StopOnIdleEnd = $false
    $Task.Settings.DisallowStartIfOnBatteries = $false
    $Task.Settings.StopIfGoingOnBatteries = $false
    $Task.Settings.DisallowStartIfOnBatteries = $true
    $Task.Settings.RunOnlyIfNetworkAvailable = $false

    #task settings help - http://msdn.microsoft.com/en-us/library/aa383512.aspx
    $Task.Settings.AllowDemandStart = $true
    $Task.Settings.RestartInterval = "PT5M"
    $Task.Settings.RestartCount = 3
    $Task.Settings.StartWhenAvailable = $true
    $Task.Settings.Enabled = $true

    $RegInfo = $Task.RegistrationInfo
    $RegInfo.Author = "Login Consultants"
    $RegInfo.Description = "Automation Machine Scheduled Task"

    # Create the action object
    $Action = $Task.Actions.Create(0)
    #$Action.Path = "$($env:windir)\system32\windowspowershell\v1.0\powershell.exe"
    $Action.Path = $Command
    If (!([string]::IsNullOrEmpty($Arguments))) {
        $Action.Arguments = "$Arguments"
    }
    If (!([string]::IsNullOrEmpty($WorkingDir))) {
        $Action.WorkingDirectory = $WorkingDir
    }

    # Create the trigger object
    $Triggers = $Task.Triggers

    #$Trigger.Repetition.Interval = $Int
    Switch ($Trigger) {
        "Once" {
            If ([string]::IsNullOrEmpty($At)) { throw "At parameter cannot be null when using triggers Once,Daily or Weekly" }
            $TimeAt = (Get-Date $At)
            $Trig = $Triggers.Create(1) # time trigger
            $Trig.StartBoundary = $TimeAt.ToString("yyyy-MM-ddTHH:mm:ss")
        }
        "Daily" {
            If ([string]::IsNullOrEmpty($At)) { throw "At parameter cannot be null when using triggers Once,Daily or Weekly" }
            $TimeAt = (Get-Date $At)
            $Trig = $Triggers.Create(2) # daily trigger
            $Trig.DaysInterval = $DaysInterval
            $Trig.StartBoundary = $TimeAt.ToString("yyyy-MM-ddTHH:mm:ss")
        }
        "Weekly" {
            If ([string]::IsNullOrEmpty($At)) { throw "At parameter cannot be null when using triggers Once,Daily or Weekly" }
            $TimeAt = (Get-Date $At)
            $Trig = $Triggers.Create(3) # weekly trigger
            $Trig.StartBoundary = $TimeAt.ToString("yyyy-MM-ddTHH:mm:ss")

            $Trig.WeeksInterval = $WeeksInterval
            # Create array for days of week	and count bitmask value of given days
            $ArrDaysOfWeek = $DaysOfWeek.Split(",")
            $daysOfWeekEnumValue = 0
            foreach ($day in $ArrDaysOfWeek) {
                if ($day -eq "Sunday") { $daysOfWeekEnumValue += 1 }
                if ($day -eq "Monday") { $daysOfWeekEnumValue += 2 }
                if ($day -eq "Tuesday") { $daysOfWeekEnumValue += 4 }
                if ($day -eq "Wednesday") { $daysOfWeekEnumValue += 8 }
                if ($day -eq "Thursday") { $daysOfWeekEnumValue += 16 }
                if ($day -eq "Friday") { $daysOfWeekEnumValue += 32 }
                if ($day -eq "Saturday") { $daysOfWeekEnumValue += 64 }
            }
            if ($daysOfWeekEnumValue -lt 1) { $Trigger.DaysInterval = 1 }
            else { $Trig.DaysOfWeek = $daysOfWeekEnumValue }
        }
        "Startup" { $Trig = $Triggers.Create(8) } # boot trigger
        "Logon" { $Trig = $Triggers.Create(9) }# logon trigger
        "Event" {
            if ([string]::IsNullOrEmpty($EventLog)) { throw "EventLog parameter cannot be null when using trigger Event" }
            if ([string]::IsNullOrEmpty($EventID)) { throw "EventID parameter cannot be null when using trigger Event" }
            $Trig = $Triggers.Create(0)
            $Trig.Subscription = "<QueryList><Query Id='1'><Select Path=`"$EventLog`">*[System[EventID=$EventID]]</Select></Query></QueryList>"
        }
    }

    # Configure task repetition
    if ($RepetitionInterval -gt 0) {
        $Trig.Repetition.Interval = "PT$($RepetitionInterval)M"
        if ($RepetitionDuration -gt 0) {
            $Trig.Repetition.Duration = "PT$($RepetitionDuration)M"
        }
    }

    If ([string]::IsNullOrEmpty($Credentials.Password)) {
        $Credentials.Password = $null
    }

    # Create the scheduled task, check if we need to runonly when logged on, run only whether logged on or not
    If ($RunOnlyWhenLoggedOn) {
        #Run only when user is logged on
        $TasksOutput = $TaskFolder.RegisterTaskDefinition($TaskName, $Task, 6, $Credentials.Username, $Credentials.Password, 3)
    }
    else {
        $TasksOutput = $TaskFolder.RegisterTaskDefinition($TaskName, $Task, 6, $Credentials.Username, $Credentials.Password, 1)
    }
    [void] [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService)
    Remove-Variable ScheduleService

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
.SYNOPSIS
Removes a Windows service.

.DESCRIPTION
The Remove-AMService cmdlet removes a Windows service.

.PARAMETER Name
Service name.

.EXAMPLE
Remove-AMService -Name MyService
#>
function Remove-AMService {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = "Name")]
        [string] $Name
    )

    $ServiceInstance = Get-CimInstance Win32_Service | Where-Object { $_.Name -eq $Name }
    $ServiceInstance | Remove-CimInstance
}

<#
	.Synopsis
	Removes a symbolic link.

	.Description
 	Removes a symbolic link, hard link, or directory junction.
	
	.Parameter Path
	Specifies the path to the symbolic link.
  	 
 	.Example
 	Remove-AMSymbolicLink -Link "d:\AM\Cache\CurrentCache"
#>
function Remove-AMSymbolicLink
{
	[CmdletBinding()]
	param 
	(
		[parameter(Mandatory=$true,ValueFromPipeline=$false)]
		[string] $Path
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		if (-not (Test-Path $Path)) {
			throw "Specified path does not exit: $Path"
		}
			
		$IsDirectory = (Get-Item $Path).PSIsContainer
		if ($IsDirectory) {
			cmd /c rmdir "$Path"
		}
		else {
			cmd /c del "$Path"
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Resolves the doublehop remoting problem

	.Description
 	Checks if we can connect to the centralshare, if not, connects to centralshare using serviceaccount credentials
  
	.Example
	Resolve-AMDoubleHopProblem
#>
function Resolve-AMDoubleHopProblem
{
	[cmdLetbinding()]
	param
	(
		
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		If ($am_offline -eq $false)
		{
			try {
				$Uri = New-Object Uri($AMCentralPath)
				If ($Uri.IsUnc -eq $true)
				{
					Push-Location
					Set-Location $AMCentralPath -ErrorAction Stop
					Pop-Location
				}
					
			}
			catch [System.UnauthorizedAccessException]
			{
				$_.Exception.GetType().ToString()
				$SecurePWD = ConvertTo-SecureString -AsPlainText -String $AMEnvironment.ServiceAccount.Password -Force
				$Credential = New-Object System.Management.Automation.PSCredential($AMEnvironment.ServiceAccount.Username,$SecurePWD)
				New-PSDrive -PSProvider FileSystem -Root $AMCentralPath -Name DoubleHopCheck -Credential $Credential
				Push-Location
				Set-Location DoubleHopCheck:
				Pop-Location
				Remove-PSDrive -Name DoubleHopCheck
			}
		}
	}
	catch [Exception]
	{
		# Do nothing if doublehop couldn't be resolved
	}
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Restarts the computer.

	.Description
 	Restarts the computer in amount of seconds that is specified. Tests if process is running elevated and exits powershell to prevent any other processing of scripts.
  
	.Parameter ShutdownTimer
 	Amount of seconds to wait before initiating the reboot (default is 30)
  
	.Example
 	Restart-AMComputer
#>
function Restart-AMComputer {
	param
	(
		[cmdLetbinding()]
		[parameter(mandatory = $false, ValueFromPipeline = $false, Position = 0)]
		[int]
		$ShutdownTimer = 30
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

	
    if ($(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) -ne $true) {
        throw "Not an administrator, cannot continue"
    }


	# Setting registry key to check if shutdown is already initiated, the key is automatically deleted after a reboot
	try {		
		$PropertyName = 'PendingFileRenameOperations'
		$FileRenameRegPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\'
		$RebootValue = "\??\C:\AUTOMATION_MACHINE_REBOOT_PENDING_$(Get-Random)"
		
		if (Test-Path $FileRenameRegPath) {
			if (($PFROValue = Get-ItemProperty -LiteralPath $FileRenameRegPath -Name $PropertyName -ErrorAction Ignore) -and $PFROValue.($PropertyName)) {
				$NewValue = $PFROValue.($PropertyName) + $RebootValue
				Set-ItemProperty -Path $FileRenameRegPath -Name $PropertyName -Value $NewValue -Type MultiString
			}
			else {
				Set-ItemProperty -Path $FileRenameRegPath -Name $PropertyName -Value $RebootValue -Type MultiString
			}
		}
		else {
			New-Item -Path $FileRenameRegPath -Force
			Set-ItemProperty -Path $FileRenameRegPath -Name $PropertyName -Value $RebootValue -Type MultiString -Force
		}
	
	}
	catch {
		Write-AMWarning 'Could not set the for AM Rebooting to to a file rename key' -EventLog
	}


	Write-AMStatus "Restarting"
	Write-AMInfo "Restarting computer in $ShutdownTimer seconds"
	# Set the reboot using shutdown.exe with the value specified in shutdown timer (Restart-Computer cmdlet doesn't let us specify a shutdowntimer and does not exist powershell properly)
	Invoke-Expression ". $env:windir\system32\shutdown.exe /r /t $($ShutdownTimer)"			

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Sets a regvalue or restore a regvalue from the backupstore

	.Description
 	Sets a regvalue with the option to save the original value in a backup store and reset it from the backup store

	.Parameter Path
	The path for the reg value: e.g: HKLM:\Software\Automation Machine

	.Parameter Name
	The name of the reg value: e.g. MaxTokenSize

	.Parameter Value
 	The value for the reg value: e.g. 655535

	.Parameter Type
	The valuetype for the reg value. e.g. String or DWORD

	.Parameter Backup
	Switch parameter indicating that the original value should be stored in the backup store. If there's no original value, the value is stored in the backup store with the value Delete, so the reset parameter knows that the value should be removed when performing a reset

	.Parameter Reset
	Switch parameter indicating that the backup value should be restored or the set value should be deleted.

	.Example
 	Set-AMRegValue -Path "HKLM:\Software\Automation Machine" -Name TestPath -Value 1 -Type DWORD -Backup

	.Example
	Set-AMRegValue -Path "HKLM:\Software\Automation Machine" -Name TestPath -Reset

	.Example
	Set-AMRegValue -Path "HKLM:\Software\Automation Machine" -Name TestPath -Value 1 -Type DWORD

#>
function Set-AMRegValue {
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $true)]
        [string]
        $Path,

        [parameter(mandatory = $true)]
        [string]
        $Name,

        [parameter(mandatory = $false)]
        [string]
        $Value,

        [parameter(mandatory = $false)]
        [string]
        $Type,

        [parameter(mandatory = $false)]
        [switch]
        $Backup,

        [parameter(mandatory = $false)]
        [switch]
        $Reset

    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    $Path = Convert-AMRegistryPath -Path $Path
    $RegValueReg = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    $RegValueBackupBase64 = Convert-AMString -ToBase64 -String $(Join-Path $Path $Name)
    $BackupStorePath = 'Registry::HKEY_LOCAL_MACHINE\Software\Automation Machine\BackupStore'
    $RegValueBackup = Get-ItemProperty -Path $BackupStorePath -Name $RegValueBackupBase64 -ErrorAction SilentlyContinue

    If (-not $Backup -and -not $Reset) {
        If ($RegValueReg -is [Object]) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
        }
        [void] (New-ItemProperty -PropertyType $Type -Path $Path -Name $Name -Value $Value -ErrorAction Stop)
    }

    If ($Backup) {
        If (!$(Test-Path $BackupStorePath)) {
            [void] (New-Item $BackupStorePath -Force)
        }

        If ($RegValueReg -is [Object]) {
            If ($RegValueBackup -isnot [Object]) {
                New-ItemProperty -Path $BackupStorePath -Name $RegValueBackupBase64 -Value $RegValueReg.($Name)
            }
            Remove-ItemProperty -Path $Path -Name $Name -Force
        }
        If ($RegValueReg -isnot [Object]) {
            If ($RegValueBackup -isnot [Object]) {
                [void] (New-ItemProperty -Path $BackupStorePath -Name $RegValueBackupBase64 -Value "Delete" -PropertyType String)
            }
        }
        [void] (New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force)
    }

    If ($Reset) {
        $ResetActionReg = Get-ItemProperty $BackupStorePath -Name $RegValueBackupBase64 -ErrorAction SilentlyContinue
        If ($ResetActionReg -is [Object]) {
            If ($ResetActionReg.($RegValueBackupBase64) -eq "Delete") {
                Remove-ItemProperty -Path $BackupStorePath -Name $RegValueBackupBase64 -Force
                Remove-ItemProperty -Path $Path -Name $Name -Force
            }
            Else {
                Remove-ItemProperty $Path -Name $Name -Force -ErrorAction SilentlyContinue
                [void] (New-ItemProperty -Path $Path -Name $Name -Value $ResetActionReg.($RegValueBackupBase64))
                Remove-ItemProperty -Path $BackupStorePath -Name $RegValueBackupBase64 -Force
            }
        }
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Configure startmode of a windows service

	.Description
 	Configure startmode of a windows service.
  	
	.Parameter Name
 	Name or displayname of the service to configure
	
    .Parameter StartupType
    What should the startup behavior of the service be. Options are Automation, Manual or Disabled
	
	.Example
	Set-AMService -name spooler -startuptype disabled
		
#>
function Set-AMService 
{
    [CmdletBinding()]
	param
	(
		[parameter(mandatory=$true,ValueFromPipeline=$false,Position=0)]
		[string]
		$Name,

        [parameter(mandatory=$true,ValueFromPipeline=$false)]
		[ValidateSet("Automatic","Manual","Disabled")] 
		[string]
		$StartupType
				
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')



        
    if ($(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) -ne $true) {
        throw "Not an administrator, cannot continue"
    }

            								
		Write-AMInfo -Information "Set startuptype of service `"$Name`" to `"$StartupType`""
		Set-Service $Name -StartupType $StartupType -ErrorAction Stop
   
		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
	

<#
	.Synopsis
	Tunes the SMBv1 Protocol for Terminal Server usage.

	.Description
 	By default, the SMBv1 protocol on Terminal Servers and Windows File Servers are not properly configured for usage in a Terminal Server environment. This function will can be used to update this configuration.
  
	.Parameter MaxWorkItems
	Specifies the maximum number of receive buffers (work items) that the Server service can allocate at one time. (Default: 8192)
	
	.Parameter MaxMpxCt
	Specifies a suggested limit on the number of outstanding client requests that can be maintained for each client on this server. (Default: 2048)
 	
	.Parameter MaxRawWorkItems
	Determines the maximum number of raw work items (undivided receive buffers) that the Server service can allocate each time it runs. (Default: 512)
	
	.Parameter MaxFreeConnections
	Specifies the maximum number of free connection blocks maintained for each endpoint. (Default: 100)
	
	.Parameter MinFreeConnections
	Specifies the minimum number of free connection blocks maintained for each endpoint. (Default: 32)
	
	.Parameter MaxCmds
	Specifies the maximum number of network control blocks that the redirector can reserve. (Default: 2048)
	
	.Parameter RegistryLazyFlushInterval
	Control the registry flush interval. A registry flush may result in an unresponsive system on terminal servers. (Default: 60)
	
	.Parameter Reset
	Resets the SMBv1 Tuning parameters to their original values.
  
	.NOTES
	The SMB protocol also needs to be tuned on both Terminal Server as well as Windows based files servers. If either is not tuned, these settings will *NOT* have any effect.
 
 	.Example
 	Set-AMSMBv1Tuning
 		
	.LINK
	http://support.microsoft.com/kb/324446
	
	.LINK
	http://blogs.citrix.com/2010/10/21/smb-tuning-for-xenapp-and-file-servers-on-windows-server-2008
	
#>
function Set-AMSMBv1Tuning
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$false)]
		[int]
		$MaxWorkItems = 8192,
		
		[parameter(mandatory=$false)]
		[int]
		$MaxMpxCt = 2048,
		
		[parameter(mandatory=$false)]
		[int]
		$MaxRawWorkItems = 512,
		
		[parameter(mandatory=$false)]
		[int]
		$MaxFreeConnections = 100,
		
		[parameter(mandatory=$false)]
		[int]
		$MinFreeConnections = 32,
		
		[parameter(mandatory=$false)]
		[int]
		$MaxCmds = 2048,
		
		[parameter(mandatory=$false)]
		[int]
		$RegistryLazyFlushInterval = 60,
		
		[parameter(mandatory=$false)]
		[switch]
		$Reset
				
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		

		If (-not $Reset)
		{
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxWorkItems -Type DWORD -Value $MaxWorkItems -Backup 			
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxMpxCt -Type DWORD -Value $MaxMpxCt -Backup 			
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxRawWorkItems -Type DWORD -Value $MaxRawWorkItems -Backup			
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxFreeConnections -Type DWORD -Value $MaxFreeConnections -Backup
			Set-AMRegValue  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MinFreeConnections -Type DWORD -Value $MinFreeConnections -Backup
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanworkstation\Parameters" -Name MaxCmds -Type DWORD -Value $MaxCmds -Backup
			Set-AMRegValue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name RegistryLazyFlushInterval -Type DWORD -Value $RegistryLazyFlushInterval -Backup
		}
		If ($Reset)
		{
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxWorkItems -Reset			
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxMpxCt -Reset
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxRawWorkItems -Reset
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MaxFreeConnections -Reset
			Set-AMRegValue  -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" -Name MinFreeConnections -Reset
			Set-AMRegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanworkstation\Parameters" -Name MaxCmds -Reset
			Set-AMRegValue -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name RegistryLazyFlushInterval -Reset
		}

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Launches an external process.

	.Description
 	Launches an external process and optionally wait for it or it's children to exit.

	.Parameter Path
 	Path to the external process to launch

	.Parameter Arguments
 	Arguments to pass to the command.

	.Parameter ExpectedReturnCodes
 	String of codes that are expected to return from the external process. If the return code does not return one of the expected return codes, the script will throw the output of the external process as an exception. Works only if the NoWait has NOT been used.
    
    .Parameter WaitForChildProcesses
    If specified this command will wait for the child processes for a specified time. If set to false, child processes will not be monitored. Default: false

    .Parameter ChildProcessesTimeout
    Time in seconds, after child processes will be terminated if WaitForChildProcesses is set to true. Default: 120 seconds
    
    .Parameter NoWait
    If specified this command will not wait for the process and it's child processes to exit.

	.Example
 	Start-AMProcess -Path "%windir%\notepad.exe" -Arguments "%windir%\debug\logfile.txt" -NoWait

	.Example
	"notepad.exe" | Start-AMProcess -Arguments "%windir%\debug\logfile.txt" -NoWait

	.Example
	Start-AMProcess -Path "cmd.exe" -Arguments "/c somefile.cmd" -ExpectedReturnCodes "0 3010"

#>
function Start-AMProcess {
    [CmdletBinding(DefaultParameterSetName = "Wait")]
    param
    (
        [parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [string]
        $Path,

        [parameter(mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [string]
        $Arguments,

        [parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Wait")]
        [boolean]
        $WaitForChildProcesses = $false,

        [parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Wait")]
        [string]
        $ChildProcessesTimeout = '120',

        [parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Wait")]
        [string]
        $ExpectedReturncodes = '0 3010',

        [parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "NoWait")]
        [switch]
        $NoWait
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    [System.Diagnostics.Process] $Process = New-Object System.Diagnostics.Process
    [System.Diagnostics.ProcessStartInfo] $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    [string] $ProcessOutput = ""
    [string] $ProcessError = ""

    $StartInfo.FileName = $Path
    $StartInfo.Arguments = $Arguments
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    $StartInfo.RedirectStandardInput = $false

    Write-Verbose "Attempting to start command: $Path $Arguments"
    $Process.StartInfo = $StartInfo
    [void] $Process.Start()

    $ProcessID = $Process.Id
    if ([string]::IsNullOrEmpty($ProcessID)) {
        throw "Process launch failed for unknown reasons"
    }
    else {
        Write-AMInfo "Started process with id $ProcessID ($Path)"
        Write-AMInfo "Command: $Path $Arguments"
    }

    if (-not ($NoWait)) {
        # Redirecting output only makes sense if we are waiting for the process to end
        # We are assuming that we also need to wait for child process to end if wait was specified

        # Readoutput before wait command to make sure we don't miss anything important
        $Process.StandardOutput.ReadToEnd() | ForEach-Object { $ProcessOutput += $_ }
        $Process.StandardError.ReadToEnd() | ForEach-Object { $ProcessError += $_ }

        [void] $Process.WaitForExit()
        Write-AMInfo "Process with id $ProcessID ($Path) exited with ExitCode $($Process.ExitCode)"

        $Process.standardoutput.ReadToEnd() | ForEach-Object { $ProcessOutput += $_ }
        $Process.StandardError.ReadToEnd() | ForEach-Object { $ProcessError += $_ }

        [Boolean] $AnErrorOccured = $false
        #if ($Process.ExitCode -ne $ExpectedReturncode)
        If (!$($ExpectedReturncodes.Split().Contains($Process.ExitCode.ToString()))) {
            $AnErrorOccured = $true
        }

        if (-not ([string]::IsNullOrEmpty($ProcessError))) {
            $AnErrorOccured = $true
        }

        if ($AnErrorOccured) {
            # Check if reboot was requested
            If ($Process.Exitcode -eq 3010) {
                
    $AMDataManager.RebootNeeded = $true

            }
            if (-not ([string]::IsNullOrEmpty($ProcessError))) {
                throw $ProcessError
            }
            elseif (-not ([string]::IsNullOrEmpty($ProcessOutput))) {
                throw $ProcessOutput
            }
            else {
                throw "Process exited with exit code: $($Process.ExitCode.ToString())"
            }
        }
        else {
            If ($Process.Exitcode -eq 3010) {
                $global:am_rebooting = $true
            }
            Write-AMInfo $ProcessOutput
        }

        # Main process is handled, wait for children. This part should be made nicer.
        Write-AMInfo "Looking for child processes and waiting up to 2 minutes for them to stop"
        if ($childProcesses = Get-WmiObject win32_process -Filter "ParentProcessId = $processID") {
            $childProcesses | ForEach-Object {
                Write-AMInfo "Child process $($_.Name) with ID $($_.ProcessID) has been found"
            }
        }
        else {
            Write-AMInfo "No child processes found"
        }

        if ($WaitForChildProcesses) {
            $timeout = New-TimeSpan -Seconds $ChildProcessesTimeout
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

            while ($childProcesses = Get-WmiObject win32_process -Filter "ParentProcessId = $processID") {
                if ($stopwatch.Elapsed -lt $timeout) {
                    Start-Sleep -Milliseconds 10000
                    Write-AMInfo "Waiting for $([math]::Round($stopwatch.Elapsed.TotalSeconds, 0)) seconds"
                }
                else {
                    $childProcesses | ForEach-Object {
                        try {
                            [void] $_.terminate()
                            if ($Error.Count -gt 0) {
                                Write-AMWarning "Unable to stop child process $($_.Name) with ID $($_.ProcessID)"
                                throw $Error[0].Exception
                            }
                            Write-AMInfo "Child process $($_.Name) with ID $($_.ProcessID) is stopped"
                        }
                        catch {
                            Write-AMWarning "$($_.Exception.Message)"
                        }
                    }
                    break
                }
            }
        }
        
        Write-AMInfo "Process execution is finished"
    }
    else {
        Write-AMInfo "Started process with id $ProcessID ($Path) asynchronously. There will be no further logging about this process"
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Starts a windows service

	.Description
 	Starts a windows service by name or displayname
  	
	.Parameter Name
 	Name or displayname of the service to start
	
    .Parameter Service
	Service controller object.
	
	 .Parameter Wait
    If specified this command will wait for the service to enter the running state. Default is 60 seconds.
	
	.Parameter Seconds
	The amount of seconds to wait for the service to enter the running state, defaults to 60 seconds if this parameter is not specified.
    		
	.Example
	Start-AMService spooler -Wait -Seconds 120

	.Example
	Get-Service -Name "fontcache" | Start-AMService -Wait
#>
function Start-AMService {
	[CmdletBinding()]
	param
	(
		[parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0, ParameterSetName = "Name")]
		[string]
		$Name,

		[parameter(mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "Service")]
		[System.ServiceProcess.ServiceController]
		$Service,

		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Name")]
		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Service")]
		[switch]
		$Wait,

		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Name")]
		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Service")]
		[int]
		$Seconds = 60
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


	
    if ($(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) -ne $true) {
        throw "Not an administrator, cannot continue"
    }


	if ($PSCmdlet.ParameterSetName -eq "Service") {
		$Name = $Service.Name
	}
	elseif ($PSCmdlet.ParameterSetName -eq "Name") {
		$Service = Get-Service $Name -ErrorAction Stop
	}
					
	Write-AMInfo -Information "Starting service `"$Name`""

	if ($Service.Status -ne "Running") {
		Start-Service $Service -ErrorAction Stop
				
		if ($Wait) {
			$WaitTime = $((New-TimeSpan -Seconds $Seconds) -f "hh:mm:ss").ToString()
			Write-AMInfo -Information "Waiting for service `"$name`" to start"
			$Service.WaitForStatus("Running", $WaitTime)
		}
			
	}
	else {
		Write-AMInfo -Information "Service `"$Name`" already running"
	}

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
.SYNOPSIS
Stops a running process.

.DESCRIPTION
The Stop-AMProcess cmdlet stops a running process. You can specify a process by name. Stop-AMProcess works only on processes running on the local computer.

.PARAMETER Name
Specifies the process name.

.PARAMETER Retry
Specifies the amount of retries to stop the process. The default value is 60.

.EXAMPLE
Stop-AMProcess -Name "notepad.exe"
#>
function Stop-AMProcess {
    [CmdletBinding()]
    param (
        [parameter(mandatory=$true,ValueFromPipeline=$false,Position=0)]
        [string] $Name,

		[parameter(mandatory=$false,ValueFromPipeline=$false)]
		[int]
        $Retry = 10
    )

    $IsProcessRunning = $false
    $CurrentRetryCount = 0
    $maxRetryCount = $Retry
    do {
        $Process = Get-Process -Name $Name -ErrorAction Ignore
        $IsProcessRunning = $null -ne $Process
        if ($IsProcessRunning) {
            $CurrentRetryCount++
            Write-Verbose "Stopping $Name. Attempt $CurrentRetryCount"
            if ($CurrentRetryCount -ge $maxRetryCount) {
                Stop-Process -Id $Process.Id -Force
                try {
                    Wait-Process -Id $Process.Id -Timeout 30 -ErrorAction Stop
                }
                catch {
                    Write-Verbose $_.Message
                }
                break
            }
            else {
                Start-Sleep -Seconds 1
            }
        }
    }
    while ($IsProcessRunning)
}

<#
	.Synopsis
	Stops a windows service

	.Description
 	Stops a windows service by name or displayname

	.Parameter Name
 	Name or displayname of the service to stop

	.Parameter Service
	Service controller object.

    .Parameter Wait
    If specified this command will wait for the service to enter the stopped state.

	.Parameter Seconds
	The amount of seconds to wait for the service to enter the stopped state, defaults to 60 seconds if this parameter is not specified.

	.Example
	Stop-AMService spooler -Wait -Seconds 120

	.Example
	Get-Service -Name "fontcache" | Stop-AMService -Wait
#>
function Stop-AMService {
	[CmdletBinding()]
	param
	(
		[parameter(mandatory = $true, ValueFromPipeline = $false, Position = 0, ParameterSetName = "Name")]
		[string]
		$Name,

		[parameter(mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = "Service")]
		[System.ServiceProcess.ServiceController]
		$Service,

		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Name")]
		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Service")]
		[switch]
		$Wait,

		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Name")]
		[parameter(mandatory = $false, ValueFromPipeline = $false, ParameterSetName = "Service")]
		[int]
		$Seconds = 60
	)

	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


	if ($PSCmdlet.ParameterSetName -eq "Service") {
		$Name = $Service.Name
	}
	elseif ($PSCmdlet.ParameterSetName -eq "Name") {
		$Service = Get-Service $Name -ErrorAction SilentlyContinue
	}

	Write-AMInfo -Information "Stopping service `"$Name`""

	if ($null -ne $Service -and $Service.Status -ne "Stopped") {
		Stop-Service $Service -ErrorAction Stop -Force

		if ($Wait) {
			$WaitTime = $((New-TimeSpan -Seconds $Seconds) -f "hh:mm:ss").ToString()
			Write-AMInfo -Information "Waiting for service `"$name`" to stop"
			$Service.WaitForStatus("Stopped", $WaitTime)
		}

	}
	elseif ($null -eq $Service) {
		Write-AMInfo -Information "Service `"$Name`" does not exist"
	}
	else {
		Write-AMInfo -Information "Service `"$Name`" already stopped"
	}

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
	.Synopsis
	Tests if MsiExec.exe command was successfull.

	.Description
	Tests if MsiExec.exe command was successfull and throws exception if it wans't.
	
	.Parameter ExitCode
	Path to the installer file
		
	.Example
 	$Process = Start-process "MSIEXEC.exe" -ArgumentList $argumentlist -Wait -PassThru
	Test-AMMsiExecResult -ExitCode $Process.ExitCode
#>
function Test-AMMsiExecResult
{
	[CmdletBinding()]
	param
	(		
		[parameter(mandatory=$true)]
		[int]
		$ExitCode
	)
	
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
		#List of misiexec return codes: http://support.microsoft.com/kb/229683
		switch ($ExitCode)
		{
			0 {
				Write-AMInfo "MSIEXEC: installed successfully."
			}
			1601 {
				Throw "MSIEXEC: Installation failed: The Windows Installer service could not be accessed. Contact your support personnel to verify that the Windows Installer service is properly registered."
			}
			1602 {
				Throw "MSIEXEC: User cancel installation."
			}
			1603 {
				Throw "MSIEXEC: Fatal error during installation."
			}
			1604 {
				throw "MSIEXEC: Installation suspended, incomplete."
			}
			1605 {
				throw "MSIEXEC: This action is only valid for products that are currently installed."
			}
			1606 {
				throw "MSIEXEC: Feature ID not registered."
			}
			1607 {
				throw "MSIEXEC: Component ID not registered."
			}
			1608 {
				throw "MSIEXEC: Unknown property."
			}
			1609 {
				throw "MSIEXEC: Handle is in an invalid state."
			}
			1610 {
				throw "MSIEXEC: The configuration data for this product is corrupt. Contact your support personnel."
			}
			1611 {
				throw "MSIEXEC: Component qualifier not present."
			}
			1612 {
				throw "MSIEXEC: The installation source for this product is not available. Verify that the source exists and that you can access it."
			}
			1613 {
				throw "MSIEXEC: This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
			}
			1614 {
				throw "MSIEXEC: Product is uninstalled."
			}
			1615 {
				throw "MSIEXEC: SQL query syntax invalid or unsupported."
			}
			1616 {
				throw "MSIEXEC: Record field does not exist."
			}
			1618 {
				throw "MSIEXEC: Another installation is already in progress. Complete that installation before proceeding with this install."
			}
			1619 {
				throw "MSIEXEC: This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package."
			}
			1620 {
				throw "MSIEXEC: This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package."
			}
			1621 {
				throw "MSIEXEC: There was an error starting the Windows Installer service user interface. Contact your support personnel."
			}
			1622 {
				throw "MSIEXEC: Error opening installation log file. Verify that the specified log file location exists and is writable."
			}
			1623 {
				throw "MSIEXEC: This language of this installation package is not supported by your system."
			}
			1625 {
				throw "MSIEXEC: This installation is forbidden by system policy. Contact your system administrator."
			}
			1626 {
				throw "MSIEXEC: Function could not be executed."
			}
			1627 {
				throw "MSIEXEC: Function failed during execution."
			}
			1628 {
				throw "MSIEXEC: Invalid or unknown table specified."
			}
			1629 {
				throw "MSIEXEC: Data supplied is of wrong type."
			}
			1630 {
				throw "MSIEXEC: Data of this type is not supported."
			}
			1631 {
				throw "MSIEXEC: The Windows Installer service failed to start. Contact your support personnel."
			}
			1632 {
				throw "MSIEXEC: The temp folder is either full or inaccessible. Verify that the temp folder exists and that you can write to it."
			}
			1633 {
				throw "MSIEXEC: This installation package is not supported on this platform. Contact your application vendor."
			}
			1634 {
				throw "MSIEXEC: Component not used on this machine."
			}
			1624 {
				throw "MSIEXEC: Error applying transforms. Verify that the specified transform paths are valid."
			}
			1635 {
				throw "MSIEXEC: This patch package could not be opened. Verify that the patch package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer patch package."
			}
			1636 {
				throw "MSIEXEC: This patch package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer patch package."
			}
			1637 {
				throw "MSIEXEC: This patch package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
			}
			1638 {
				throw "MSIEXEC: Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel."
			}
			1639 {
				throw "MSIEXEC: Invalid command line argument. Consult the Windows Installer SDK for detailed command line help."
			}
			1641 {
				Write-AMInfo "MSIEXEC: The installer has initiated a restart."
			}
			1642 {
				throw "MSIEXEC: The installer cannot install the upgrade patch because the program being upgraded may be missing or the upgrade patch updates a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade patch."
			}
			1643 {
				throw "MSIEXEC: The patch package is not permitted by system policy."
			}
			3010 {
				
    $AMDataManager.RebootNeeded = $true

			}
			default {
				throw "Unknown return code from msiexec.exe: $ExitCode"
			}
		}

	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Uninstalls an MSI installer file

	.Description
	Wrapper function for msiexec.exe to uninstall MSI files

	.Parameter Path
	Path to the installer file

	.Parameter LogFile
	Where to place the MSI log file. Defaults to user's temp folder (msiexec_00000000-0000-0000-0000-000000000000.log)

	.Example
 	Uninstall-AMMSI -Path c:\temp\7z920.msi
#>
function Uninstall-AMMSIfile {
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $true)]
        [System.IO.FileInfo]
        $Path,

        [parameter(mandatory = $False)]
        [System.IO.FileInfo]
        $LogFile = "$($env:temp)\msiexec_$([Guid]::NewGuid().ToString()).log",

        [parameter(mandatory = $false)]
        [string]
        $ExpectedReturnCodes = "0 3010"
    )

    
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')


    [System.Diagnostics.Process] $Process = New-Object System.Diagnostics.Process
    [System.Diagnostics.ProcessStartInfo] $StartInfo = New-Object System.Diagnostics.ProcessStartInfo

    $StartInfo.FileName = "msiexec.exe"
    $StartInfo.Arguments = "/x `"$Path`" /passive REBOOT=`"ReallySuppress`" /log `"$($LogFile.FullName)`""
    $StartInfo.UseShellExecute = $false
    $StartInfo.RedirectStandardOutput = $false
    $StartInfo.RedirectStandardError = $false
    $StartInfo.RedirectStandardInput = $false

    $Process.StartInfo = $StartInfo
    [void] $Process.Start()

    $ProcessID = $Process.Id
    if ([string]::IsNullOrEmpty($ProcessID)) {
        throw "Process launch of msiexec.exe failed for unknown reasons"
    }
    else {
        Write-AMInfo "Started process with id $ProcessID (msiexec.exe)"
        Write-AMInfo "Command: msiexec.exe $($StartInfo.Arguments)"
    }

    [void] $Process.WaitForExit()
    Write-AMInfo "Process with id $ProcessID (msiexec.exe) exited with ExitCode $($Process.ExitCode)"

    <# HHO: Disable piping msi logfile to console output
		if (Test-Path $LogFile)
		{
			Write-Host "******************************************* START MSI LOGFILE OUTPUT *******************************************`n"
			Get-Content -Path $LogFile | Out-Host
			Write-Host "`n******************************************** END MSI LOGFILE OUTPUT ********************************************"
		}
		#>

    #List of misiexec return codes: http://support.microsoft.com/kb/229683
    If (!$($ExpectedReturnCodes.Split().Contains($Process.ExitCode.ToString()))) {
        switch ($Process.ExitCode) {
            0 {
                Write-AMInfo "MSIEXEC: $($Path) uninstalled successfully."
            }
            1601 {
                Throw "MSIEXEC: Installation failed: The Windows Installer service could not be accessed. Contact your support personnel to verify that the Windows Installer service is properly registered."
            }
            1602 {
                Throw "MSIEXEC: User cancel installation."
            }
            1603 {
                Throw "MSIEXEC: Fatal error during installation."
            }
            1604 {
                throw "MSIEXEC: Installation suspended, incomplete."
            }
            1605 {
                throw "MSIEXEC: This action is only valid for products that are currently installed."
            }
            1606 {
                throw "MSIEXEC: Feature ID not registered."
            }
            1607 {
                throw "MSIEXEC: Component ID not registered."
            }
            1608 {
                throw "MSIEXEC: Unknown property."
            }
            1609 {
                throw "MSIEXEC: Handle is in an invalid state."
            }
            1610 {
                throw "MSIEXEC: The configuration data for this product is corrupt. Contact your support personnel."
            }
            1611 {
                throw "MSIEXEC: Component qualifier not present."
            }
            1612 {
                throw "MSIEXEC: The installation source for this product is not available. Verify that the source exists and that you can access it."
            }
            1613 {
                throw "MSIEXEC: This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
            }
            1614 {
                throw "MSIEXEC: Product is uninstalled."
            }
            1615 {
                throw "MSIEXEC: SQL query syntax invalid or unsupported."
            }
            1616 {
                throw "MSIEXEC: Record field does not exist."
            }
            1618 {
                throw "MSIEXEC: Another installation is already in progress. Complete that installation before proceeding with this install."
            }
            1619 {
                throw "MSIEXEC: This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package."
            }
            1620 {
                throw "MSIEXEC: This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package."
            }
            1621 {
                throw "MSIEXEC: There was an error starting the Windows Installer service user interface. Contact your support personnel."
            }
            1622 {
                throw "MSIEXEC: Error opening installation log file. Verify that the specified log file location exists and is writable."
            }
            1623 {
                throw "MSIEXEC: This language of this installation package is not supported by your system."
            }
            1625 {
                throw "MSIEXEC: This installation is forbidden by system policy. Contact your system administrator."
            }
            1626 {
                throw "MSIEXEC: Function could not be executed."
            }
            1627 {
                throw "MSIEXEC: Function failed during execution."
            }
            1628 {
                throw "MSIEXEC: Invalid or unknown table specified."
            }
            1629 {
                throw "MSIEXEC: Data supplied is of wrong type."
            }
            1630 {
                throw "MSIEXEC: Data of this type is not supported."
            }
            1631 {
                throw "MSIEXEC: The Windows Installer service failed to start. Contact your support personnel."
            }
            1632 {
                throw "MSIEXEC: The temp folder is either full or inaccessible. Verify that the temp folder exists and that you can write to it."
            }
            1633 {
                throw "MSIEXEC: This installation package is not supported on this platform. Contact your application vendor."
            }
            1634 {
                throw "MSIEXEC: Component not used on this machine."
            }
            1624 {
                throw "MSIEXEC: Error applying transforms. Verify that the specified transform paths are valid."
            }
            1635 {
                throw "MSIEXEC: This patch package could not be opened. Verify that the patch package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer patch package."
            }
            1636 {
                throw "MSIEXEC: This patch package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer patch package."
            }
            1637 {
                throw "MSIEXEC: This patch package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."
            }
            1638 {
                throw "MSIEXEC: Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel."
            }
            1639 {
                throw "MSIEXEC: Invalid command line argument. Consult the Windows Installer SDK for detailed command line help."
            }
            3010 {
                
    $AMDataManager.RebootNeeded = $true

            }
            default {
                throw "Unknown return code from msiexec.exe: $($Process.ExitCode)"
            }
        }
    }
    else {
        Write-AMInfo "MSIEXEC: uninstalled successfully with expected return code: $($Process.ExitCode)"
        if ($Process.Exitcode -eq 3010) {
            
    $AMDataManager.RebootNeeded = $true

        }
        if ($Process.ExitCode -eq 0) {
            Write-AMInfo "MSIEXEC: $($Path) uninstalled successfully."
        }
    }

    
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
	.Synopsis
	Unregisters an extension with an application.

	.Description
 	Unregisters an extension with an application.
  
	.Parameter Extension
 	The extension to register with the application

	.Parameter ProgID
	Optional. The ProgID to register with the application.
	
	.Parameter LocalMachine
	Optional. Switch parameter indicating the file type should be registered on LocalMachine level instead of user level. Needs local admin rights.
	
	.NOTES
	LocalMachine parameter needs local administrator rights to be able to register the filetype.
 
 	.Example
 	Unregister-AMFileType -Extension ".jpga" 
	
	.Example
	UNregister-AMFileType -Extension ".jpga" -LocalMachine
	
	.Example
	Unregister-AMFileType -ProgID "IrfanView_JPGA"
	
	.Example
	Unregister-AMFileType -ProgID "IrfanView_JPGA" -LocalMachine


#>
function Unregister-AMFileType
{
	[CmdletBinding()]
	param
	(
		[parameter(mandatory=$false)]
		[string]
		$Extension,
		
		[parameter(mandatory=$false)]
		[string]
		$ProgID,
		
		[parameter(mandatory=$false)]
		[switch]
		$LocalMachine
		
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

				

		If ($ProgID -and $Extension)
		{
			Write-Error "Both ProgID and Extension are provided, only one can be supplied"
		}
		
				
		if ($localMachine) {
			$regPrefix = "Registry::HKEY_LOCAL_MACHINE\Software\Classes\"
		}
		else {
			$regPrefix = "Registry::HKEY_CURRENT_USER\Software\Classes\"
		}
				
			If (-not [string]::IsNullOrEmpty($ProgID))
			{
				$ExtensionProgID = Get-ChildItem $regPrefix | ? {$_.GetValue("") -eq $ProgID}
				If ($ExtensionProgID)
				{
					If ((Test-Path $ExtensionProgID.PSPath) -and (Test-Path $(Join-Path $regPrefix $ProgID)))
					{
						Remove-Item $ExtensionProgID.PSPath -Recurse
						Remove-Item $(Join-Path $regPrefix $ProgID) -Recurse
					}
				}
			}
				
			If (-not [string]::IsNullOrEmpty($Extension))
			{
				If (Test-Path $(Join-Path $regPrefix $Extension))
				{
					$ProgIDExtension = $(Get-ItemProperty $(Join-Path $regPrefix $Extension)).("(default)")
					
					If ((Test-Path $(Join-Path $regPrefix $Extension)) -and (Test-Path $(Join-Path $regPrefix $ProgIDExtension)))
					{
						Remove-Item $(Join-Path $regPrefix $Extension) -Recurse
						Remove-Item $(Join-Path $regPrefix $ProgIDExtension) -Recurse
					}
					
				}
			}
		

		
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}

<#
.SYNOPSIS
Deletes a scheduled task from the folder.

.DESCRIPTION
The Unregister-AMScheduledTask cmdlet deletes a scheduled task from the folder on a local computer.

.PARAMETER Name
Scheduled task name.

.PARAMETER Path
Folder path.

.EXAMPLE
Unregister-AMScheduledTask -Path "\Automation Machine" -Name "My task"

.NOTES
General notes
#>
function Unregister-AMScheduledTask {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string] $Name,

        [parameter(Mandatory = $false)]
        [string] $Path = "/"
    )

    $TaskFolder = Get-AMScheduledTaskFolder -Path $Path
    try {
        $Task = $TaskFolder.GetTask($Name)
    }
    catch {
    }

    if (($null -ne $TaskFolder) -and ($null -ne $Task)) {
        try {
            $TaskFolder.DeleteTask($Name, 0)
        }
        catch {
            Write-AMWarning "Failed to delete `"$Name`" scheduled task: $($_.Exception.Message)"
        }
    }
}

<#
	.Synopsis
	Writes an event to the Automation Machine event log.
	
	.Description
 	The Write-AMEventLog cmdlet writes an event to the Automation Machine event log ("Application and Services Logs\AM").
	
	.Parameter Message
 	Specifies the event message. This parameter is required.
	
	.Parameter EntryType
	Specifies the entry type of the event.  Valid values are Error, Warning and Information. The default value is Information.
	
	.Parameter EventId
	Specifies the event identifier. Range 100-199 is reserved for error messages, 200-299 - for warning messages, 300 and higher - for information messages.
	
	.Example
	Write-AMEventLog -Message "Test event log entry"
#>
function Write-AMEventLog {
	[CmdletBinding()]
	param(
		[parameter(mandatory=$true)]
		[string] $Message,
		[System.Diagnostics.EventLogEntryType] $EntryType = [System.Diagnostics.EventLogEntryType]::Information,
		[int] $EventId = -1 # 100-199 - errors, 200-299 - warnings, 300 - information
	)
	
	
	Write-AMVerboseHeader -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

		
	try
	{
		if ($EventId -eq -1) {
			if ($EntryType -eq [System.Diagnostics.EventLogEntryType]::Error) {
				$EventId = 100
			}
			elseif ($EntryType -eq [System.Diagnostics.EventLogEntryType]::Warning) {
				$EventId = 200
			}
			else {
				$EventId = 300
			}
		}
	
		$EventLogName = "AM"
		$EventSource = "Automation Machine"
		
		if ([System.Diagnostics.EventLog]::Exists($EventLogName) -and [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
			Write-EventLog -LogName $EventLogName -Source $EventSource -EntryType $EntryType -EventId $EventId -Message $Message
		}
	}
	catch [Exception]
    {
		Write-Host $_ -ForegroundColor Red
    }
	
	
    Invoke-AMReboot -Info $MyInvocation -Verbose:$PSBoundParameters.ContainsKey('Verbose')

}
<#
.SYNOPSIS
Modifies an existing desktop.

.DESCRIPTION
The Edit-AMXADesktop cmdlet modifies an existing desktop rule.

.PARAMETER Uuid
Specifies the GUID of the existing desktop rule.

.PARAMETER Name
Specifies the administrative name of the desktop rule.

.PARAMETER Description
Specifies an optional description of the desktop rule.

.PARAMETER Group
Specifies the group whose users are granted an entitlement to a desktop session by the rule.

.PARAMETER ActiveBroker
Specifies active broker.

.EXAMPLE
An example
#>
function Edit-AMXADesktop {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [Guid]
        $Uuid,

        [parameter(mandatory = $true)]
        [string]
        $Name,

        [parameter(mandatory = $false)]
        [string]
        $Description,

        [parameter(mandatory = $false)]
        [string]
        $Group,

        [parameter(mandatory = $true)]
        [string]
        $ActiveBroker
    )

    $Job = Invoke-Command -Verbose:$true -Computername $ActiveBroker -AsJob -ArgumentList @($Uuid, $Name, $Description, $Group) -ScriptBlock {
        param (
            $Uuid,
            $Name,
            $Description,
            $Group
        )
        $VerbosePreference = $Using:VerbosePreference
        Add-PSSnapin Citrix*

        $desktop = Get-BrokerEntitlementPolicyRule -UUID $Uuid
        if ($null -eq $desktop) {
            throw "Desktop $Uuid not found"
        }

        $desktop | Rename-BrokerEntitlementPolicyRule -NewName $Name

        if ([string]::IsNullOrEmpty($Group)) {
            $desktop | Set-BrokerEntitlementPolicyRule -Description $Description -PublishedName $Name -IncludedUserFilterEnabled $false
        }
        else {
            $desktop | Set-BrokerEntitlementPolicyRule -Description $Description -PublishedName $Name -IncludedUserFilterEnabled $true -IncludedUsers $Group
        }
    }

    [void] (Wait-Job $Job)

    if ($Job.State -eq "Failed") {
        throw $job.ChildJobs[0].JobStateInfo.Reason.Message
    }
}

<#
.SYNOPSIS
Gets active broker.

.DESCRIPTION
Gets DDCs from registry and determines the active broker.

.EXAMPLE
$ActiveBroker = Get-AMXAActiveBroker
#>
function Get-AMXAActiveBroker {

    param(
    )

    $ActiveBroker = $null

    Write-Verbose "Getting DDCs from registry"
    # Determine active broker
    $ListOfDDCs = (Get-ItemProperty "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent") | Select-Object -ExpandProperty ListOfDDcs -ea Silent
    if ($ListOfDDCs -ne $null)
    {
        foreach ($DDC in $ListOfDDcs.Split() | Where-Object {-not ([string]::IsNullOrEmpty($_))})
        {
            Write-Verbose "Querying DDC: $($DDC)"
            try 
            {
                $BrokerService = Get-Service -Computername $DDC -Name CitrixBrokerService -ea silent
                If ($BrokerService -eq $null)
                {
                    Write-Verbose "Unable to find CitrixBrokerService on $($DDC)"
                    continue
                }
                else
                {
                    Write-Verbose "CitrixBrokerService status: $($BrokerService.Status)"
                }
                
                $ConfigService = Get-Service -Computername $DDC -Name CitrixConfigurationService -ea silent
                If ($ConfigService -eq $null)
                {
                    Write-Verbose "Unable to find CitrixConfigurationService on $($DDC)"
                    continue
                }
                else
                {
                    Write-Verbose "CitrixConfigurationService status: $($ConfigService.Status)"
                }
                If (($ConfigService.Status -eq "Running") -and ($BrokerService.Status -eq "Running"))
                {
                    Write-Verbose "Setting activebroker variable to $($DDC)"
                    $ActiveBroker = $DDC
                    continue
                }
            }
            catch
            {									
                continue
            }								
        }
    }
    
    return $ActiveBroker
}

<#
.SYNOPSIS
Gets the desktop group UUID from registry

.DESCRIPTION
Gets the desktop group UUID from registry

.EXAMPLE
$DesktopGroupUUID = Get-AMXADesktopGroupUuid
#>
function Get-AMXADesktopGroupUuid
{
	[CmdletBinding(DefaultParameterSetName="Default")]
	param
	(
    )

    $DesktopGroupUUID = $null
    $CitrixVDARegistryKey = "HKLM:\SOFTWARE\Citrix\VirtualDesktopAgent\State"
    if (Test-Path $CitrixVDARegistryKey)
    {
        $DesktopGroupUUID = (Get-ItemProperty $CitrixVDARegistryKey) | Select-Object -ExpandProperty DesktopGroupId -ea Silent
    }
    return $DesktopGroupUUID

}

<#
.SYNOPSIS
Creates a new Desktop.

.DESCRIPTION
The New-AMXADesktop cmdlet adds a new desktop rule to the site's entitlement policy.

.PARAMETER Name
Specifies the administrative name of the new desktop rule.

.PARAMETER Description
Specifies an optional description of the new desktop rule.

.PARAMETER Group
Specifies the group whose users are granted an entitlement to a desktop session by the new rule.

.PARAMETER DesktopGroupUuid
Specifies the GUID of the desktop group to which the new desktop rule applies.

.PARAMETER ActiveBroker
Specifies active broker.

.EXAMPLE
New-AMXADesktop -Name "Desktop 1" -Description "Desktop description" -DesktopGroupUuid "878b9f9b-dc5d-41a6-aab5-fd3a949983f6" -ActiveBroker "XD-INFRA"
#>
function New-AMXADesktop {
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)]
        [string]
        $Name,

        [parameter(mandatory = $false)]
        [string]
        $Description,

        [parameter(mandatory = $false)]
        [string]
        $Group,

        [parameter(mandatory = $true)]
        [Guid]
        $DesktopGroupUuid,

        [parameter(mandatory = $true)]
        [string]
        $ActiveBroker
    )

    $Job = Invoke-Command -Verbose:$true -Computername $ActiveBroker -AsJob -ArgumentList @($Name, $Description, $Group, $DesktopGroupUuid) -ScriptBlock {
        param (
            $Name,
            $Description,
            $Group,
            $DesktopGroupUuid
        )
        $VerbosePreference = $Using:VerbosePreference
        Add-PSSnapin Citrix*

        $Desktop = $null

        $DesktopGroup = Get-BrokerDesktopGroup -UUID $DesktopGroupUuid
        if ($null -eq $DesktopGroup) {
            throw "Desktop group $DesktopGroupUuid not found"
        }

        if ([string]::IsNullOrEmpty($Group)) {
            $Desktop = New-BrokerEntitlementPolicyRule -Name $Name -Description $Description -DesktopGroupUid $DesktopGroup.Uid -PublishedName $Name -IncludedUserFilterEnabled $false
        }
        else {
            $Desktop = New-BrokerEntitlementPolicyRule -Name $Name -Description $Description -DesktopGroupUid $DesktopGroup.Uid -PublishedName $Name -IncludedUserFilterEnabled $true -IncludedUsers $Group
        }

        return $Desktop
    }

    [void] (Wait-Job $Job)

    if ($Job.State -eq "Failed") {
        throw $job.ChildJobs[0].JobStateInfo.Reason.Message
    }

    $Result = Receive-Job $Job

    return $Result
}


If (-not (Test-Path variable:PSSenderInfo))
{
	If (-not ($host.Version.Major -ge 3))
	{
		throw "Powershell v3 or higher is required for AM, detected version: $($host.Version)"
	}
}
$OrginalTitle = $Host.UI.RawUI.WindowTitle


$Host.UI.RawUI.WindowTitle = "Login AM 2021 - Administrator API"
try {
$AMModulePath = Split-Path -Parent $MyInvocation.MyCommand.Definition
If ([string]::IsNullOrEmpty($AMCentralPath))
{
	if (-not (Test-Path "HKLM:\Software\Automation Machine"))
	{
		throw "Could not load datamanager, HKLM:\Software\Automation Machine does not exist"
	}
	$AMRegConfig = Get-Item "HKLM:\Software\Automation Machine"
	$AMCentralPath = [System.Environment]::ExpandEnvironmentVariables($AMRegConfig.GetValue("AMCentralPath"))
}
If ([string]::IsNullOrEmpty($AMLocalPath))
{
	if (-not (Test-Path "HKLM:\Software\Automation Machine"))
	{
		throw "Could not load datamanager, HKLM:\Software\Automation Machine does not exist"
	}
	$AMRegConfig = Get-Item "HKLM:\Software\Automation Machine"
	$AMLocalPath = [System.Environment]::ExpandEnvironmentVariables($AMRegConfig.GetValue("AMLocalPath"))
	If ([string]::IsNullOrEmpty($AMLocalPath))
	{
		$AMLocalPath = "$env:ALLUSERSPROFILE\Automation Machine"
	}
}
If ([string]::IsNullOrEmpty($EnvironmentID))
{
	$AMEnv = (get-itemproperty -path "HKLM:\Software\Automation Machine" -name "AMEnvironment" -ErrorAction SilentlyContinue)
	If ($AMEnv -eq $null)
	{
		$EnvironmentID = (Get-Item $AMModulePath).Parent.Parent.Parent.Name
	}
	else
	{
		$EnvironmentID = $AMEnv.AMEnvironment
	}
}
try
{
	New-Object Guid($EnvironmentID)
}
catch
{
throw "Unable to determine environment ID, if you are loading the module from a folder outside of the AMCentralPath\(guid)\bin\modules folder, either provide an environmentID through the -Argumentlist parameter for import-module, or set the AMEnvironmentID property in HKLM\Software\Automation Machine to the correct environmentID.`nExpected a GUID value, got $($EnvironmentID)"
}
$AMModulePath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$AMModulesTemp = $(Join-Path $env:TEMP "AMModules")
if (!(Test-Path $AMModulesTemp)) {New-Item -ItemType Directory -Path $AMModulesTemp}
ForEach ($ModuleTempFolder in get-childitem $AMModulesTemp -Directory | ? {$_.EnumerateFiles("remove")})
{
	$IsModuleRemoved = $false
	$TryCount = 0
	while (($IsModuleRemoved -eq $false) -and ($TryCount -lt 5)) {
		try
		{
			$TryCount++
			Remove-Item $ModuleTempFolder.FullName -Recurse -Force -ErrorAction Stop
			$IsModuleRemoved = $true
		}
		catch
		{
			Start-Sleep -Seconds 1
		}
	}
}
$AMModuleTempPath = $(Join-Path $AMModulesTemp $([Guid]::NewGuid().ToString()))
Copy-Item -Recurse -Path $AMModulePath -Destination $AMModuleTempPath -Force -ErrorAction Stop
ForEach ($Assembly in Get-ChildItem "$AMModulePath\*" -Filter "*.dll")
{
	$TempAssembly = $AMModuleTempPath + "\$($Assembly.Name)"
	Import-Module "$TempAssembly" -ErrorAction Stop
}
[void] [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression")
[void] [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem")
Set-Variable -Name AmWellKnown -Value $([AM.Data.WellKnown.WellKnown]) -Scope Global
Add-Type -AssemblyName "System.ServiceProcess"
try {
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
	[void] (New-Item -Path "$($AMModuleTempPath)\remove" -ItemType File -Force)
	Set-AMPermissions -PrincipalName "S-1-1-0" -Permissions "FullControl" -Path $AMModuleTempPath -Recurse -Type Allow
   $Host.UI.RawUI.WindowTitle = $OrginalTitle
}
}
catch {
	Write-AMWarning $_.Exception.Message
}
try {
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
	[void] (New-Item -Path "$($AMModuleTempPath)\remove" -ItemType File -Force)
	Set-AMPermissions -PrincipalName "S-1-1-0" -Permissions "FullControl" -Path $AMModuleTempPath -Recurse -Type Allow
   $Host.UI.RawUI.WindowTitle = $OrginalTitle
}
}
catch {
	Write-AMWarning $_.Exception.Message
}
$AMDataManager = New-Object AutomationMachine.Data.DataManager($AMCentralPath, (New-Object Guid($EnvironmentID)))
$AMCurrentSharePath = $AMDataManager.AMFileShare
$AMDatamanager.ReadEnvironment($EnvironmentID,$true)
$AMEnvironment = $AMDataManager.Environment
If ($AMEnvironment -eq $null)
{
	throw "Error loading Automation Machine environment data from $($AMCurrentSharePath)`nModulePath: $($AMModulePath)`nEnvironmentID: $($EnvironmentID)`nAMCentralPath: $($AMCentralPath)"
}
$am_module = "admin"
$AMEnvironment | Add-member -Name ServiceAccount -Type ScriptProperty -Value {Get-AMServiceAccount} -Force
$am_files = $AMCentralPath
$am_env_files = "$($AMCurrentSharePath)\$($AMEnvironment.id.tostring())"
$am_env_name = $AMEnvironment.Name
$am_env_prefix = $AMEnvironment.Prefix
$am_cache = $AMLocalPath
if (Test-AMElevation)
{
	$am_context = "System"
	$am_logpath = "$AMLocalPath\Logging"
}
else
{
	$am_context = "user"
	$am_logpath = "$env:Userprofile\Automation Machine\Logging"
}
$am_no_transcript = $NoTranscript
if (test-path $am_files) {$am_offline = $false} else {$am_offline = $true}
Export-ModuleMember -Variable "am_files"
Export-ModuleMember -Variable "am_env_files"
Export-ModuleMember -Variable "am_env_name"
Export-ModuleMember -Variable "am_env_prefix"
Export-ModuleMember -Variable "am_cache"
Export-ModuleMember -Variable "am_context"
Export-ModuleMember -Variable "am_offline"
Export-ModuleMember -Variable "am_logpath"
Export-ModuleMember -Variable "am_module"
Export-ModuleMember -Variable "am_no_transcript"
[System.Environment]::SetEnvironmentVariable("am_files",$am_files,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_env_files",$am_env_files,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_env_name",$am_env_name,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_env_prefix",$am_env_prefix,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_logpath",$am_logpath,[System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("am_offline",$am_offline,[System.EnvironmentVariableTarget]::Process)
Export-ModuleMember -Variable "AMEnvironment"
Export-ModuleMember -Variable "AMDataManager"
Export-ModuleMember -Variable "AMCentralPath"
Export-ModuleMember -Variable "AMLocalPath"
Export-ModuleMember -Variable "AMModuleTempPath"
New-Alias -Name Get-AMCollectionType -Value Get-AMEventMap
Export-ModuleMember -Function Add-AMGroupMember, Get-AMDirectoryEntry, Get-AMDirectoryEntryMember, Get-AMDomainDN, Get-AMLDAPPath, Get-AMSID, Move-AMDirectoryEntry, New-AMGroup, New-AMOU, Set-AMMaxTokenSize, Set-AMPermissions, Wait-AMObjectReplication, Copy-AMSDirectory, Get-AMActionItemTemplate, Get-AMCollection, Get-AMCollectionEventMap, Get-AMComputer, Get-AMConfigurationCategory, Get-AMDomain, Get-AMEventMap, Get-AMImportedFilePath, Get-AMImportedMediaPath, Get-AMLayer, Get-AMLogonMode, Get-AMMedia, Get-AMPackage, Get-AMPackageCategory, Get-AMPlugin, Get-AMRootOU, Get-AMServiceAccount, Get-AMSFileServiceProxy, Get-AMUserTargetedLayer, Get-AMVariable, Install-AMLogshippingTask, Install-AMStartupTask, Install-AMUserUsageTask, Invoke-AMReboot, Read-AMActionItems, Read-AMComputerStatus, Read-AMEnvironment, Read-AMGlobalVariables, Read-AMPrivateVariables, Resolve-AMFilterExpression, Resolve-AMMediaPath, Set-AMMaintenanceFlag, Start-AMSplashScreen, Stop-AMSplashScreen, Test-AMFolderChanges, Test-AMMaintenanceFlag, Update-AMCache, Update-AMCacheLink, Write-AMError, Write-AMInfo, Write-AMLogFile, Write-AMStatus, Write-AMVerboseHeader, Write-AMWarning, Add-AMLayer, Add-AMPackage, Copy-AMCollection, Copy-AMLayer, Copy-AMPackage, Edit-AMCollection, Edit-AMComputer, Edit-AMFilter, Edit-AMLayer, Edit-AMPackage, Edit-AMPackageCategory, Edit-AMPlugin, Edit-AMUserTargetedLayer, Edit-AMVariable, Edit-AMVariableFilter, Import-AMCollection, Import-AMLayer, Import-AMMedia, Import-AMPackage, New-AMActionItem, New-AMActionItemInstance, New-AMCollection, New-AMComputer, New-AMConfigurationCategory, New-AMFilter, New-AMLayer, New-AMPackage, New-AMPackageCategory, New-AMPlugin, New-AMUserTargetedLayer, New-AMVariable, New-AMVariableFilter, Remove-AMActionItem, Remove-AMCollection, Remove-AMComputer, Remove-AMConfigurationCategory, Remove-AMEnvironment, Remove-AMFilter, Remove-AMLayer, Remove-AMPackage, Remove-AMPackageCategory, Remove-AMPlugin, Remove-AMUserTargetedLayer, Remove-AMVariable, Remove-AMVariableFilter, Set-AMActionItem, Set-AMCollection, Set-AMConfigurationCategory, Set-AMLayer, Set-AMMedia, Set-AMServiceAccount, Set-AMVariable, Set-AMVariableFilter, Set-AMVariableOverride, Test-AMClientHostname, Test-AMCollection, Test-AMCollectionType, Test-AMComputerDomain, Test-AMDayOfWeek, Test-AMEnvironmentId, Test-AMEnvironmentName, Test-AMEnvironmentType, Test-AMEnvVar, Test-AMEvent, Test-AMFileExist, Test-AMHostname, Test-AMIPAddress, Test-AMMemberOf, Test-AMOddEven, Test-AMOSArch, Test-AMOSLang, Test-AMOSName, Test-AMOSVersion, Test-AMOU, Test-AMRegistry, Test-AMRegKeyExist, Test-AMRegValExist, Test-AMRegValue, Test-AMServiceStartMode, Test-AMServiceStatus, Test-AMSPVersion, Test-AMUILang, Test-AMUsername, Get-AMRDConnectionBrokerHighAvailability, Get-AMRDRemoteApp, Get-AMRDSessionHost, New-AMRemoteApp, Set-AMRDSessionHost, Set-AMRemoteApp, Add-AMAssembly, Compare-AMFiles, Compress-AMFolder, Convert-AMRegistryPath, Convert-AMString, Expand-AMEnvironmentVariables, Expand-AMZipfile, Get-AMFileEncoding, Get-AMFingerPrint, Get-AMMutex, Get-AMTranscriptPath, New-AMPSSession, New-AMRandomItemName, Set-AMCacheSecurity, Set-AMEnvironmentVariables, Split-AMFile, Test-AMElevation, Set-AMViewApplication, Add-AMRegistryString, Connect-AMDrive, Connect-AMPrinter, Disconnect-AMDrive, Disconnect-AMPrinter, Get-AMComputerDomain, Get-AMLoggedOnUsers, Get-AMOperatingSystemArchitecture, Get-AMPendingReboot, Get-AMScheduledTaskFolder, Get-AMSymbolicLinkTarget, Import-AMCertificate, Import-AMRegFile, Install-AMMSIFile, Invoke-AMChocolateyPackage, Invoke-AMCustomScript, Invoke-AMSQLCommand, New-AMShare, New-AMShortcut, New-AMSymbolicLink, New-AMWebShortcut, Register-AMFileType, Register-AMScheduledTask, Remove-AMService, Remove-AMSymbolicLink, Resolve-AMDoubleHopProblem, Restart-AMComputer, Set-AMRegValue, Set-AMService, Set-AMSMBv1Tuning, Start-AMProcess, Start-AMService, Stop-AMProcess, Stop-AMService, Test-AMMsiExecResult, Uninstall-AMMSIFile, Unregister-AMFileType, Unregister-AMScheduledTask, Write-AMEventLog, Edit-AMXADesktop, Get-AMXAActiveBroker, Get-AMXADesktopGroupUid, New-AMXADesktop
Export-ModuleMember -Alias "*-*"
Resolve-AMDoubleHopProblem
$ErrorActionPreference = "Stop"
}
catch {
	throw $_
}
