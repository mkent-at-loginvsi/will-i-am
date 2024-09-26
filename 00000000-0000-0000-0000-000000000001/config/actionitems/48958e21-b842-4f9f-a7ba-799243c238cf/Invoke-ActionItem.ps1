<#
	.Synopsis
	Invokes the Invoke-SCCMInstall action item.

	.Description
 	Imports a package or application from a target SCCM server and runs it. On applications MSI's are supported. On packages executables are supported.
	
	.Parameter Actionitem
	Specifies the actionitem which to invoke.
		 
 	.Example
#>
function Invoke-SCCMInstall
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
	$AppID = $($Variables | ? {$_.name -eq "SCCM Package ID"}).Value | Expand-AMEnvironmentVariables
	$ProgramName = $($Variables | ? {$_.name -eq "SCCM Program Name"}).Value | Expand-AMEnvironmentVariables
	$ExpectedReturnCodes = $($Variables | ? {$_.name -eq "Expected Return Codes"}).Value | Expand-AMEnvironmentVariables
	
	
	# General Variables
	If (-not (Test-Path variable:am_col))
	{
		Set-Variable -Name am_col -Scope Global -Value (Get-AMCollection -Current)
	}
	$SCCMCredentials = $(Get-AMVariable -Id $AmWellKnown::Plugins.SccmConnector.SccmServerCredentialsVariable.Id -ParentId $AmWellKnown::Plugins.SccmConnector.Id -CollectionId $am_col.Id).Value
	$Credentials = New-Object PSCredential($($SCCMCredentials.UserName | Expand-AMEnvironmentVariables),$(ConvertTo-SecureString -AsPlainText -String $SCCMCredentials.Password -Force))
	$SCCMServer = (Get-ChildItem env:am_sccm_url).Value | Expand-AMEnvironmentVariables
	
	# Retrieve basic SCCM stuff
	try
	{
		$SiteCode = (Get-WmiObject -Namespace root\sms -Class SMS_ProviderLocation -Credential $Credentials -ComputerName $SCCMServer).SiteCode
	}
	catch
	{
		$Reason = $_
		Throw "Retrieving sitecode from SCCM server has failed. Error message: `'$Reason`'"
	}
	
	# Retrieve Application or Package info
	try
	{
		$Application = Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_Application -Credential $Credentials -ComputerName $SCCMServer | where {$_.CI_ID -eq $ProgramName}
		if ($Application -eq $null)
		{
			# Can't find an application so lets search for a package
			Write-AMInfo "Couldn't find an application with the name `'$ProgramName`'"
			$SCCMPackage = Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_Package -Credential $Credentials -ComputerName $SCCMServer | where {$_.PackageID -eq $AppID}
			if ($SCCMPackage -eq $null)
			{
				# Package also not found
				Write-AMInfo "Couldn't find a package with the ID `'$AppID`'"
			}
		}
		if (($Application -eq $null) -and ($SCCMPackage -eq $null))
		{
			# Can't find an application or a package so throw an error
			Throw "Can't find an Application with name `'$ProgramName`' or a Package with ID `'$AppID`' on $SCCMServer"
		}
		if (($Application -ne $null) -or ($SCCMPackage -ne $null))
		{
			# Found either an application or package so you can disregard previous warnings
			Write-AMInfo "Found either an application or program, previous warnings can be ignored"
		}
	}
	catch
	{
		# Retrieving the package or application has failed entirely. Throw back the error
		$Reason = $_
		Throw "Retrieving Application/Package `'$AppID`' from SCCM server has failed. Error message: `'$Reason`'"
	}
	
	# $Application variable isn't empty so we got something back, start processing it here
	if ($Application -ne $null)
	{
		try
		{
			# Get the application and load into an XML
			$Application.Get()
			$XML = [xml] $Application.SDMPackageXML
			ForEach ($DeploymentType in $XML.AppMgmtDigest.DeploymentType)
			{
				# Remove duplicate entries, somehow WMI returns old instances of applications. The sorting of applications on datelastmodified property makes sure that latest version is processed last
				$Matches = $List | ? {$_.ProgramName -contains $DeploymentType.title.innertext}
				Foreach ($Match  in $Matches)
				{
					$List.Remove($Match)           
				}

				# Retrieve MSI location and MSI filename
				$MSIFileLocation = $DeploymentType.Installer.Contents.Content.Location
				if((($DeploymentType.Installer.InstallAction.args.arg | ? {$_.name -eq "InstallCommandLine"}).InnerText) -match '"(.+?).msi"')
				{
					$MSIFile = ($Matches[1] + ".msi")
				}
				else 
				{
					Throw "Can't find MSIFile, are you sure this is an application with an MSI?"
				}

				# Concatenate the file location and filename and run it
				$ApplicationMSI = Join-Path -Path $MSIFileLocation -ChildPath $MSIFile
				Install-AMMSIfile -Path $ApplicationMSI
			}
		}
		catch
		{
			$Reason = $_
			Throw "Executing Application `'$AppID`' from SCCM server has failed. Error message: `'$Reason`'"
		}
	}

	# $SCCMPackage isn't empty so we got something back, processing it here
	if ($SCCMPackage -ne $null)
	{
		try
		{
			# Retrieve info from SCCM server
			$Program = Get-WmiObject -Namespace "root\sms\site_$SiteCode" -Class SMS_Program -Credential $Credentials -ComputerName $SCCMServer | where {($_.PackageID -eq $AppID) -and $_.ProgramName -eq $ProgramName}
			if ($Program -eq $null)
			{
				Throw "Couldn't find a program with the ID `'$AppID`' and name `'$ProgramName`'"
			}
		}
		catch
		{
			$Reason = $_
			Throw "Retrieving program with ID `'$AppID`' and name `'$ProgramName`' from SCCM server has failed. Error message: `'$Reason`'"
		}

		try
		{
			# Retrieve executable and UNC path
			$SourcePath = $SCCMPackage.PkgSourcePath
			if (($Program.CommandLine) -match '"(.+?).exe"')
			{
				$ProgramExecutable = ($Matches[1] + ".exe")
				$Arguments = ($Program.CommandLine).TrimStart("`"$ProgramExecutable`" ")
			}
			elseif (((($Program.CommandLine).split(" "))[0]) -like "*.exe")
			{
				$ProgramExecutable = (($Program.CommandLine).split(" "))[0]
				$Arguments = ($Program.CommandLine).TrimStart("$ProgramExecutable ")
			}
			else 
			{
				Throw "Can't find an executable, are you sure this is a package with an executable?"
			}

			# Concatenate the stuff and execute it using the external process actionitem
			$ProgramCommand = Join-Path -Path $SourcePath -ChildPath $ProgramExecutable
			Start-AMProcess -Path $ProgramCommand -Arguments $Arguments -ExpectedReturnCodes $ExpectedReturnCodes
		}
		catch
		{
			$Reason = $_
			Throw "Executing package with ID `'$AppID`' from SCCM server has failed. Error message: `'$Reason`'"
		}
	}
}