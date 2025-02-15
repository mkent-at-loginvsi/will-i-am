function global:Write-AMInitInfo {
	param ([Object] $Object)
	if (-not $VerboseMode) {
		write-host $Object -NoNewline
	}
	else {
		write-host $Object
	}
}

function global:Write-AMSuccess {
	if (-not $VerboseMode) {
		write-host "`t[DONE]" -ForegroundColor Green
	}
	else {
		write-host "[DONE]" -ForegroundColor Green
	}
}

function global:Write-AMFailure {
	if (-not $VerboseMode) {
		write-host "`t[FAILED]" -ForegroundColor Red
	}
	else {
		write-host "[FAILED]" -ForegroundColor Red
	}
}

function global:Initialize-AMTask {
	param(
		[Parameter(Mandatory=$true, Position=0)]
		[string] $Name,
		[Parameter(Mandatory=$true, Position=1)]
		[scriptblock] $Script
	)
	try {
		$TaskName = ""
		if ($AddTaskPrefix -eq $true) {
			$TaskName = "TASK: "
		}
		$TaskName += $Name
		Write-AMInitInfo $TaskName
		& $Script
		Write-AMSuccess
	}
	catch {
		Write-AMFailure
		Write-AMEventLogEntry -Message ($_.Exception.Message + "`nError occured during `"$Name`" step (Initialize-AM.ps1).") -EntryType Error
		throw $_
	}
}

function global:New-AMSymbolicLink
{
	[CmdletBinding()]
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
	try
	{
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
			write-host $output
		}
	}
	catch [Exception]
	{
		throw $_
	}
}

function global:Test-AMElevation
{
	Return $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
}

function global:Write-AMEventLogEntry {
	param(
		[parameter(mandatory=$true)]
		[string] $Message,
		[System.Diagnostics.EventLogEntryType] $EntryType = [System.Diagnostics.EventLogEntryType]::Information,
		[int] $EventId = -1 # 100-199 - errors, 200-299 - warnings, 300 - information
	)
	
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
}

function global:Stop-AMServiceAndWait {
    param(
		[parameter(mandatory=$true)]
		[string] $Name
    )

    $Service = Get-Service -Name $Name -ErrorAction Ignore
    if ($Service -ne $null) {
        Write-Verbose "Stopping $Name"
        Stop-Service -Name $Name -Force
        $Service.WaitForStatus('Stopped','00:00:30') # 30 seconds timeout
    }
}

function global:Get-ScheduleService {
	$SchTaskUserName = $AMEnvironment.ServiceAccount.UserName

	if($SchTaskUserName.StartsWith(".\")) {	$SchTaskUserName = $SchTaskUserName.Replace(".\",$env:COMPUTERNAME + "\")}
	$SchTaskPassword = $AMEnvironment.ServiceAccount.Password
	
	if ([string]::IsNullOrEmpty($SchTaskUserName)) { throw "Service account is not set for the environment" }
	$ScheduleService = New-Object -ComObject "Schedule.Service"
	$ScheduleService.Connect()
	
	return $ScheduleService
}

function global:Get-CleanAMScheduledTaskFolder {
	param(
		[parameter(mandatory=$true)]
		[string] $SchTaskName,

		[parameter(mandatory=$true)]
		[object] $ScheduleService
	)

	# Get username and password from environment and use it for the scheduled task
	
	$TaskFolder = $ScheduleService.GetFolder("\") # root folder
	Try {
		$TaskFolder = $TaskFolder.GetFolder("Automation Machine")
	}
	Catch {
		$TaskFolder = $TaskFolder.CreateFolder("Automation Machine")
	}
	Try {
		$TaskFolder.DeleteTask($SchTaskName)
	}
	Catch {

	}

	return $TaskFolder
}
