function Join-ComputerToAD
{
    param
	(
        [parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$ComputerIp = "",

		[parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$ComputerName = "",

		[parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$LocalAdminName = "",

        [parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$LocalAdminPassword = "",

        [parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$RootOu = "",

        [parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$DomainFqdn = "",

        [parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$AdAccountName = "",

        [parameter(ParameterSetName="Default",mandatory=$true,ValueFromPipeline=$true)]
		[string]
		$AdAccountPassword = ""
	)


	If (-not ($LocalAdminName.StartsWith(".\")))
	{
		$LocalAdminName = ".\" + $LocalAdminName
	}

    $secureLocalPassword = ConvertTo-SecureString $LocalAdminPassword -AsPlainText -Force
    $localcredential = New-Object System.Management.Automation.PSCredential ($LocalAdminName, $secureLocalPassword)

    $secureAdPassword = ConvertTo-SecureString $AdAccountPassword -AsPlainText -Force
	$adCredential = New-Object System.Management.Automation.PSCredential ($AdAccountName, $secureAdPassword)

    $count = 0
    $maxcount = 30
    $result = $false
    $retry = $true
	do
    {
        $count = $count + 1
        try
        {
            $OUPath = ""
			$RootOu.Split("\") | %{$OUPath = ",ou=$($_)" + $OUPath}
			$OUPath = $OUPath.TrimStart(",")
			#$OUPath = "OU=$($RootOu)"

            $domainNames = $DomainFqdn.Split('.')
            foreach($domainSplit in $domainNames){
                $OUPath += ",dc=$($domainSplit)"
            }

			$so = New-PSSessionOption -IdleTimeout 600000
            $Result = Invoke-Command -ComputerName $ComputerIp -Credential $localcredential -Authentication Credssp -ArgumentList @($adCredential,$OUPath,$DomainFqdn,$ComputerName) -ea Stop -SessionOption $so -ScriptBlock {
                Param(
                    $DomainCredential,
                    $OUPath,
                    $DomainName,
					$ComputerName
                    )
                try
				{
					Add-Computer -DomainName $DomainName -Credential $DomainCredential -OUPath $OUPath -WarningAction SilentlyContinue -ErrorAction Stop
				}
				catch
				{
					if ((Get-WmiObject win32_computersystem).Domain -eq $DomainName)
					{
						Write-Verbose "Received exception: $_, but joined domain $DomainName succesfully"
					}
					else
					{
						if ($_.Exception.Message -like "*Computer*failed to join domain*from its current workgroup*with following error message: The system cannot find the file specified.*")
						{
                            $ErrorMessage = $_.Exception.Message -replace "The system cannot find the file specified.","The path `"$OUPath`" not found"
                            throw $ErrorMessage
						}

						throw $_
					}
				}

				Start-Sleep -seconds 30
				#Rename-Computer -NewName $ComputerName -DomainCredential $DomainCredential -Force -ErrorAction Stop
				[void] (& gpupdate /Target:Computer)
				#schtasks /create /tn "Fix WinRM" /tr "powershell -executionpolicy bypass -command 'Set-ExecutionPolicy bypass -force;Enable-PSRemoting -SkipNetworkProfileCheck -force;Enable-WSManCredSSP -Role Server -Force'" /RU "SYSTEM" /RL HIGHEST /SC ONSTART /F
				#Stop-Computer
                return $true
            }
			If ($result -eq $true)
			{
				Write-Verbose "Succesfully joined $ComputerName to $DomainFqdn"
				$retry = $false
			}
        }
        catch [System.Management.Automation.Remoting.PSRemotingTransportException]
        {
			# Only loop in case of remoting connection troubles, likely caused by vm not completely started up etc, other exceptions should be reported.
            #Write-Host $_ -foregroundcolor red
            Write-Verbose "Failed to join domain with reason :$($_), retrying $($maxcount - $count) more times..."
            $reason = $_
			$retry = $true
            Start-Sleep -Seconds 2
        }
		catch
		{
			throw $_
		}
        if ($count -ge $maxcount)
        {
            throw $reason
        }

    } while ($retry -eq $true)
}