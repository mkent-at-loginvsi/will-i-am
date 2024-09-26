function Rename-AMComputer {
    param
    (
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $true)]
        [string]
        $ComputerIp = "",
		
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $true)]
        [string]
        $ComputerName = "",
		
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $true)]
        [string]
        $LocalAdminName = "",
        
        [parameter(ParameterSetName = "Default", mandatory = $true, ValueFromPipeline = $true)]
        [string]
        $LocalAdminPassword = ""
    )

    
    if (-not ($LocalAdminName.StartsWith(".\"))) {
        $LocalAdminName = ".\" + $LocalAdminName
    }
	
    $secureLocalPassword = ConvertTo-SecureString $LocalAdminPassword -AsPlainText -Force
    $localcredential = New-Object System.Management.Automation.PSCredential ($LocalAdminName, $secureLocalPassword)

    $so = New-PSSessionOption -IdleTimeout 600000
    $Result = Invoke-Command -ComputerName $ComputerIp -Credential $localcredential -ArgumentList @($localCredential, $ComputerName) -ea Stop -SessionOption $so -ScriptBlock {
        param (
            $LocalCredential,
            $ComputerName
        )
        Rename-Computer -NewName $ComputerName -LocalCredential $LocalCredential -Force -ErrorAction Stop
        schtasks /create /tn "Fix WinRM" /tr "powershell -executionpolicy bypass -command 'Set-ExecutionPolicy bypass -force;Enable-PSRemoting -SkipNetworkProfileCheck -force;Enable-WSManCredSSP -Role Server -Force'" /RU "SYSTEM" /RL HIGHEST /SC ONSTART /F
        return $true
    }
    
    if ($result -eq $true) {
        Write-Verbose "Succesfully renamed computer to $ComputerName"
    }

}