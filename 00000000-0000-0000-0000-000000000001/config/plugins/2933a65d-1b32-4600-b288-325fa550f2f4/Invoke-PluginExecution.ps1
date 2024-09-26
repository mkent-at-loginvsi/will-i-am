param(
    [parameter(Mandatory = $true, ValueFromPipeline = $false)]
    [AutomationMachine.Data.Package] $Package,
    [parameter(Mandatory = $true, ValueFromPipeline = $false)]
    [AutomationMachine.Data.Plugin] $Plugin
)

$StatusPath = Join-Path $([AutomationMachine.Data.DataFilePath]::REGISTRY_KEY_ROOT).Replace("HKEY_LOCAL_MACHINE", "HKLM:") "Status"
$MaintenanceFlag = (Get-ItemProperty -Path $StatusPath -Name "Maintenance" -ErrorAction SilentlyContinue)
if (($null -eq $MaintenanceFlag) -or ($MaintenanceFlag.Maintenance -ne $true)) {
    Write-AMInfo "Deployment flag not set to true, not processing deployment plugin during this run"
    return (Test-AMDeploymentCompletion -Package $Package)
}
else {
    [Boolean] $IsDynamic = (Get-AMVariable -Id "00000000-0000-0000-0000-000000000009" -ParentId $Plugin.Id -CollectionId $am_col.Id -ComponentId $Package.Id).Value

    if ($IsDynamic) {
        Write-AMInfo "$($Package.Name) is marked as dynamic"
        try {
            Read-AMActionItems $Package
            $Package = Get-AMPackage -Id $Package.Id

            $DeploymentResult = Invoke-AMActionSet -Package $Package -Plugin $Plugin -Track -Dynamic
            If ($DeploymentResult -eq 0) {
                Set-Variable -name am_pkg_installed -value $true -Scope 3 # Needs to be scope 3, because of the way invoke-pluginfinalization is called
            }
            return $true
        }
        catch [Exception] {
            throw $_
        }
    }
    else {
        Write-AMInfo "$($Package.Name) is marked as chronologic"
        try {
            Read-AMActionItems $Package
            $Package = Get-AMPackage -Id $Package.Id

            # Invoke-AMActionSet returns -1 is package is already installed.
            $DeploymentResult = 0
            $DeploymentResult = Invoke-AMActionSet -Package $Package -Plugin $Plugin -Track
            if ($DeploymentResult -eq 0) {
                Set-Variable -name am_pkg_installed -value $true -Scope 3
            }
            return $true
        }
        catch [Exception] {
            throw $_
        }
    }
}