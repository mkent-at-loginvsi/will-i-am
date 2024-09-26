Param
( 
    [switch]$CheckIsDoneAfterPackageProcessing
)

$deploymentPluginId = [Guid]"2933a65d-1b32-4600-b288-325fa550f2f4"

function ShouldRunUpdates 
{
    Param([string] $updatesTimingVariableValue)

    switch($updatesTimingVariableValue) 
    {
        "Before package processing" #should update before package processing
        {
            if ($CheckIsDoneAfterPackageProcessing -eq $false) 
            { 
                return $true;
            }
        }

        "After package processing" #should update after package processing
        {
            if ($CheckIsDoneAfterPackageProcessing -eq $true) 
            { 
                return $true;
            }
        }

        "Both" #should update in both cases
        {
            return $true;
        }

        default
        {
            return $false
        }

    }

}

function RunWindowsUpdatesCheckIfNecessary()
{
    $deploymentPluginEnabled = [boolean] ((Get-AMVariable -Id 00000000-0000-0000-0000-000000000001 -ParentId $deploymentPluginId -CollectionId $am_col.Id).Value)
    if ($deploymentPluginEnabled) 
    {
        $updatesTiming = ([AutomationMachine.Data.Types.List] (Get-AMVariable -Id e90e90ac-0e42-41b8-9f75-bd1e94d847b1 -ParentId $deploymentPluginId -CollectionId $am_col.Id).Value).Value
        if ((ShouldRunUpdates $updatesTiming) -eq $true)
        {
            & "$am_env_files\config\plugins\2933a65d-1b32-4600-b288-325fa550f2f4\Optional\wua.ps1"                   # Deployment plugin
        }
    }
}

RunWindowsUpdatesCheckIfNecessary
