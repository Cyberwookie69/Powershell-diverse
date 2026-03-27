<#
.SYNOPSIS
    Update existing vCenter roles based on the P1/P3 test plan.
.DESCRIPTION
    Use -P1, -P3, or both to update the corresponding role(s).
    The script:
      1. Connects to vCenter.
      2. Validates all privilege IDs (inline, right before the update).
      3. Strips existing privileges and sets the exact desired set.
      4. Shows before/after diff + denied check.
      5. Exports results to CSV.
.PARAMETER vCenter
    FQDN or IP of the vCenter Server.
.PARAMETER P1
    Switch: update the P1-Operator role.
.PARAMETER P3
    Switch: update the P3-Operator role.
.PARAMETER P1RoleName
    Name of the existing P1 role in vCenter. Default: "p1-operator".
.PARAMETER P3RoleName
    Name of the existing P3 role in vCenter. Default: "p3-operator".
.EXAMPLE
    .\Update-VCenterRolePrivileges.ps1 -vCenter vc01.lab.local -P1 -P1RoleName "my-p1-role" -WhatIf
.EXAMPLE
    .\Update-VCenterRolePrivileges.ps1 -vCenter vc01.lab.local -P1 -P3 -WhatIf
#>

#Requires -Modules VMware.VimAutomation.Core

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$vCenter,

    [switch]$P1,
    [switch]$P3,

    [string]$P1RoleName = "p1-operator",
    [string]$P3RoleName = "p3-operator"
)

# ===================================================================
# VALIDATION: at least one switch required
# ===================================================================
if (-not $P1 -and -not $P3) {
    Write-Error "Specify at least -P1 or -P3 (or both)." -ErrorAction Stop
}

# ===================================================================
# PRIVILEGE DEFINITIONS
# ===================================================================

# --- P1 Allowed ---
$p1Allowed = @(
    "System.Anonymous"
    "System.View"
    "System.Read"
    "VirtualMachine.Interact.PowerOn"
    "VirtualMachine.Interact.PowerOff"
    "VirtualMachine.Interact.Reset"
    "VirtualMachine.Interact.ConsoleInteract"
    "VirtualMachine.Interact.DeviceConnection"
    "VirtualMachine.Interact.AnswerQuestion"
    "VirtualMachine.Interact.GuestControl"
    "VirtualMachine.Interact.SetCDMedia"
    "Datastore.Browse"
)

# --- P1 Denied ---
# FIX: VirtualMachine.Interact.Backup removed (privilege ID does not exist in vSphere 7.x/8.x)
$p1Denied = @(
    "VirtualMachine.Interact.Suspend"
    "VirtualMachine.Interact.ToolsInstall"
    "VirtualMachine.Config.CPUCount"
    "VirtualMachine.Config.Memory"
    "VirtualMachine.Config.AddNewDisk"
    "VirtualMachine.Config.Rename"
    "VirtualMachine.Config.Settings"
    "VirtualMachine.State.CreateSnapshot"
    "VirtualMachine.State.RevertToSnapshot"
    "VirtualMachine.GuestOperations.Execute"
    "VirtualMachine.Provisioning.Clone"
    "VirtualMachine.Provisioning.DeployTemplate"
    "VirtualMachine.Inventory.Create"
    "VirtualMachine.Inventory.Delete"
    "Folder.Create"
    "Network.Assign"
    "Resource.AssignVMToPool"
    "ScheduledTask.Create"
    "Alarm.Create"
    "Datastore.AllocateSpace"
    "Datastore.FileManagement"
)

# --- P3 Allowed ---
# FIX: ContentLibrary.DownloadSession removed (does not exist as a privilege ID)
$p3Allowed = @(
    # Basics
    "System.Anonymous"
    "System.View"
    "System.Read"

    # VM Interact
    "VirtualMachine.Interact.PowerOn"
    "VirtualMachine.Interact.PowerOff"
    "VirtualMachine.Interact.Reset"
    "VirtualMachine.Interact.ConsoleInteract"
    "VirtualMachine.Interact.DeviceConnection"
    "VirtualMachine.Interact.AnswerQuestion"
    "VirtualMachine.Interact.GuestControl"
    "VirtualMachine.Interact.Suspend"
    "VirtualMachine.Interact.ToolsInstall"
    "VirtualMachine.Interact.SetCDMedia"
    "VirtualMachine.Interact.DefragmentAllDisks"

    # Datastore
    "Datastore.Browse"
    "Datastore.AllocateSpace"
    "Datastore.FileManagement"

    # VM Config
    "VirtualMachine.Config.AddNewDisk"
    "VirtualMachine.Config.DiskExtend"
    "VirtualMachine.Config.RemoveDisk"
    "VirtualMachine.Config.CPUCount"
    "VirtualMachine.Config.Memory"
    "VirtualMachine.Config.AddRemoveDevice"
    "VirtualMachine.Config.Rename"
    "VirtualMachine.Config.Annotation"
    "VirtualMachine.Config.AdvancedConfig"
    "VirtualMachine.Config.UpgradeVirtualHardware"
    "VirtualMachine.Config.ChangeTracking"
    "VirtualMachine.Config.Settings"

    # VM State / Snapshots
    "VirtualMachine.State.CreateSnapshot"
    "VirtualMachine.State.RevertToSnapshot"
    "VirtualMachine.State.RemoveSnapshot"
    "VirtualMachine.State.RenameSnapshot"

    # Guest Operations
    "VirtualMachine.GuestOperations.Query"
    "VirtualMachine.GuestOperations.Execute"
    "VirtualMachine.GuestOperations.Modify"

    # Provisioning
    "VirtualMachine.Provisioning.Clone"
    "VirtualMachine.Provisioning.DeployTemplate"
    "VirtualMachine.Provisioning.MarkAsTemplate"
    "VirtualMachine.Provisioning.MarkAsVM"
    "VirtualMachine.Provisioning.Customize"
    "VirtualMachine.Provisioning.GetVmFiles"

    # Inventory
    "VirtualMachine.Inventory.Create"
    "VirtualMachine.Inventory.Delete"
    "VirtualMachine.Inventory.Move"

    # Folder / Network / Resource
    "Folder.Create"
    "Folder.Delete"
    "Folder.Rename"
    "Network.Assign"
    "Resource.AssignVMToPool"
    "Resource.CreatePool"
    "Resource.EditPool"

    # ScheduledTask / Alarm / Global
    "ScheduledTask.Create"
    "ScheduledTask.Edit"
    "ScheduledTask.Run"
    "Alarm.Create"
    "Alarm.Edit"
    "Alarm.Acknowledge"
    "Global.CancelTask"

    # Other
    "StorageProfile.View"
)

# --- P3 Denied ---
$p3Denied = @(
    "Global.Licenses"
    "Datastore.Config"
    "Datastore.Move"
    "Datastore.Delete"
    "DVSwitch.Create"
    "DVSwitch.Modify"
    "DVSwitch.Delete"
    "DVSwitch.PortSetting"
    "DVSwitch.HostOp"
    "DVSwitch.Vspan"
    "DVPortgroup.Create"
    "DVPortgroup.Modify"
    "DVPortgroup.Delete"
    "DVPortgroup.ScopeOp"
    "DVPortgroup.PolicyOp"
    "VApp.Create"
    "VApp.Delete"
    "VApp.Import"
    "VApp.Export"
    "VApp.PowerOn"
    "VApp.PowerOff"
    "VApp.ApplicationConfig"
    "VApp.InstanceConfig"
    "VApp.ResourceConfig"
    "VApp.AssignVM"
    "VApp.AssignResourcePool"
    "VApp.AssignVApp"
    "VApp.Clone"
    "VApp.Move"
    "VApp.Rename"
    "VApp.Unregister"
    "VApp.ExtractOvfEnvironment"
    "ContentLibrary.CreateLocalLibrary"
    "ContentLibrary.UpdateLocalLibrary"
    "ContentLibrary.DeleteLocalLibrary"
    "ContentLibrary.AddLibraryItem"
    "ContentLibrary.UpdateLibraryItem"
    "ContentLibrary.DeleteLibraryItem"
    "Authorization.ModifyPermissions"
    "Host.Inventory.AddHostToCluster"
    "Host.Inventory.RemoveHostFromCluster"
    "Host.Inventory.MoveHost"
    "Host.Config.Maintenance"
    "Host.Config.Connection"
    "Host.Config.Settings"
    "Host.Config.Storage"
    "Host.Config.Network"
    "Host.Config.AdvancedConfig"
    "Global.Settings"
    "Cryptographer.ManageEncryptionPolicy"
    "Cryptographer.ManageKeys"
    "Cryptographer.ManageKeyServers"
    "Cryptographer.Encrypt"
    "Cryptographer.Decrypt"
    "Cryptographer.Access"
    "Extension.Register"
    "Extension.Update"
    "Extension.Unregister"
    "Authorization.ModifyRoles"
    "StorageProfile.Update"
    "Global.SetCustomField"
)

# ===================================================================
# FUNCTION: Privilege validation
# ===================================================================
function Test-PrivilegeIds {
    param(
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string[]]$Denied,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Server
    )

    $allPriv = Get-VIPrivilege -Server $Server -ErrorAction Stop |
               Select-Object -ExpandProperty Id

    $invalidAllowed = $Allowed | Where-Object { $_ -notin $allPriv }
    $invalidDenied  = $Denied | Where-Object { $_ -notin $allPriv }
    $overlap        = $Allowed | Where-Object { $_ -in $Denied }

    if ($invalidAllowed) {
        Write-Error "[$Label] Invalid Allowed privileges: $($invalidAllowed -join ', ')" -ErrorAction Stop
    }
    if ($invalidDenied) {
        Write-Warning "[$Label] Invalid Denied privileges (ignored during check): $($invalidDenied -join ', ')"
    }
    if ($overlap) {
        Write-Error "[$Label] Overlap between Allowed and Denied: $($overlap -join ', ')" -ErrorAction Stop
    }

    Write-Host "[$Label] Privilege validation passed. Allowed: $($Allowed.Count) | Denied: $($Denied.Count)" -ForegroundColor Green
}

# ===================================================================
# FUNCTION: Update role
# ===================================================================
function Update-VCenterRole {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$RoleName,
        [Parameter(Mandatory)][string[]]$DesiredPrivileges,
        [Parameter(Mandatory)][string[]]$DeniedPrivileges,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Server
    )

    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host " $Label - Role: $RoleName" -ForegroundColor Cyan
    Write-Host "$('=' * 70)`n" -ForegroundColor Cyan

    # --- Inline validation (prevents TOCTOU) ---
    Test-PrivilegeIds -Allowed $DesiredPrivileges -Denied $DeniedPrivileges -Label $Label -Server $Server

    $DesiredPrivileges = $DesiredPrivileges | Sort-Object -Unique

    # --- Retrieve role ---
    $role = Get-VIRole -Name $RoleName -Server $Server -ErrorAction SilentlyContinue
    if (-not $role) {
        throw "Role '$RoleName' does not exist on $Server."
    }

    # --- Before snapshot ---
    $before = (Get-VIPrivilege -Role $role |
               Select-Object -ExpandProperty Id) | Sort-Object

    # --- Retrieve privilege objects ---
    $privObjects = Get-VIPrivilege -Id $DesiredPrivileges -Server $Server -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess($RoleName, "Strip all privileges and set exactly $($DesiredPrivileges.Count) new privileges")) {

        # Strip all existing privileges, then set the exact desired set
        $currentPrivs = Get-VIPrivilege -Role $role
        if ($currentPrivs) {
            Set-VIRole -Role $role -RemovePrivilege $currentPrivs -Confirm:$false -ErrorAction Stop | Out-Null
        }

        # Add exactly the desired set
        Set-VIRole -Role $role -AddPrivilege $privObjects -Confirm:$false -ErrorAction Stop | Out-Null

        Write-Host "Role '$RoleName' successfully updated with exactly $($DesiredPrivileges.Count) privileges." -ForegroundColor Green

        # After snapshot (only on actual change)
        $after = (Get-VIPrivilege -Role (Get-VIRole -Name $RoleName -Server $Server) |
                  Select-Object -ExpandProperty Id) | Sort-Object
    }
    else {
        # In WhatIf mode, use the desired set as projection
        Write-Host "[WhatIf] No changes applied. Diff shows projection." -ForegroundColor Yellow
        $after = $DesiredPrivileges | Sort-Object
    }

    # --- Diff ---
    $added   = $after | Where-Object { $_ -notin $before }
    $removed = $before | Where-Object { $_ -notin $after }

    Write-Host "`n--- Before / After ---" -ForegroundColor Cyan
    Write-Host "BEFORE : $($before.Count) privileges"
    Write-Host "AFTER  : $($after.Count) privileges"

    if ($added) {
        Write-Host "`nAdded (+):" -ForegroundColor Green
        $added | ForEach-Object { Write-Host " + $_" -ForegroundColor Green }
    }
    if ($removed) {
        Write-Host "`nRemoved (-):" -ForegroundColor Red
        $removed | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
    }
    if (-not $added -and -not $removed) {
        Write-Host "`nNo changes." -ForegroundColor Yellow
    }

    # --- Denied check ---
    $leaks = $after | Where-Object { $_ -in $DeniedPrivileges }
    Write-Host "`n--- NEGATIVE TEST (Denied) ---" -ForegroundColor Cyan
    if ($leaks) {
        Write-Warning "DENIED privileges present on role:"
        $leaks | ForEach-Object { Write-Warning " ! $_" }
    }
    else {
        Write-Host "No DENIED privileges detected. Test plan compliant." -ForegroundColor Green
    }

    # --- CSV export ---
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $csvPath = "${RoleName}_Privileges_$timestamp.csv"
    $whatIfTag = if (-not $PSCmdlet.ShouldProcess) { " (WhatIf projection)" } else { "" }

    $after | ForEach-Object {
        [PSCustomObject]@{
            RoleName    = $RoleName
            PrivilegeId = $_
            Status      = "ALLOWED$whatIfTag"
            Timestamp   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            vCenter     = $Server
            IsDenied    = ($_ -in $DeniedPrivileges)
        }
    } | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nExport: $csvPath`n" -ForegroundColor Cyan
}

# ===================================================================
# MAIN
# ===================================================================
Write-Host "`n$('#' * 70)" -ForegroundColor Cyan
Write-Host " vCenter Role Privilege Updater" -ForegroundColor Cyan
Write-Host " vCenter : $vCenter" -ForegroundColor Cyan
Write-Host " Roles   : $(if($P1){$P1RoleName}) $(if($P3){$P3RoleName})" -ForegroundColor Cyan
Write-Host "$('#' * 70)`n" -ForegroundColor Cyan

# --- Connection ---
$ownConnection = $false
try {
    if (-not ($global:DefaultVIServers | Where-Object { $_.Name -eq $vCenter })) {
        Write-Host "Connecting to $vCenter ..." -ForegroundColor Yellow
        Connect-VIServer -Server $vCenter -ErrorAction Stop | Out-Null
        $ownConnection = $true
    }
    Write-Host "Successfully connected to $vCenter`n" -ForegroundColor Green
}
catch {
    Write-Error "Connection failed: $_" -ErrorAction Stop
}

# --- Updates with try/catch for graceful error handling ---
$success = $true

if ($P1) {
    try {
        Update-VCenterRole -RoleName $P1RoleName `
                           -DesiredPrivileges $p1Allowed `
                           -DeniedPrivileges $p1Denied `
                           -Label "P1 UPDATE" `
                           -Server $vCenter
    }
    catch {
        Write-Warning "P1 update failed: $_"
        $success = $false
    }
}

if ($P3) {
    try {
        Update-VCenterRole -RoleName $P3RoleName `
                           -DesiredPrivileges $p3Allowed `
                           -DeniedPrivileges $p3Denied `
                           -Label "P3 UPDATE" `
                           -Server $vCenter
    }
    catch {
        Write-Warning "P3 update failed: $_"
        $success = $false
    }
}

# --- Result ---
Write-Host "`n$('#' * 70)" -ForegroundColor Cyan
if ($success) {
    Write-Host " All selected roles updated successfully." -ForegroundColor Green
}
else {
    Write-Warning " One or more roles had issues. Check output above."
}
Write-Host "$('#' * 70)`n" -ForegroundColor Cyan

# --- Disconnect only if we created the connection ---
if ($ownConnection) {
    Disconnect-VIServer -Server $vCenter -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Disconnected from $vCenter.`n" -ForegroundColor Yellow
}
