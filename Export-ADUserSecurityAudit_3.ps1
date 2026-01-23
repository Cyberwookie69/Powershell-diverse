#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Exports security-relevant AD user attributes to CSV.

.DESCRIPTION
    This script reads all users from the local Active Directory and exports
    authentication, access and audit-related fields to a CSV file.
    
    The script is intended for security audits and helps identify:
    - Accounts that are no longer in use (stale accounts)
    - Accounts with old passwords
    - Accounts that don't require a password (risk!)
    - Service accounts and shared mailboxes
    - Accounts with elevated privileges (adminCount)

.PARAMETER OutputPath
    Path to the output CSV file. Default: current directory with timestamp.

.PARAMETER SearchBase
    Optional OU to search. Default: entire domain.

.EXAMPLE
    .\Export-ADUserSecurityAudit.ps1
    .\Export-ADUserSecurityAudit.ps1 -OutputPath "C:\Audit\users.csv"
    .\Export-ADUserSecurityAudit.ps1 -SearchBase "OU=Users,DC=contoso,DC=com"

.NOTES
    Author: Security Audit Script
    Requires: ActiveDirectory PowerShell module and read access to AD
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".\AD_User_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter()]
    [string]$SearchBase
)

# ============================================================================
# HELPER FUNCTIONS
# These functions are called later in the script to process data
# ============================================================================

function Convert-FileTimeToDateTime {
    <#
    .SYNOPSIS
        Converts a Windows FileTime to a readable date/time.
        
    .DESCRIPTION
        Active Directory stores dates as "FileTime" - a number representing the
        number of 100-nanosecond intervals since January 1, 1601.
        This function converts that to a normal date that humans can read.
        
        Special values:
        - 0 = never set
        - 9223372036854775807 = "never" (used for accountExpires)
    #>
    param($FileTime)
    
    if ($null -eq $FileTime -or $FileTime -eq 0 -or $FileTime -eq 9223372036854775807) {
        return $null
    }
    try {
        return [DateTime]::FromFileTime($FileTime)
    }
    catch {
        return $null
    }
}

function Get-AccountType {
    <#
    .SYNOPSIS
        Determines the account type based on naming, location and properties.
        
    .DESCRIPTION
        Accounts are categorized to improve overview:
        - User Account:      Regular user accounts
        - Service Account:   Accounts for applications/services (e.g. svc_backup)
        - Admin Account:     Administrator accounts (e.g. admin.jansen)
        - External Account:  External employees, contractors
        - Test Account:      Test and temporary accounts
        - Disabled Account:  Accounts in a "former employees" OU
        - Machine Account:   Computer/server accounts
        
        Detection is based on:
        - Name patterns (svc_, admin., test., etc.)
        - OU location (OU=ServiceAccounts, OU=Admins, etc.)
        - Description field
        - UserAccountControl flags (for machine accounts)
    #>
    param(
        [string]$SamAccountName,
        [string]$DistinguishedName,
        [int]$UserAccountControl,
        [string]$Description
    )
    
    $sam = $SamAccountName.ToLower()
    $dn = $DistinguishedName.ToLower()
    $desc = if ($Description) { $Description.ToLower() } else { "" }
    
    # Machine accounts are identified by special UAC flags or $ at the end of the name
    if ($UserAccountControl -band 4096) { return "Machine Account" }      # WORKSTATION_TRUST_ACCOUNT
    if ($UserAccountControl -band 8192) { return "Server Account" }       # SERVER_TRUST_ACCOUNT
    if ($sam.EndsWith('$')) { return "Machine Account" }
    
    # Service accounts: often used for applications running under their own account
    if ($sam -match '^(svc[_-]|service[_-])' -or 
        $sam -match '(svc|service)$' -or
        $dn -match 'ou=service' -or
        $desc -match 'service account') {
        return "Service Account"
    }
    
    # Admin accounts: accounts with administrator privileges
    if ($sam -match '(^admin[_.-]|[_.-]admin$|^adm[_.-]|[_.-]adm$)' -or
        $dn -match 'ou=admin') {
        return "Admin Account"
    }
    
    # External accounts: temporary employees, contractors, vendors
    if ($sam -match '(^extern|^guest|^contractor|^vendor)' -or
        $dn -match 'ou=(external|guests|contractors|vendors)') {
        return "External Account"
    }
    
    # Test accounts: for testing purposes only
    if ($sam -match '(^test[_.-]|[_.-]test$|^tmp[_.-]|^temp[_.-])' -or
        $dn -match 'ou=test' -or
        $desc -match 'test\s?account') {
        return "Test Account"
    }
    
    # Disabled accounts in special OUs for former employees
    if ($dn -match 'ou=(disabled|former|ex-employees|uitdienst)') {
        return "Disabled Account"
    }
    
    # Everything that doesn't fall into the above categories is a regular user
    return "User Account"
}

function Test-IsSharedMailbox {
    <#
    .SYNOPSIS
        Checks if an account is a shared mailbox.
        
    .DESCRIPTION
        Shared mailboxes are email accounts used by multiple people,
        for example info@company.com or hr@company.com.
        
        Detection methods:
        1. Exchange attribute msExchRecipientTypeDetails (value 4 = shared mailbox)
        2. Name patterns: shared., mailbox., mbx., sm.
        3. OU location: OU=SharedMailboxes
        4. Description: "shared mailbox", "gedeelde mailbox", "functional mailbox"
    #>
    param(
        [string]$SamAccountName,
        [string]$DistinguishedName,
        [string]$Description,
        $RecipientTypeDetails
    )
    
    # Method 1: Exchange attribute (most reliable if present)
    # Value 4 means SharedMailbox in Exchange
    if ($null -ne $RecipientTypeDetails) {
        if ($RecipientTypeDetails -eq 4) { return $true }
    }
    
    # Method 2: Recognition based on naming and location
    $sam = $SamAccountName.ToLower()
    $dn = $DistinguishedName.ToLower()
    $desc = if ($Description) { $Description.ToLower() } else { "" }
    
    # Check name patterns that indicate a shared mailbox
    if ($sam -match '^(shared[_.-]|mailbox[_.-]|mbx[_.-]|sharedmailbox|sm[_.-])' -or
        $sam -match '([_.-]shared|[_.-]mailbox|[_.-]mbx)$') {
        return $true
    }
    
    # Check if account is in a shared mailbox OU
    if ($dn -match 'ou=(shared\s?mailbox|sharedmailboxes|shared|mailboxes)') {
        return $true
    }
    
    # Check description for indicators
    if ($desc -match 'shared\s?mailbox|gedeelde\s?mailbox|functionele\s?mailbox') {
        return $true
    }
    
    return $false
}

# ============================================================================
# MAIN SCRIPT
# This is where the actual execution of the script begins
# ============================================================================

# List of properties to retrieve from Active Directory
# These are later processed into the final CSV columns
$Properties = @(
    'SamAccountName'              # Username (login name)
    'DisplayName'                 # Display name (full name)
    'userAccountControl'          # Contains various account settings as bitflags
    'pwdLastSet'                  # When password was last changed
    'badPwdCount'                 # Number of failed login attempts
    'lockoutTime'                 # Time when account was locked
    'lastLogon'                   # Last login (per domain controller)
    'lastLogonTimestamp'          # Last login (replicated, less current)
    'whenCreated'                 # Creation date of the account
    'whenChanged'                 # Last modification date
    'adminCount'                  # 1 = account is/was member of an admin group
    'Description'                 # Description of the account
    'logonWorkstations'           # Restriction to specific computers
    'accountExpires'              # Expiration date of the account
    'DistinguishedName'           # Full AD path (for OU detection)
    'msExchRecipientTypeDetails'  # Exchange mailbox type (if Exchange is present)
)

Write-Host "Starting AD User Security Audit..." -ForegroundColor Cyan
Write-Host "Retrieving users from Active Directory..." -ForegroundColor Yellow

# Set up parameters for retrieving users
$GetADUserParams = @{
    Filter     = '*'              # Retrieve all users
    Properties = $Properties      # Include the above properties
}

# Optional: only search a specific OU
if ($SearchBase) {
    $GetADUserParams['SearchBase'] = $SearchBase
    Write-Host "SearchBase: $SearchBase" -ForegroundColor Yellow
}

# Retrieve all users from Active Directory
try {
    $Users = Get-ADUser @GetADUserParams
    Write-Host "Found $($Users.Count) users" -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve AD users: $_"
    exit 1
}

# ============================================================================
# PROCESSING
# Loop through all users and process the data into a usable format
# ============================================================================

$Results = foreach ($User in $Users) {
    
    # Convert date/time fields from FileTime to readable dates
    $pwdLastSetDate = Convert-FileTimeToDateTime -FileTime $User.pwdLastSet
    $lockoutTimeDate = Convert-FileTimeToDateTime -FileTime $User.lockoutTime
    $lastLogonDate = Convert-FileTimeToDateTime -FileTime $User.lastLogon
    $lastLogonTSDate = Convert-FileTimeToDateTime -FileTime $User.lastLogonTimestamp
    $accountExpiresDate = Convert-FileTimeToDateTime -FileTime $User.accountExpires

    # Determine the most recent login
    # lastLogon is per DC and very current, lastLogonTimestamp replicates but can be up to 14 days old
    # We take the most recent of the two
    $effectiveLastLogon = if ($lastLogonDate -gt $lastLogonTSDate) { $lastLogonDate } else { $lastLogonTSDate }

    # ========================================================================
    # Decode UserAccountControl (UAC) flags
    # This field contains multiple settings as bits. We extract the relevant ones.
    # ========================================================================
    $uac = $User.userAccountControl
    
    # Bit 2 (value 2): Account is disabled
    $isDisabled = [bool]($uac -band 2)
    
    # Account is locked if a lockoutTime is set
    $isLockedOut = if ($lockoutTimeDate) { $true } else { $false }
    
    # Bit 17 (value 65536): Password does NOT expire
    # We invert this so True = password DOES expire (safer)
    $passwordExpires = -not [bool]($uac -band 65536)
    
    # Bit 6 (value 32): Password not required - SECURITY RISK!
    $emptyPasswordAllowed = [bool]($uac -band 32)

    # Determine the account type (User, Service, Admin, etc.)
    $accountType = Get-AccountType -SamAccountName $User.SamAccountName `
                                   -DistinguishedName $User.DistinguishedName `
                                   -UserAccountControl $uac `
                                   -Description $User.Description

    # Check if it's a shared mailbox
    $isSharedMailbox = Test-IsSharedMailbox -SamAccountName $User.SamAccountName `
                                            -DistinguishedName $User.DistinguishedName `
                                            -Description $User.Description `
                                            -RecipientTypeDetails $User.msExchRecipientTypeDetails

    # ========================================================================
    # Compose output object
    # This will become one row in the CSV
    # ========================================================================
    [PSCustomObject]@{
        # Identification
        SamAccountName         = $User.SamAccountName
        DisplayName            = $User.DisplayName
        AccountType            = $accountType
        IsSharedMailbox        = $isSharedMailbox
        
        # Account Status
        IsDisabled             = $isDisabled          # True = account is disabled
        IsLockedOut            = $isLockedOut         # True = account is locked (too many failed attempts)
        PasswordExpires        = $passwordExpires     # True = password must be changed periodically
        EmptyPasswordAllowed   = $emptyPasswordAllowed # True = RISK: empty password allowed
        
        # Password information
        PasswordLastSet        = $pwdLastSetDate      # Date of last password change
        PasswordAge_Days       = if ($pwdLastSetDate) { [math]::Round(((Get-Date) - $pwdLastSetDate).TotalDays, 0) } else { $null }
        
        # Login information
        BadPasswordCount       = $User.badPwdCount    # Number of failed login attempts
        LastLogon              = $effectiveLastLogon  # Last successful login
        LastLogon_Days_Ago     = if ($effectiveLastLogon) { [math]::Round(((Get-Date) - $effectiveLastLogon).TotalDays, 0) } else { $null }
        
        # Lifecycle information
        WhenCreated            = $User.whenCreated    # When account was created
        WhenChanged            = $User.whenChanged    # Last modification to the account
        AccountExpires         = $accountExpiresDate  # Expiration date (empty = does not expire)
        
        # Privilege indicator
        AdminCount             = $User.adminCount     # 1 = account is/was member of an admin group
        
        # Other
        Description            = $User.Description    # Description of the account
        LogonWorkstations      = $User.logonWorkstations # Restriction to specific computers
    }
}

# ============================================================================
# EXPORT
# Write the results to a CSV file
# ============================================================================

try {
    # Export to CSV with semicolon as delimiter (for European Excel)
    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "`nExport completed successfully!" -ForegroundColor Green
    Write-Host "Output file: $((Resolve-Path $OutputPath).Path)" -ForegroundColor Cyan
    Write-Host "Total users exported: $($Results.Count)" -ForegroundColor Cyan
}
catch {
    Write-Error "Failed to export CSV: $_"
    exit 1
}

# ============================================================================
# SUMMARY
# Display an overview of potential security issues
# ============================================================================

Write-Host "`n--- Security Highlights ---" -ForegroundColor Magenta

$disabledCount = ($Results | Where-Object { $_.IsDisabled }).Count
$lockedCount = ($Results | Where-Object { $_.IsLockedOut }).Count
$adminCountSet = ($Results | Where-Object { $_.AdminCount -eq 1 }).Count
$noExpirePwd = ($Results | Where-Object { -not $_.PasswordExpires }).Count
$emptyPwdAllowed = ($Results | Where-Object { $_.EmptyPasswordAllowed }).Count
$staleAccounts = ($Results | Where-Object { $_.LastLogon_Days_Ago -gt 90 }).Count
$oldPasswords = ($Results | Where-Object { $_.PasswordAge_Days -gt 365 }).Count
$sharedMailboxes = ($Results | Where-Object { $_.IsSharedMailbox }).Count

Write-Host "Disabled accounts:           $disabledCount"
Write-Host "Locked out accounts:         $lockedCount"
Write-Host "AdminCount = 1:              $adminCountSet (privileged group membership)"
Write-Host "Password never expires:      $noExpirePwd"
Write-Host "Empty password allowed:      $emptyPwdAllowed (RISK!)"
Write-Host "Stale accounts (>90 days):   $staleAccounts"
Write-Host "Old passwords (>365 days):   $oldPasswords"
Write-Host "Shared mailboxes:            $sharedMailboxes"

Write-Host "`n--- Account Types ---" -ForegroundColor Magenta
$Results | Group-Object AccountType | Sort-Object Count -Descending | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count)"
}
