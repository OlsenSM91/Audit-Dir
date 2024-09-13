# Ensure you run this script with administrative privileges for auditing changes
param (
    [string]$DirectoryPath = $null,  # Optional argument for the directory path
    [string]$WebhookURL = $null      # Optional argument for the Discord webhook URL
)

# Function to ensure required modules and tools are available
function Ensure-RequiredModules {
    try {
        # Check if the System.Windows.Forms assembly is available for the folder browser dialog
        try {
            Add-Type -AssemblyName System.Windows.Forms
        } catch {
            Write-Host "The 'System.Windows.Forms' assembly is missing. Attempting to install it..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
            Install-Module -Name WindowsForms -Force -ErrorAction Stop
            Add-Type -AssemblyName System.Windows.Forms
            Write-Host "'System.Windows.Forms' successfully installed and loaded."
        }

        # Check if the 'auditpol' command is available
        $auditPolicy = Get-Command auditpol.exe -ErrorAction SilentlyContinue
        if (-not $auditPolicy) {
            Write-Error "'auditpol' command is not available on this system. This script requires 'auditpol' to function correctly."
            exit
        }
    } catch {
        Write-Error "An error occurred while ensuring required modules and tools: $_"
        exit
    }
}

# Function to show folder browser dialog
function Select-FolderDialog {
    try {
        # Load the Windows Forms assembly for the folder browser dialog
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select the directory to enable auditing"  # Instruction for the user
        $folderBrowser.ShowNewFolderButton = $true  # Allow creating new folders if needed

        # Show the dialog and capture the selected folder path
        if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            return $folderBrowser.SelectedPath  # Return the selected folder path
        }
    } catch {
        Write-Error "An error occurred while trying to open the folder browser dialog: $_"
    }
    return $null  # Return null if no folder is selected or if an error occurs
}

# Function to check and configure the Audit Object Access policy
function Ensure-AuditPolicy {
    try {
        # Check if the 'auditpol' command is available (already done in Ensure-RequiredModules)
        $auditPolicy = Get-Command auditpol.exe -ErrorAction SilentlyContinue
        if (-not $auditPolicy) {
            Write-Error "The 'auditpol' command is not available. Exiting script."
            exit
        }

        # Retrieve the current audit policy for "Object Access" - File System
        $objectAccess = & auditpol /get /category:"Object Access" /subcategory:"File System"

        # Check if Success and Failure are not enabled
        if ($objectAccess -notmatch "Success.*Yes" -or $objectAccess -notmatch "Failure.*Yes") {
            Write-Host "Audit Object Access is not properly configured. Enabling Success and Failure auditing."

            # Enable Success and Failure auditing for the "File System"
            & auditpol /set /subcategory:"File System" /success:enable /failure:enable
            if ($?) {
                Write-Host "Audit Object Access policy has been successfully updated."
            } else {
                Write-Error "Failed to update the Audit Object Access policy. Please check permissions or system settings."
                exit
            }
        } else {
            Write-Host "Audit Object Access policy is already correctly configured."
        }
    } catch {
        Write-Error "An error occurred while ensuring the Audit Object Access policy: $_"
        exit
    }
}

# Function to get current auditing rules for the directory
function Get-CurrentAuditing {
    param (
        [string]$DirectoryPath
    )

    try {
        # Get the ACL (Access Control List) for the directory
        $acl = Get-Acl -Path $DirectoryPath

        # Get existing audit rules from the ACL
        $auditRules = $acl.Audit

        if ($auditRules.Count -eq 0) {
            return "No current auditing rules found for ${DirectoryPath}."
        } else {
            $auditSummary = "Current auditing rules for ${DirectoryPath}:" + "`n"
            foreach ($rule in $auditRules) {
                $auditSummary += "Principal: $($rule.IdentityReference) - Access: $($rule.FileSystemRights) - AuditFlags: $($rule.AuditFlags)" + "`n"
            }
            return $auditSummary
        }
    } catch {
        Write-Error "Failed to retrieve the current auditing rules for ${DirectoryPath}: $_"
        return "Error retrieving auditing rules."
    }
}

# Function to configure file system auditing on the specified directory
function Enable-DirectoryAuditing {
    param (
        [string]$DirectoryPath  # The directory path to enable auditing on
    )

    try {
        # Define the auditing permissions (File Edit, Access, and Deletion)
        $rights = [System.Security.AccessControl.FileSystemRights]"Write, Delete, Read, ExecuteFile, ChangePermissions, TakeOwnership"

        # Define correct Inheritance and Propagation flags
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        $auditFlags = [System.Security.AccessControl.AuditFlags]"Success, Failure"

        # Create a new FileSystemAuditRule for the directory
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", $rights, $inheritanceFlags, $propagationFlags, $auditFlags)

        # Get the current ACL (Access Control List) for the directory
        $acl = Get-Acl $DirectoryPath

        # Add the new audit rule to the ACL
        $acl.AddAuditRule($rule)

        # Apply the updated ACL back to the directory
        Set-Acl -Path $DirectoryPath -AclObject $acl

        # Verify if the new auditing rule has been applied
        $updatedAuditRules = Get-CurrentAuditing -DirectoryPath $DirectoryPath
        if ($updatedAuditRules -notmatch "Principal: Everyone") {
            throw "Failed to apply auditing rules for ${DirectoryPath}."
        }

        Write-Host "Auditing has been successfully enabled for the directory: ${DirectoryPath}."
        Write-Host "File edits, access, and deletions will now be logged in the Event Viewer."
    } catch {
        Write-Error "An error occurred while enabling auditing for the directory ${DirectoryPath}: $_"
    }
}

# Function to send the summary to a Discord webhook
function Send-DiscordWebhook {
    param (
        [string]$WebhookURL,
        [string]$Message
    )

    try {
        # Ensure the webhook URL is provided
        if (-not $WebhookURL) {
            Write-Warning "Discord webhook URL not provided. Skipping webhook notification."
            return
        }

        # Send a POST request to the Discord webhook
        $payload = @{
            content = $Message
        } | ConvertTo-Json

        Invoke-RestMethod -Uri $WebhookURL -Method Post -Body $payload -ContentType 'application/json'
        Write-Host "Summary sent to Discord webhook."
    } catch {
        Write-Error "Failed to send the summary to the Discord webhook: $_"
    }
}

# Check if the script is being run with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as an administrator. Please restart it with elevated privileges."
    exit
}

# Ensure required modules and tools are available
Ensure-RequiredModules

# Check and ensure that Audit Object Access is configured
Ensure-AuditPolicy

# Check if the directory path was provided as an argument
if (-not $DirectoryPath) {
    # If no directory path was provided, open the folder browser dialog
    $DirectoryPath = Select-FolderDialog
}

# If a directory path was not selected or provided, exit the script
if (-not $DirectoryPath) {
    Write-Error "No directory was selected or provided. Exiting the script."
    exit
}

# Check if the directory exists before proceeding
if (-not (Test-Path -Path $DirectoryPath -PathType Container)) {
    Write-Error "The specified directory '${DirectoryPath}' does not exist. Please provide a valid directory."
    exit
}

# Get the current auditing configuration for the directory
$currentAuditing = Get-CurrentAuditing -DirectoryPath $DirectoryPath
Write-Host "`n$currentAuditing"

# Enable auditing on the specified directory
Enable-DirectoryAuditing -DirectoryPath $DirectoryPath

# Prepare a summary of the script's actions
$summary = "${currentAuditing}`nAuditing has been successfully enabled for ${DirectoryPath}.`n"

# Send the summary to Discord webhook, if provided
Send-DiscordWebhook -WebhookURL $WebhookURL -Message $summary

# Output the summary to the console
Write-Host "`nSummary:`n$summary"
