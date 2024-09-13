# Audit-Dir

This PowerShell script enables auditing on a specified directory, allowing you to track file edits, access, and deletions within the Windows Event Viewer.

**Features:**

* Checks for administrator privileges before running.
* Verifies the required 'auditpol' command for auditing configuration.
* Allows enabling auditing through two methods:
    * Downloading the script and running it directly with elevated privileges.
    * Using Inline Execution (irm | iex) for a one-time execution.
* Configures "Audit Object Access" policy for success and failure auditing.
* Adds auditing rules to the specified directory for "Everyone" user with detailed access rights.
* Retrieves and displays the current auditing configuration before and after modification.
* Optionally sends a summary of the script's actions to a Discord webhook (requires URL argument).

**Requirements:**

* PowerShell 5.1 or later
* Administrative privileges

**Installation (Method 1: Inline Execution):**

1. Open PowerShell as administrator.
2. Run the following command:

   ```powershell
   irm https://raw.githubusercontent.com/OlsenSM91/Audit-Dir/main/auditdir.ps1 | iex
   ```

**Installation (Method 2: Download and Run):**

1. Download the script:

   ```
   irm https://raw.githubusercontent.com/OlsenSM91/Audit-Dir/main/auditdir.ps1 -Outfile 'C:\Path\To\Save\script.ps1'
   ```

2. Run the script with elevated privileges:

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\Path\To\Save\script.ps1
   ```

**Usage:**

The script will walk you through selecting a directory or provide a default folder browser dialog. You can optionally specify a Discord webhook URL for a summary. This function can also be modified for Slack/Teams.

**Optional Argument:**

* `-WebhookURL`: Provide the URL of your Discord webhook to receive script execution details (silent).

**License:**

This script is licensed under The Unlicense, meaning you're free to use, modify, and distribute it freely.

**Example Usage (Download and Run):**

```powershell
powershell -ExecutionPolicy Bypass -File AuditDir.ps1 -DirectoryPath "C:\Users\Public\Documents" -WebhookURL "https://discord.com/api/webhooks/..."
```

**Example Usage (Inline Execution):**

```powershell
irm https://raw.githubusercontent.com/OlsenSM91/Audit-Dir/main/auditdir.ps1 | iex -ArgumentList "-DirectoryPath", "C:\Users\Public\Documents", "-WebhookURL", "https://discord.com/api/webhooks/..."
```

**Note:**

This script modifies system settings. Use it with caution and ensure proper backups before running.
