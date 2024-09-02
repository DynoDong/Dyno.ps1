$report = @()

# Header for File Search Results
$report += "File Search Results:`n"
$report += "*********************************************`n"

$extensions = @(".exe", ".bat", ".cmd", ".ps1", ".com", ".vbs")
$searchPath = "C:\"

try {
    Write-Host "Scanning for files with extensions: $($extensions -join ', ')"
    $filesWithExtensions = Get-ChildItem -Path $searchPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $extensions -contains [System.IO.Path]::GetExtension($_.FullName).ToLower()
    }
    
    if ($filesWithExtensions) {
        $report += "Files with specified extensions found:`n"
        $filesWithExtensions | ForEach-Object { $report += " - $($_.FullName)`n" }
    } else {
        $report += "No files with specified extensions found.`n"
    }
    
    Write-Host "Scan complete."
} catch {
    $report += "An error occurred during file scanning: $_`n"
}

# Header for Pattern Search Results
$report += "`nSearch Criteria Results:`n"
$report += "*********************************************`n"

$searchCriteria = @("loader") # Add or modify file patterns as needed
$searchPath = "C:\"

try {
    Write-Host "Searching for files matching the criteria: $($searchCriteria -join ', ')"
    foreach ($pattern in $searchCriteria) {
        $filesMatchingCriteria = Get-ChildItem -Path $searchPath -Recurse -Include $pattern -ErrorAction SilentlyContinue
        if ($filesMatchingCriteria) {
            $report += "Files matching pattern '$pattern' found:`n"
            $filesMatchingCriteria | ForEach-Object { $report += " - $($_.FullName)`n" }
        } else {
            $report += "No files matching pattern '$pattern' found.`n"
        }
    }
    
    Write-Host "Search complete."
} catch {
    $report += "An error occurred during pattern search: $_`n"
}

# Header for System Check Results
$report += "`nSystem Check Results:`n"
$report += "*********************************************`n"

try {
    $kernelDmaProtection = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume | Select-Object -ExpandProperty ProtectionStatus
    if ($kernelDmaProtection -eq $null) {
        $report += "Kernel DMA Protection: Not available or cannot be determined`n"
    } elseif ($kernelDmaProtection -eq 0) {
        $report += "Kernel DMA Protection: Disabled`n"
    } else {
        $report += "Kernel DMA Protection: Enabled`n"
    }
} catch {
    $report += "Kernel DMA Protection: Error checking`n"
}

try {
    $secureBoot = Confirm-SecureBootUEFI
    if ($secureBoot -eq $true) {
        $report += "Secure Boot: Enabled`n"
    } else {
        $report += "Secure Boot: Disabled`n"
    }
} catch {
    $report += "Secure Boot: Error checking`n"
}

try {
    $vbsStatus = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard
    if ($vbsStatus -eq $null) {
        $report += "Virtualization-Based Security (VBS): Not available or cannot be determined`n"
    } elseif ($vbsStatus.RequiredSecurityProperties -eq 0) {
        $report += "Virtualization-Based Security (VBS): Not allowed`n"
    } else {
        $report += "Virtualization-Based Security (VBS): Allowed`n"
    }
} catch {
    $report += "Virtualization-Based Security (VBS): Error checking`n"
}

try {
    $hyperVStatus = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($hyperVStatus.HypervisorPresent -eq $true) {
        $report += "Hyper-V Virtualization: Enabled in firmware`n"
    } else {
        $report += "Hyper-V Virtualization: Not enabled in firmware`n"
    }
} catch {
    $report += "Hyper-V Virtualization: Error checking`n"
}

try {
    $pciDevices = Get-CimInstance -ClassName Win32_PnPSignedDriver | Where-Object { $_.DeviceID -like "*PCI*" }
    if ($pciDevices) {
        $report += "Devices connected to PCIe ports:`n"
        foreach ($device in $pciDevices) {
            $report += " - $($device.DeviceName) ($($device.DeviceID))`n"
        }
    } else {
        $report += "No PCIe devices found or cannot be determined`n"
    }
} catch {
    $report += "PCIe Devices: Error checking`n"
}

# Retrieve Windows Installation Date
$report += "`nSystem Information:`n"
$report += "*********************************************`n"

try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $installationDate = $osInfo.InstallDate
    $report += "Windows Installation Date: $installationDate`n"
} catch {
    $report += "Windows Installation Date: Error retrieving information`n"
}

$report | ForEach-Object { Write-Output $_ }

Write-Output "System check completed."

# Email the results
try {
    $smtpServer = "smtp.gmail.com"
    $smtpPort = 587 # Port for TLS
    $smtpFrom = "tristan.downs66@gmail.com"
    $smtpTo = "tristan.downs66@gmail.com"
    $smtpUser = "tristan.downs66@gmail.com"
    $smtpPass = "yoyn xlny nqcj hfli" # Provided password

    $messageSubject = "PCcheckResults"
    $messageBody = $report -join "`n"
    
    Send-MailMessage -SmtpServer $smtpServer -Port $smtpPort -From $smtpFrom -To $smtpTo -Subject $messageSubject -Body $messageBody -Credential (New-Object PSCredential($smtpUser, (ConvertTo-SecureString $smtpPass -AsPlainText -Force))) -UseSsl
    Write-Output "Email sent successfully."
} catch {
    Write-Output "An error occurred while sending the email: $_"
}

# Generate a .txt file on the desktop and make it read-only
try {
    $desktopPath = [System.Environment]::GetFolderPath("Desktop")
    $filePath = Join-Path -Path $desktopPath -ChildPath "PcCheckLogs.txt"

    # Write the report to the file
    $report -join "`n" | Out-File -FilePath $filePath -Encoding UTF8

    # Set the file attribute to read-only
    $file = Get-Item -Path $filePath
    $file.Attributes = [System.IO.FileAttributes]::ReadOnly

    Write-Output "Report saved to $filePath and set to read-only."
} catch {
    Write-Output "An error occurred while creating the log file: $_"
}

Write-Host "Press Enter to close this window..."
Read-Host
