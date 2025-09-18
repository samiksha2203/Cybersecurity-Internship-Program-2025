# Hybrid FIM - FileSystemWatcher + synchronous hash polling (robust)
# Save as watcher.ps1. Run in PowerShell: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force ; .\watcher.ps1

$watchPath = "D:\Shivani Practice\Cybersecurity\FIM\watched"
$logFile   = "D:\Shivani Practice\Cybersecurity\FIM\logs\fim_log.txt"

# Ensure folders exist
if (-not (Test-Path $watchPath)) { New-Item -Path $watchPath -ItemType Directory -Force | Out-Null }
$logDir = Split-Path $logFile
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

# Small helper to write to console + log file (safe)
function Write-Log {
    param($type, $filePath)
    try {
        $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $user = $env:USERNAME
        $line = "$time`t$type`t$filePath`t$user"
        Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
        Write-Host $line
    } catch {
        Write-Host "Failed to write log: $_"
    }
}

# Build initial hash baseline
$hashTable = @{}
Write-Host "Initializing baseline hashes..."
Get-ChildItem -Path $watchPath -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $h = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        $h = $null
    }
    $hashTable[$_.FullName] = $h
    # Optional: comment out next line if you don't want a long baseline print
    Write-Host "BASELINE: $($_.FullName) -> $h"
}

# Create FileSystemWatcher
$fsw = New-Object System.IO.FileSystemWatcher $watchPath -Property @{
    IncludeSubdirectories = $true
    NotifyFilter = [System.IO.NotifyFilters]'FileName, DirectoryName, LastWrite, Size, CreationTime'
    Filter = '*.*'
}
$fsw.EnableRaisingEvents = $true

# Use $user variable in remote actions
$user = $env:USERNAME

# Register events (these actions only log; they will not try to modify $hashTable)
$created = Register-ObjectEvent $fsw Created -Action {
    try {
        $f = $Event.SourceEventArgs.FullPath
        $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $line = "$t`tCREATED`t$f`t$using:user"
        Add-Content -Path $using:logFile -Value $line -ErrorAction SilentlyContinue
        Write-Host $line
    } catch { Write-Host "Created-event action error: $_" }
}

$deleted = Register-ObjectEvent $fsw Deleted -Action {
    try {
        $f = $Event.SourceEventArgs.FullPath
        $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $line = "$t`tDELETED`t$f`t$using:user"
        Add-Content -Path $using:logFile -Value $line -ErrorAction SilentlyContinue
        Write-Host $line
    } catch { Write-Host "Deleted-event action error: $_" }
}

$renamed = Register-ObjectEvent $fsw Renamed -Action {
    try {
        $old = $Event.SourceEventArgs.OldFullPath
        $new = $Event.SourceEventArgs.FullPath
        $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $line = "$t`tRENAMED`t$old -> $new`t$using:user"
        Add-Content -Path $using:logFile -Value $line -ErrorAction SilentlyContinue
        Write-Host $line
    } catch { Write-Host "Renamed-event action error: $_" }
}

Write-Host "Watcher registered. Starting polling loop..."
Write-Host "Log file: $logFile"
Write-Host "Perform file actions in: $watchPath"
Write-Host "Press Enter in this window to stop the watcher."

# Main polling loop - synced, updates $hashTable safely
$stop = $false
# We'll poll every 2 seconds but allow immediate Enter to stop
while (-not $stop) {
    try {
        $currentFiles = Get-ChildItem -Path $watchPath -File -Recurse -ErrorAction SilentlyContinue
        # Check each file for hash changes or new files
        foreach ($f in $currentFiles) {
            $p = $f.FullName
            try {
                $newHash = (Get-FileHash -Path $p -Algorithm SHA256 -ErrorAction Stop).Hash
            } catch {
                $newHash = $null
            }

            if (-not $hashTable.ContainsKey($p)) {
                # New file discovered by polling (Created event may have fired too)
                if ($newHash) { Write-Log "HASH_CREATED" $p } else { Write-Log "CREATED" $p }
                $hashTable[$p] = $newHash
            } else {
                $oldHash = $hashTable[$p]
                if ($newHash -and $oldHash -and ($newHash -ne $oldHash)) {
                    Write-Log "HASH_CHANGED" $p
                    $hashTable[$p] = $newHash
                } elseif (-not $newHash -and $oldHash) {
                    # file unreadable now
                    Write-Log "HASH_UNREADABLE" $p
                    $hashTable[$p] = $newHash
                }
            }
        }

        # Detect deleted files (present in hashTable but no longer on disk)
        $deletedKeys = $hashTable.Keys | Where-Object { -not (Test-Path $_) }
        foreach ($dk in $deletedKeys) {
            Write-Log "HASH_DELETED" $dk
            $null = $hashTable.Remove($dk)
        }
    } catch {
        Write-Host "Polling loop error (non-fatal): $_"
    }


    # wait loop with Enter-key check (2 seconds total)
    $waitMs = 2000
    $step = 200
    for ($i=0; $i -lt ($waitMs / $step); $i++) {
        Start-Sleep -Milliseconds $step
        if ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'Enter') { $stop = $true; break }
        }
    }
}

# Cleanup
Write-Host "Stopping... unregistering events."
Unregister-Event -SourceIdentifier $created.Name -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier $deleted.Name -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier $renamed.Name -ErrorAction SilentlyContinue
Unregister-Event -ErrorAction SilentlyContinue
try { $fsw.Dispose() } catch {}
Write-Host "Watcher stopped."
