# Define Event IDs for checking
$EventIDs = @(3079, 4660, 4663, 1102, 104, 1100)
$EventLogs = @("Application", "Security", "System")
$Results = @()

# Check for log changes
foreach ($EventLog in $EventLogs) {
    Write-Host "Checking log: $EventLog"
    
    foreach ($EventID in $EventIDs) {
        Write-Host "Checking Event ID: $EventID"
        $Events = Get-WinEvent -LogName $EventLog -FilterXPath "*[System/EventID=$EventID]" -MaxEvents 3 -ErrorAction SilentlyContinue
        
        if ($Events) {
            foreach ($Event in $Events) {
                # Select relevant properties for output
                $Results += [PSCustomObject]@{
                    TimeCreated = $Event.TimeCreated
                    EventID = $Event.Id
                    LogName = $Event.LogName
                    Message = $Event.Message
                    Level = $Event.LevelDisplayName
                }
            }
        } else {
            Write-Host "No events found for ID $EventID in log $EventLog"
        }
    }
}

# Check for log clearance (Event ID 1102)
$ClearanceEvents = Get-WinEvent -LogName Security -FilterXPath "*[System/EventID=1102]" -MaxEvents 3 -ErrorAction SilentlyContinue
if ($ClearanceEvents) {
    Write-Host "Log clearance events found in Security log."
    foreach ($Event in $ClearanceEvents) {
        $Results += [PSCustomObject]@{
            TimeCreated = $Event.TimeCreated
            EventID = $Event.Id
            LogName = $Event.LogName
            Message = $Event.Message
            Level = $Event.LevelDisplayName
        }
    }
} else {
    Write-Host "No log clearance events found."
}

# Check for log modifications (Event ID 104 and 1100)
$ModificationEvents = Get-WinEvent -LogName Security -FilterXPath "*[System/EventID=104 or System/EventID=1100]" -MaxEvents 3 -ErrorAction SilentlyContinue
if ($ModificationEvents) {
    Write-Host "Log modification events found in Security log."
    foreach ($Event in $ModificationEvents) {
        $Results += [PSCustomObject]@{
            TimeCreated = $Event.TimeCreated
            EventID = $Event.Id
            LogName = $Event.LogName
            Message = $Event.Message
            Level = $Event.LevelDisplayName
        }
    }
} else {
    Write-Host "No log modification events found."
}

# Export results if any events were found
if ($Results) {
    $OutputPath = "$($env:USERPROFILE)\Desktop\RLUEvents.csv"
    $Results | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Logs exported to $OutputPath"
} else {
    Write-Host "No matching events found."
}
