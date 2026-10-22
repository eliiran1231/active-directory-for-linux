param([Parameter(Mandatory)][string]$Since)
$ErrorActionPreference = 'Stop'
# Read existing events only. Never enable logs or alter Schannel policy.
# Event timing alone does not attribute an event to a fixture connection.
try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'System'; ProviderName = 'Schannel'; StartTime = [DateTime]::Parse($Since)
    } -MaxEvents 50 -ErrorAction Stop)
    Write-Host "Existing Schannel events in test window: $($events.Count) (maximum 50; attribution not established)"
    foreach ($event in $events) {
        Write-Host "Schannel event id=$($event.Id); utc=$($event.TimeCreated.ToUniversalTime().ToString('o'))"
        [xml]$xml = $event.ToXml()
        foreach ($field in $xml.Event.EventData.Data) {
            # Do not publish rendered messages, certificate blobs, account names,
            # arbitrary event fields or payloads. Only known numeric status fields.
            if ($field.Name -in @('ErrorCode', 'ErrorState', 'AlertDesc', 'Status', 'Type') -and
                $field.InnerText -match '^(0x[0-9a-fA-F]+|[0-9]+)$') {
                Write-Host "  $($field.Name)=$($field.InnerText)"
            }
        }
    }
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        Write-Host 'Existing Schannel events: no matching events in test window.'
    } else {
        Write-Host "Existing Schannel events unavailable: category=$($_.CategoryInfo.Category); type=$($_.Exception.GetType().Name); HResult=$('{0:X8}' -f $_.Exception.HResult)"
    }
}
