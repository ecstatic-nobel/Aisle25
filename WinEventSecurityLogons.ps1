#
# Description:  Searches the Windows Security Event logs for user login attempts and write it to a CSV file.
# Usage:        .\WinEventSecurityLogons.ps1 -OutputFile OUTPUTFILE
#

Param (
    [Parameter(Mandatory=$True)]
    [string]$OutputFile
)

Get-EventLog -LogName Security |
    ? {$_.EventID -eq 4624 -or $_.EventID -eq 4625} |
    Select EventID, @{Name="Domain";Expression={$_.ReplacementStrings[6]}}, @{Name="User";Expression={$_.ReplacementStrings[5]}}, @{Name="ComputerName";Expression={$_.ReplacementStrings[11]}}, @{Name="SourceNetworkAddress";Expression={$_.ReplacementStrings[18]}} | where {$_.ComputerName -ne '-'} |
    Export-Csv -NoTypeInformation $OutputFile
