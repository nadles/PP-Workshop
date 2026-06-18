Get-BitLockerVolume | ForEach-Object {
    $vol = $_

    $vol.KeyProtector |
    Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"} |
    ForEach-Object {

        try {
            BackupToAAD-BitLockerKeyProtector `
                -MountPoint $vol.MountPoint `
                -KeyProtectorId $_.KeyProtectorId `
                -ErrorAction Stop

            Write-Output "$env:COMPUTERNAME OK"
        }
        catch {
            Write-Output "$env:COMPUTERNAME ERROR $_"
        }
    }
}
