Describe 'Test-ExpressVpnRoute' {
    It 'handles an empty DNS name list under StrictMode' {
        $scriptPath = Join-Path $PSScriptRoot '..\Test-ExpressVpnRoute.ps1'
        & powershell.exe -NoProfile -File $scriptPath -Destination '127.0.0.1' `
            -Port 9 -TcpTimeoutSeconds 1 *> $null

        (@(2, 3, 4)).Contains($LASTEXITCODE) | Should Be $true
    }
}
