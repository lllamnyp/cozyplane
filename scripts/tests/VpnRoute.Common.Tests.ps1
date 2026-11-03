$modulePath = Join-Path $PSScriptRoot '..\VpnRoute.Common.psm1'
Import-Module $modulePath -Force

Describe 'Test-VpnRouteRequest' {
    It 'accepts a route that excludes the VPN next hop' {
        { Test-VpnRouteRequest -DestinationPrefix '172.16.0.0/16' -InterfaceIndex 7 `
            -NextHop '192.0.2.1' -ExcludedNextHop '198.51.100.1' -RouteMetric 5 } | Should Not Throw
    }

    It 'rejects the excluded VPN next hop as the route gateway' {
        { Test-VpnRouteRequest -DestinationPrefix '172.16.0.0/16' -InterfaceIndex 7 `
            -NextHop '198.51.100.1' -ExcludedNextHop '198.51.100.1' -RouteMetric 5 } | Should Throw
    }

    It 'rejects a destination without CIDR notation' {
        { Test-VpnRouteRequest -DestinationPrefix '172.16.0.0' -InterfaceIndex 7 `
            -NextHop '192.0.2.1' -ExcludedNextHop '198.51.100.1' -RouteMetric 5 } | Should Throw
    }
}

Describe 'Set-VpnBypassRoute' {
    It 'exposes PowerShell WhatIf support' {
        $scriptPath = Join-Path $PSScriptRoot '..\Set-VpnBypassRoute.ps1'
        (Get-Command $scriptPath).Parameters.ContainsKey('WhatIf') | Should Be $true
    }

    It 'executes WhatIf without changing the route table' {
        $scriptPath = Join-Path $PSScriptRoot '..\Set-VpnBypassRoute.ps1'
        $candidate = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
            Where-Object { $_.NextHop -ne '0.0.0.0' } |
            Sort-Object RouteMetric |
            Select-Object -First 1
        if ($null -eq $candidate) {
            Set-TestInconclusive 'No usable IPv4 default route is available.'
        }

        { & $scriptPath -Mode Ensure -DestinationPrefix '198.51.100.42/32' `
            -InterfaceIndex $candidate.InterfaceIndex -NextHop $candidate.NextHop `
            -ExcludedNextHop '192.0.2.254' -WhatIf | Out-Null } | Should Not Throw
    }
}
