param(
    [Parameter(Mandatory = $true)][ValidatePattern('^wg-client-[0-9]+-[0-9]+$')][string]$Namespace,
    [Parameter(Mandatory = $true)][ValidatePattern('^10\.250\.[12]\.[0-9]+$')][string]$Target
)
# Run after the Linux suite with KEEP=1 (its deleted client frees a quota slot).
# The profile is temporary, uses only test routes, and never exports its private key.
$ErrorActionPreference = 'Stop'
$context = 'kind-cozyplane-wg-client'
$runner = 'cozyplane-wg-client-tools'
$kubeconfig = '/tmp/cozyplane-wg-client/kubeconfig'
$session = 'wgctest' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$wg = (Get-Command wg.exe).Source
$wireguard = (Get-Command wireguard.exe).Source
$directory = Join-Path ([IO.Path]::GetTempPath()) $session
$profile = Join-Path $directory ($session + '.conf')
$errorLog = Join-Path $directory 'tunnel-error.log'
$outputLog = Join-Path $directory 'tunnel-output.log'
$installed = $false
$installAttempted = $false
$connectionCreated = $false
$serviceCreated = $false
$labelledPods = @()
$pod = $null
function Kube {
    param([string[]]$Arguments)
    $output = & rtk proxy docker exec -e "KUBECONFIG=$kubeconfig" $runner kubectl --context $context -n $Namespace @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Dedicated-cluster command failed.' }
    return $output
}
function Create-Object {
    param($Object)
    $Object | ConvertTo-Json -Depth 20 | & rtk proxy docker exec -i -e "KUBECONFIG=$kubeconfig" $runner kubectl --context $context -n $Namespace create -f - | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Dedicated fixture creation failed.' }
}
function Update-Endpoint {
    $gateway = (Kube @('get','vpngateway','gateway','-o','json')) | ConvertFrom-Json
    $port = (& rtk proxy docker exec -e "KUBECONFIG=$kubeconfig" $runner kubectl --context $context get port $gateway.status.appliancePort -o json) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $port.spec.podName) { throw 'Gateway selected appliance is unavailable.' }
    $selected = $port.spec.podName
    if ($selected -ne $script:pod) {
        Kube @('label','pod',$selected,"cozyplane.test/windows-endpoint=$session") | Out-Null
        $script:labelledPods += $selected
        if ($script:pod) {
            Kube @('label','pods','-l',"cozyplane.test/windows-endpoint=$session",'--field-selector',"metadata.name=$($script:pod)",'cozyplane.test/windows-endpoint-') | Out-Null
        }
        $script:pod = $selected
    }
}
try {
    if (Get-Service -Name ('WireGuardTunnel$' + $session) -ErrorAction SilentlyContinue) { throw 'Temporary tunnel name already exists.' }
    $existingTestRoutes = @(Get-NetRoute -AddressFamily IPv4 | Where-Object {
        $_.DestinationPrefix -match '^10\.250\.[12]\.'
    })
    if ($existingTestRoutes.Count -gt 0) { throw 'Existing Windows routes overlap the dedicated test CIDRs; temporary profile was not installed.' }
    New-Item -ItemType Directory -Path $directory | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($identity in @($sid, (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory -AclObject $acl
    $private = (& $wg genkey).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Local WireGuard key generation failed.' }
    $public = ($private | & $wg pubkey).Trim()
    Create-Object @{apiVersion='sdn.cozystack.io/v1alpha1';kind='VPNConnection';metadata=@{name=$session};spec=@{
        gatewayRef=@{name='gateway'};wireguard=@{peerPublicKey=$public;client=@{addressPools=@('clients-v4');vpcRefs=@(@{name='site-a'},@{name='site-b'})}}
    }}
    $connectionCreated = $true
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    do {
        $connection = (Kube @('get','vpnconnection',$session,'-o','json')) | ConvertFrom-Json
        $ready = @($connection.status.conditions | Where-Object {
            $_.type -eq 'ClientConfigured' -and $_.status -eq 'True' -and $_.observedGeneration -eq $connection.metadata.generation
        }).Count -gt 0
        if (-not $ready) { Start-Sleep -Seconds 2 }
    } until ($ready -or [DateTime]::UtcNow -gt $deadline)
    if (-not $ready) { throw 'Workstation configuration was not applied.' }
    foreach ($prefix in $connection.status.clientConfig.allowedIPs) {
        if ($prefix -notin @('10.250.1.0/24','10.250.2.0/24')) { throw 'Profile contains a route outside the dedicated fixture.' }
    }
    Update-Endpoint
    Create-Object @{apiVersion='v1';kind='Service';metadata=@{name=$session};spec=@{
        type='NodePort';selector=@{'cozyplane.test/windows-endpoint'=$session};ports=@(@{name='wireguard';protocol='UDP';port=51820;targetPort=51820;nodePort=31820})
    }}
    $serviceCreated = $true
    $addresses = @($connection.status.assignedAddresses | ForEach-Object { "$_/32" }) -join ', '
    $allowed = $connection.status.clientConfig.allowedIPs -join ', '
    $config = @"
[Interface]
PrivateKey = $private
Address = $addresses
MTU = $($connection.status.clientConfig.mtu)

[Peer]
PublicKey = $($connection.status.clientConfig.serverPublicKey)
Endpoint = 127.0.0.1:51829
AllowedIPs = $allowed
PersistentKeepalive = 5
"@
    [IO.File]::WriteAllText($profile, $config, (New-Object Text.UTF8Encoding $false))
    $config = $null; $private = $null
    $installAttempted = $true
    $install = Start-Process -FilePath $wireguard -ArgumentList @('/installtunnelservice', ('"' + $profile + '"')) -WindowStyle Hidden -Wait -PassThru -RedirectStandardError $errorLog -RedirectStandardOutput $outputLog
    if ($install.ExitCode -ne 0) {
        $diagnostic = Get-Content -LiteralPath $errorLog -Raw
        if ($diagnostic -match '(?i)(access.*denied|acc.*refus|administrator|administrateur)') {
            throw 'Windows refused permission to create the temporary WireGuard tunnel service (access denied).'
        }
        throw "Temporary WireGuard tunnel installation failed with exit code $($install.ExitCode); private diagnostics were not exported."
    }
    $installed = $true
    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    [System.Net.WebRequest]::DefaultWebProxy = $null
    do {
        try {
            Update-Endpoint
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://${Target}:8080/" -TimeoutSec 4
            if ($response.StatusCode -eq 200 -and $response.Content.Trim() -eq ('site-' + @{'1'='a';'2'='b'}[$Target.Split('.')[2]])) { break }
            $response = $null
        }
        catch { Start-Sleep -Seconds 2 }
    } until ([DateTime]::UtcNow -gt $deadline)
    if (-not $response -or $response.StatusCode -ne 200) { throw 'Windows application traffic over the temporary WireGuard profile failed.' }
    Write-Output "PASS: Windows WireGuard application traffic via dedicated UDP NodePort; HTTP $($response.StatusCode)."
} finally {
    if ($installAttempted -and ($installed -or (Get-Service -Name ('WireGuardTunnel$' + $session) -ErrorAction SilentlyContinue))) {
        $uninstall = Start-Process -FilePath $wireguard -ArgumentList @('/uninstalltunnelservice', $session) -WindowStyle Hidden -Wait -PassThru -RedirectStandardError $errorLog -RedirectStandardOutput $outputLog
        if ($uninstall.ExitCode -ne 0) { Write-Warning 'Temporary WireGuard tunnel cleanup failed.' }
    }
    if ($serviceCreated) { try { Kube @('delete','service',$session,'--ignore-not-found') | Out-Null } catch { Write-Warning 'Temporary Service cleanup failed.' } }
    if ($connectionCreated) { try { Kube @('delete','vpnconnection',$session,'--ignore-not-found','--timeout=180s') | Out-Null } catch { Write-Warning 'Temporary VPNConnection cleanup failed.' } }
    if ($labelledPods.Count) { try { Kube @('label','pods','-l',"cozyplane.test/windows-endpoint=$session",'cozyplane.test/windows-endpoint-') | Out-Null } catch {} }
    if (Test-Path -LiteralPath $profile) { Remove-Item -LiteralPath $profile }
    if (Test-Path -LiteralPath $errorLog) { Remove-Item -LiteralPath $errorLog }
    if (Test-Path -LiteralPath $outputLog) { Remove-Item -LiteralPath $outputLog }
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory }
}
