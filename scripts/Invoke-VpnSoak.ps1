[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Kctx,
    [string]$Kubeconfig = '',
    [TimeSpan]$Duration = ([TimeSpan]::FromHours(24)),
    [TimeSpan]$HealthInterval = ([TimeSpan]::FromSeconds(30)),
    [TimeSpan]$TrafficInterval = ([TimeSpan]::FromSeconds(5)),
    [string]$Namespace = '',
    [string]$MetricsNamespace = '',
    [string]$PodSelector = 'app=cozyplane-vpn-gateway',
    [string[]]$TrafficCommand = @(),
    [switch]$NoTraffic,
    [string]$SetupScript = '',
    [switch]$AllowSetup,
    [string]$CleanupScript = '',
    [switch]$Cleanup,
    [switch]$Preserve,
    [string]$OutputDirectory = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Duration -le [TimeSpan]::Zero -or $HealthInterval -le [TimeSpan]::Zero -or $TrafficInterval -le [TimeSpan]::Zero) {
    throw 'Duration, HealthInterval, and TrafficInterval must be positive.'
}
if (-not $NoTraffic -and $TrafficCommand.Count -eq 0) {
    throw 'Provide -TrafficCommand as an executable plus arguments, or explicitly opt out with -NoTraffic.'
}
if ($AllowSetup -and [string]::IsNullOrWhiteSpace($SetupScript)) {
    throw '-AllowSetup requires -SetupScript.'
}
if ($Cleanup -and [string]::IsNullOrWhiteSpace($CleanupScript)) {
    throw '-Cleanup requires -CleanupScript.'
}
if ($Cleanup -and $Preserve) {
    throw '-Cleanup and -Preserve are mutually exclusive.'
}
if (-not $AllowSetup -and -not [string]::IsNullOrWhiteSpace($SetupScript)) {
    throw 'Setup is disabled by default. Add -AllowSetup to run -SetupScript.'
}
if ($Kubeconfig -and -not (Test-Path -LiteralPath $Kubeconfig -PathType Leaf)) {
    throw "Kubeconfig does not exist: $Kubeconfig"
}

$kubectlBaseArguments = @('--context', $Kctx)
if ($Kubeconfig) { $kubectlBaseArguments = @('--kubeconfig', $Kubeconfig) + $kubectlBaseArguments }

function Invoke-Kubectl {
    param([string[]]$Arguments, [switch]$IgnoreFailure)

    $output = & kubectl @kubectlBaseArguments @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $IgnoreFailure) {
        throw "kubectl $($Arguments -join ' ') failed: $output"
    }
    [pscustomobject]@{ ExitCode = $exitCode; Output = ($output -join "`n") }
}

function Get-VpnMetrics {
    param([string]$TargetNamespace)

    $args = @('get', 'pods', '-l', $PodSelector, '-o', 'json')
    if ($TargetNamespace) { $args += @('-n', $TargetNamespace) } else { $args += '--all-namespaces' }
    $podQuery = Invoke-Kubectl -Arguments $args -IgnoreFailure
    if ($podQuery.ExitCode -ne 0) {
        return [pscustomobject]@{ Namespace = ''; Pod = ''; ExitCode = $podQuery.ExitCode; Metrics = $podQuery.Output; DownConnections = 0 }
    }
    $pods = $podQuery.Output | ConvertFrom-Json
    foreach ($pod in $pods.items) {
        if ($pod.status.phase -ne 'Running') { continue }
        $path = "/api/v1/namespaces/$($pod.metadata.namespace)/pods/$($pod.metadata.name):9410/proxy/metrics"
        $metrics = Invoke-Kubectl -Arguments @('get', '--raw', $path) -IgnoreFailure
        [pscustomobject]@{
            Namespace = $pod.metadata.namespace
            Pod = $pod.metadata.name
            ExitCode = $metrics.ExitCode
            Metrics = $metrics.Output
            DownConnections = [regex]::Matches($metrics.Output, '(?m)^cozyplane_vpn_connection_up(?:\{[^}]*\})?\s+0(?:\.0+)?(?:\s|$)').Count
        }
    }
}

function Get-HealthSummary {
    param($Nodes, $Pods, $Connections)

    $unreadyNodes = @()
    $unhealthyPods = @()
    $unhealthyConnections = @()
    if ($Nodes.ExitCode -eq 0) {
        $unreadyNodes = @(((($Nodes.Output | ConvertFrom-Json).items) | Where-Object {
            -not ($_.status.conditions | Where-Object { $_.type -eq 'Ready' -and $_.status -eq 'True' })
        }) | ForEach-Object { $_.metadata.name })
    }
    if ($Pods.ExitCode -eq 0) {
        $unhealthyPods = @(((($Pods.Output | ConvertFrom-Json).items) | Where-Object {
            $_.status.phase -notin @('Running', 'Succeeded')
        }) | ForEach-Object { "$($_.metadata.namespace)/$($_.metadata.name):$($_.status.phase)" })
    }
    if ($Connections.ExitCode -eq 0) {
        $unhealthyConnections = @(((($Connections.Output | ConvertFrom-Json).items) | Where-Object {
            $_.status.phase -ne 'Established'
        }) | ForEach-Object { "$($_.metadata.namespace)/$($_.metadata.name):$($_.status.phase)" })
    }
    [pscustomobject]@{
        UnreadyNodes = $unreadyNodes
        UnhealthyPods = $unhealthyPods
        UnhealthyConnections = $unhealthyConnections
    }
}

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) { throw 'kubectl is required.' }
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Get-Location) ("vpn-soak-" + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$runMetadata = [pscustomobject]@{
    Context = $Kctx; Kubeconfig = $Kubeconfig; StartedAtUtc = [DateTime]::UtcNow.ToString('o'); Duration = $Duration.ToString()
    HealthInterval = $HealthInterval.ToString(); TrafficInterval = $TrafficInterval.ToString()
    Namespace = $Namespace; MetricsNamespace = $MetricsNamespace; PodSelector = $PodSelector
    TrafficEnabled = -not $NoTraffic; CleanupRequested = [bool]$Cleanup; PreserveRequested = [bool]$Preserve
}
$runMetadata | ConvertTo-Json | Set-Content -NoNewline (Join-Path $OutputDirectory 'run.json')

if ($AllowSetup) {
    & $SetupScript
    if ($LASTEXITCODE -ne 0) { throw "Setup script failed with exit code $LASTEXITCODE." }
}

$healthPath = Join-Path $OutputDirectory 'health.jsonl'
$metricsPath = Join-Path $OutputDirectory 'metrics.jsonl'
$trafficPath = Join-Path $OutputDirectory 'traffic.jsonl'
$started = [DateTime]::UtcNow
$nextHealth = $started
$nextTraffic = $started
$failures = 0

try {
    while (([DateTime]::UtcNow - $started) -lt $Duration) {
        $now = [DateTime]::UtcNow
        if ($now -ge $nextHealth) {
            $nodes = Invoke-Kubectl -Arguments @('get', 'nodes', '-o', 'json') -IgnoreFailure
            $podsArgs = @('get', 'pods', '-o', 'json')
            if ($Namespace) { $podsArgs += @('-n', $Namespace) } else { $podsArgs += '--all-namespaces' }
            $pods = Invoke-Kubectl -Arguments $podsArgs -IgnoreFailure
            $connections = Invoke-Kubectl -Arguments @('get', 'vpnconnections.sdn.cozystack.io', '--all-namespaces', '-o', 'json') -IgnoreFailure
            $healthSummary = Get-HealthSummary -Nodes $nodes -Pods $pods -Connections $connections
            $health = [pscustomobject]@{ TimestampUtc = $now.ToString('o'); Nodes = $nodes; Pods = $pods; VPNConnections = $connections; Summary = $healthSummary }
            $health | ConvertTo-Json -Depth 6 -Compress | Add-Content $healthPath

            $metricNamespace = if ($MetricsNamespace) { $MetricsNamespace } else { $Namespace }
            foreach ($sample in @(Get-VpnMetrics -TargetNamespace $metricNamespace)) {
                [pscustomobject]@{ TimestampUtc = $now.ToString('o'); Sample = $sample } |
                    ConvertTo-Json -Depth 5 -Compress | Add-Content $metricsPath
                if ($sample.ExitCode -ne 0 -or $sample.DownConnections -gt 0) { $failures++ }
            }
            if ($nodes.ExitCode -ne 0 -or $pods.ExitCode -ne 0 -or $connections.ExitCode -ne 0 -or
                $healthSummary.UnreadyNodes.Count -gt 0 -or $healthSummary.UnhealthyPods.Count -gt 0 -or
                $healthSummary.UnhealthyConnections.Count -gt 0) { $failures++ }
            $nextHealth = $now + $HealthInterval
        }

        if (-not $NoTraffic -and $now -ge $nextTraffic) {
            $trafficArguments = if ($TrafficCommand.Count -gt 1) { $TrafficCommand[1..($TrafficCommand.Count - 1)] } else { @() }
            $trafficOutput = & $TrafficCommand[0] @trafficArguments 2>&1
            $traffic = [pscustomobject]@{ TimestampUtc = $now.ToString('o'); ExitCode = $LASTEXITCODE; Output = ($trafficOutput -join "`n") }
            $traffic | ConvertTo-Json -Depth 3 -Compress | Add-Content $trafficPath
            if ($traffic.ExitCode -ne 0) { $failures++ }
            $nextTraffic = $now + $TrafficInterval
        }
        Start-Sleep -Milliseconds 250
    }
} finally {
    if ($Cleanup) {
        & $CleanupScript
        if ($LASTEXITCODE -ne 0) { $failures++ }
    }
}

$summary = [pscustomobject]@{ StartedAtUtc = $started.ToString('o'); FinishedAtUtc = [DateTime]::UtcNow.ToString('o'); Failures = $failures; OutputDirectory = $OutputDirectory }
$summary | ConvertTo-Json | Set-Content -NoNewline (Join-Path $OutputDirectory 'summary.json')
$summary
if ($failures -gt 0) { exit 1 }
