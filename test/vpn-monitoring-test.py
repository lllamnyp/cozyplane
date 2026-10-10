#!/usr/bin/env python3
"""Evaluate rendered VPN rules and dashboards and scrape HTTP fixtures in VictoriaMetrics.

Requires Docker, Python/PyYAML and wireguard-http.prom/ipsec-http.prom produced
by the Go HTTP-handler tests (VPN_MONITORING_ARTIFACT_DIR). No real cluster is
modified. Kernel/WireGuard/VICI boundaries and Kubernetes discovery metadata are
fixtures; exposition, HTTP scraping, query evaluation and alert rules are real.
"""
import argparse
import json
import re
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


def docker(*args):
    result = subprocess.run(['rtk', 'proxy', 'docker', *map(str, args)], capture_output=True, text=True, encoding='utf-8')
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    return result.stdout


def series(metric, labels, value):
    return {'series': metric + '{' + ','.join(k + '=' + json.dumps(v) for k, v in labels.items()) + '}', 'values': str(value) + '+0x20'}


def render(repo, report):
    output = docker('run', '--rm', '--mount', f'type=bind,source={repo},target=/src', '-w', '/src', 'alpine/helm:3.19.0', 'template', 'cozyplane', 'chart/cozyplane', '--namespace', 'kube-system',
                    '--api-versions', 'operator.victoriametrics.com/v1beta1/VMRule', '--api-versions', 'operator.victoriametrics.com/v1beta1/VMPodScrape', '--api-versions', 'grafana.integreatly.org/v1beta1/GrafanaDashboard',
                    '--set', 'vpn.observability.rules.noTraffic.enabled=true', '--set', 'vpn.observability.rules.additionalLabels.monitoring=local', '--set', 'vpn.observability.podScrape.additionalLabels.monitoring=local')
    resources = {item['kind']: item for item in yaml.safe_load_all(output) if item and item['kind'] in ('VMRule', 'VMPodScrape', 'GrafanaDashboard')}
    (report / 'rendered-monitoring.yaml').write_text(yaml.safe_dump_all(resources.values(), sort_keys=False), encoding='utf-8')
    rule = resources['VMRule']['spec']
    dashboard = json.loads(resources['GrafanaDashboard']['spec']['json'])
    (report / 'rules.yml').write_text(yaml.safe_dump(rule, sort_keys=False), encoding='utf-8')
    (report / 'dashboard.json').write_text(json.dumps(dashboard, indent=2) + '\n', encoding='utf-8')
    return resources, dashboard


def rule_tests(resources, report):
    rules = {rule['alert']: rule for group in resources['VMRule']['spec']['groups'] for rule in group['rules'] if 'alert' in rule}
    logical = {'cluster': 'test-cluster', 'namespace': 'tenant-a', 'gateway': 'gateway-a', 'connection': 'connection-a', 'backend': 'wireguard'}
    active = dict(logical, job='cozyplane-vpn-gateways', pod='gateway-a-vpn-active', instance='192.0.2.1:9410')
    standby = dict(logical, job='cozyplane-vpn-gateways', pod='gateway-a-vpn-standby', instance='192.0.2.2:9410')
    target = {k: v for k, v in active.items() if k not in ('connection', 'backend')}
    pod = {k: v for k, v in target.items() if k not in ('job', 'instance')}
    inventory = {'cluster': 'test-cluster', 'namespace': 'tenant-a', 'pod': active['pod'], 'container': 'vpn-gateway', 'job': 'kube-state-metrics'}
    inventory_result = {k: inventory[k] for k in ('cluster', 'namespace', 'pod')}
    tests = []

    def case(name, inputs, alert, labels=None, value=0, at='12m'):
        expected = []
        expected_alerts = []
        if labels is not None:
            expected = [{'labels': '{' + ','.join(k + '=' + json.dumps(v) for k, v in sorted(labels.items())) + '}', 'value': value}]
            alert_labels = dict(labels, **rules[alert].get('labels', {}))
            annotations = {key: re.sub(r'\{\{\s*\$labels\.(\w+)\s*\}\}', lambda m: alert_labels.get(m.group(1), ''), text) for key, text in rules[alert].get('annotations', {}).items()}
            expected_alerts = [{'exp_labels': alert_labels, 'exp_annotations': annotations}]
        tests.append({'name': name, 'interval': '1m', 'input_series': inputs,
                      'promql_expr_test': [{'expr': rules[alert]['expr'], 'eval_time': at, 'exp_samples': expected}],
                      'alert_rule_test': [{'eval_time': at, 'alertname': alert, 'exp_alerts': expected_alerts}]})

    case('HA: healthy active and down standby do not alert separately by instance', [series('cozyplane_vpn_connection_up', active, 1), series('cozyplane_vpn_connection_up', standby, 0)], 'CozyplaneVPNConnectionDown')
    case('HA: both replicas down produce one logical connection alert', [series('cozyplane_vpn_connection_up', active, 0), series('cozyplane_vpn_connection_up', standby, 0)], 'CozyplaneVPNConnectionDown', logical)
    case('Other namespace cannot mask a down connection', [series('cozyplane_vpn_connection_up', active, 0), series('cozyplane_vpn_connection_up', dict(active, namespace='tenant-b'), 1)], 'CozyplaneVPNConnectionDown', logical)
    case('Installed IPsec SA with old IKE establishment is not stale WireGuard', [series('cozyplane_vpn_connection_last_handshake_timestamp_seconds', dict(active, backend='ipsec'), 30)], 'CozyplaneVPNConnectionHandshakeStale')
    case('WireGuard stale handshake fires', [series('cozyplane_vpn_connection_last_handshake_timestamp_seconds', active, 30)], 'CozyplaneVPNConnectionHandshakeStale', logical, 30)
    case('Healthy HA handshake suppresses stale standby', [series('cozyplane_vpn_connection_last_handshake_timestamp_seconds', active, 600), series('cozyplane_vpn_connection_last_handshake_timestamp_seconds', standby, 30)], 'CozyplaneVPNConnectionHandshakeStale')
    case('Never handshaked remains visible', [series('cozyplane_vpn_connection_last_handshake_timestamp_seconds', active, 0)], 'CozyplaneVPNConnectionNeverHandshake', logical)
    case('Successful handshake suppresses never-handshake standby', [series('cozyplane_vpn_connection_last_handshake_timestamp_seconds', active, 600), series('cozyplane_vpn_connection_last_handshake_timestamp_seconds', standby, 0)], 'CozyplaneVPNConnectionNeverHandshake')
    case('Scrape error is detected when tunnel series disappear', [series('up', target, 0)], 'CozyplaneVPNScrapeFailed', pod)
    case('Known Kubernetes appliance with no target is detected', [series('kube_pod_container_info', inventory, 1)], 'CozyplaneVPNTargetMissing', inventory_result, 1)
    case('Failed target is present: no duplicate missing-target alert', [series('kube_pod_container_info', inventory, 1), series('up', target, 0)], 'CozyplaneVPNTargetMissing')
    case('Terminating appliance is excluded', [series('kube_pod_container_info', inventory, 1), series('kube_pod_deletion_timestamp', inventory_result, 600)], 'CozyplaneVPNTargetMissing')
    case('Empty successful scrape without inventory metric alerts', [series('up', target, 1)], 'CozyplaneVPNMetricsMissing', pod, 1)
    case('Zero configured peers is valid, not absent telemetry', [series('up', target, 1), series('cozyplane_vpn_gateway_connections', dict(target, backend='wireguard'), 0)], 'CozyplaneVPNMetricsMissing')
    case('Missing kube-state-metrics inventory is visible', [series('up', target, 1)], 'CozyplaneVPNInventoryUnavailable', pod, 1)
    case('Available inventory and restarts do not alert', [series('up', target, 1), series('kube_pod_container_info', inventory, 1), series('kube_pod_container_status_restarts_total', inventory, 0)], 'CozyplaneVPNInventoryUnavailable')
    case('Inventory without restart metrics is incomplete', [series('up', target, 1), series('kube_pod_container_info', inventory, 1)], 'CozyplaneVPNInventoryUnavailable', pod, 1)
    case('Missing CPU and memory metrics are visible', [series('up', target, 1)], 'CozyplaneVPNResourceMetricsUnavailable', pod, 1)
    case('Available CPU and memory metrics do not alert', [series('up', target, 1), series('container_cpu_usage_seconds_total', inventory, 1), series('container_memory_working_set_bytes', inventory, 1048576)], 'CozyplaneVPNResourceMetricsUnavailable')
    core_metrics = ['cozyplane_vpn_connection_' + field for field in ('rx_bytes_total', 'tx_bytes_total', 'up', 'last_handshake_timestamp_seconds')]
    complete = [series('cozyplane_vpn_gateway_connections', dict(target, backend='wireguard'), 1)] + [series(metric, active, 0) for metric in core_metrics]
    contract_labels = dict(pod, backend='wireguard')
    case('All configured WireGuard metric families are present', complete, 'CozyplaneVPNConnectionMetricsIncomplete')
    case('One missing byte counter cannot stay invisible', complete[:1] + complete[2:], 'CozyplaneVPNConnectionMetricsIncomplete', contract_labels, 4)
    duplicate = [series(metric, dict(active, scraper_replica='replica-b'), 0) for metric in core_metrics]
    case('Replica transport labels cannot double-count metric inventory', complete + duplicate, 'CozyplaneVPNConnectionMetricsIncomplete')
    case('All connection metrics missing is not an empty healthy gateway', complete[:1], 'CozyplaneVPNConnectionMetricsIncomplete', contract_labels, 4)
    case('Empty configured gateway has no missing connections', [series('cozyplane_vpn_gateway_connections', dict(target, backend='wireguard'), 0)], 'CozyplaneVPNConnectionMetricsIncomplete')
    ipsec_complete = [series('cozyplane_vpn_gateway_connections', dict(target, backend='ipsec'), 1)] + [series(metric, dict(active, backend='ipsec'), 0) for metric in core_metrics + ['cozyplane_vpn_connection_rx_packets_total', 'cozyplane_vpn_connection_tx_packets_total']]
    case('IPsec requires its packet counters too', ipsec_complete[:-1], 'CozyplaneVPNConnectionMetricsIncomplete', dict(pod, backend='ipsec'), 6)
    case('Complete IPsec monitoring does not alert', ipsec_complete, 'CozyplaneVPNConnectionMetricsIncomplete')
    case('Unreadable kernel counters do not masquerade as zero errors', [series('cozyplane_vpn_ipsec_xfrm_collection_success', target, 0)], 'CozyplaneVPNIPsecXfrmTelemetryUnavailable', pod)
    case('Absent XFRM collection health is detected', [series('cozyplane_vpn_gateway_connections', dict(target, backend='ipsec'), 2)], 'CozyplaneVPNIPsecXfrmTelemetryUnavailable', pod, 2)
    case('Healthy flag without mandatory replay counter is incomplete', [series('cozyplane_vpn_ipsec_xfrm_collection_success', target, 1)], 'CozyplaneVPNIPsecXfrmTelemetryUnavailable', pod, 1)
    case('Complete kernel telemetry does not alert', [series('cozyplane_vpn_ipsec_xfrm_collection_success', target, 1), series('cozyplane_vpn_ipsec_xfrm_errors_total', dict(target, reason='XfrmInStateSeqError'), 0)], 'CozyplaneVPNIPsecXfrmTelemetryUnavailable')
    errors = series('cozyplane_vpn_ipsec_xfrm_errors_total', dict(target, reason='XfrmInStateSeqError'), 0)
    errors['values'] = '0+10x20'
    case('Sustained replay errors are actionable', [errors], 'CozyplaneVPNIPsecXfrmErrors', {k: v for k, v in dict(pod, reason='XfrmInStateSeqError').items() if k != 'pod'}, 1/6)
    inputs = [series(metric, active, 0) for metric in ('cozyplane_vpn_connection_rx_bytes_total', 'cozyplane_vpn_connection_tx_bytes_total')]
    case('Opt-in idle traffic alert evaluates its full window', inputs, 'CozyplaneVPNConnectionNoTraffic', logical, at='35m')
    # The traffic window is 30m, so this fixture needs more than 20 minutes.
    for item in tests[-1]['input_series']: item['values'] = '0+0x40'
    (report / 'rules-test.yml').write_text(yaml.safe_dump({'rule_files': ['rules.yml'], 'evaluation_interval': '1m', 'tests': tests}, sort_keys=False), encoding='utf-8')
    mount = f'type=bind,source={report},target=/fixtures'
    checked = docker('run', '--rm', '--entrypoint', '/bin/promtool', '--mount', mount, '-w', '/fixtures', 'prom/prometheus:v3.2.1', 'check', 'rules', 'rules.yml')
    checked += docker('run', '--rm', '--entrypoint', '/bin/promtool', '--mount', mount, '-w', '/fixtures', 'prom/prometheus:v3.2.1', 'test', 'rules', 'rules-test.yml')
    (report / 'promtool.txt').write_text(checked, encoding='utf-8')
    return len(tests)


def scrape_tests(resources, dashboard, report):
    names = ['cozyplane-vpn-monitor-test-fixture', 'cozyplane-vpn-monitor-test-victoria']
    network = 'cozyplane-vpn-monitor-test'
    created = []
    owned_network = False
    try:
        docker('network', 'create', '--label', 'cozyplane.test=vpn-monitor', network)
        owned_network = True
        mount = f'type=bind,source={report},target=/fixtures'
        # Model the standby using zero-valued configured-peer output; no synthetic
        # success is substituted for a real collector or tunnel.
        active = (report / 'wireguard-http.prom').read_text()
        standby = re.sub(r'^(cozyplane_vpn_connection_\w+\{[^\n]+\}) \d+$', r'\1 0', active, flags=re.M)
        (report / 'wireguard-standby.prom').write_text(standby)
        relabels = resources['VMPodScrape']['spec']['podMetricsEndpoints'][0]['relabelConfigs']
        relabels = [{ {'sourceLabels': 'source_labels', 'targetLabel': 'target_label'}.get(k, k): v for k, v in row.items()} for row in relabels]
        jobs = []
        for suffix, path, gateway in [('active', 'wireguard-http.prom', 'gateway-a'), ('standby', 'wireguard-standby.prom', 'gateway-a'), ('ipsec', 'ipsec-http.prom', 'gateway-b')]:
            jobs.append({'job_name': suffix, 'metrics_path': '/' + path, 'scrape_interval': '2s', 'scrape_timeout': '1s', 'static_configs': [{'targets': [names[0] + ':9000'], 'labels': {'__meta_kubernetes_namespace': 'tenant-a', '__meta_kubernetes_pod_name': gateway + '-vpn-' + suffix, '__meta_kubernetes_pod_label_sdn_cozystack_io_vpn_gateway': gateway}}], 'relabel_configs': relabels})
        # Explicit dependency fixtures: not a claim that real exporters are deployed.
        dependency = []
        for gateway, suffix in [('gateway-a', 'active'), ('gateway-a', 'standby'), ('gateway-b', 'ipsec')]:
            labels = '{cluster="test-cluster",namespace="tenant-a",pod="' + gateway + '-vpn-' + suffix + '",container="vpn-gateway"}'
            dependency += ['kube_pod_container_info' + labels + ' 1', 'kube_pod_container_status_restarts_total' + labels + ' 0', 'container_cpu_usage_seconds_total' + labels + ' 1', 'container_memory_working_set_bytes' + labels + ' 1048576']
        (report / 'dependencies.prom').write_text('\n'.join(dependency) + '\n')
        jobs.append({'job_name': 'dependency-fixtures', 'scrape_interval': '2s', 'static_configs': [{'targets': [names[0] + ':9000']}], 'metrics_path': '/dependencies.prom'})
        (report / 'victoria-scrape.yml').write_text(yaml.safe_dump({'global': {'external_labels': {'cluster': 'test-cluster'}}, 'scrape_configs': jobs}, sort_keys=False))
        docker('run', '-d', '--name', names[0], '--label', 'cozyplane.test=vpn-monitor', '--network', network, '--mount', mount, '-w', '/fixtures', 'python:3.13.9-alpine3.22', 'python', '-m', 'http.server', '9000')
        created.append(names[0])
        docker('run', '-d', '--name', names[1], '--label', 'cozyplane.test=vpn-monitor', '--network', network, '--mount', mount, '-p', '127.0.0.1::8428', 'victoriametrics/victoria-metrics:v1.109.0', '-storageDataPath=/tmp/data', '-promscrape.config=/fixtures/victoria-scrape.yml', '-search.latencyOffset=0s')
        created.append(names[1])
        port = docker('port', names[1], '8428/tcp').strip().rsplit(':', 1)[1]
        base = 'http://127.0.0.1:' + port

        def query(expr):
            url = base + '/api/v1/query?' + urllib.parse.urlencode({'query': expr, 'nocache': 1})
            with urllib.request.urlopen(url, timeout=10) as response: data = json.load(response)
            assert data['status'] == 'success', data
            return data['data']['result']

        deadline = time.monotonic() + 55
        while time.monotonic() < deadline:
            try:
                result = query('up{job="cozyplane-vpn-gateways"}')
                if len(result) == 3 and all(row['value'][1] == '1' for row in result): break
            except (OSError, AssertionError): pass
            time.sleep(1)
        else: raise AssertionError('VictoriaMetrics did not discover all three fixture endpoints')
        # Rates and increases require multiple real scrape samples.
        time.sleep(5)
        common = ('cozyplane_vpn_gateway_connections', 'cozyplane_vpn_connection_rx_bytes_total', 'cozyplane_vpn_connection_tx_bytes_total', 'cozyplane_vpn_connection_up', 'cozyplane_vpn_connection_last_handshake_timestamp_seconds')
        inventory = {}
        for backend, count in [('wireguard', 2), ('ipsec', 1)]:
            metrics = common + (('cozyplane_vpn_connection_rx_packets_total', 'cozyplane_vpn_connection_tx_packets_total') if backend == 'ipsec' else ())
            for metric in metrics:
                rows = query(metric + '{backend="' + backend + '"}')
                expected = count if metric == 'cozyplane_vpn_gateway_connections' else count * 2
                assert len(rows) == expected, (metric, backend, rows)
                assert all(all(row['metric'].get(label) for label in ('namespace', 'gateway', 'pod', 'backend', 'cluster')) for row in rows), rows
                inventory[metric + '/' + backend] = len(rows)
        assert query('cozyplane_vpn_ipsec_xfrm_errors_total{reason="XfrmInStateSeqError"}')[0]['value'][1] == '37'
        queries = []
        for panel in dashboard['panels']:
            for target in panel['targets']:
                expr = target['expr'].replace('$__rate_interval', '1m').replace('$namespace', 'tenant-a').replace('$gateway', '.*').replace('$connection', '.*')
                rows = query(expr)
                if panel['id'] != 12: assert rows, (panel['title'], expr)
                queries.append({'panel': panel['title'], 'series': len(rows)})
        for group in resources['VMRule']['spec']['groups']:
            for rule in group['rules']:
                rows = query(rule['expr'])
                if rule['alert'] in ('CozyplaneVPNInventoryUnavailable', 'CozyplaneVPNResourceMetricsUnavailable', 'CozyplaneVPNConnectionMetricsIncomplete'): assert not rows, (rule['alert'], rows)
        healthy = query('max by (cluster,namespace,gateway,connection,backend) (cozyplane_vpn_connection_up{gateway="gateway-a",connection="connection-a"})')
        assert len(healthy) == 1 and healthy[0]['value'][1] == '1', healthy
        # Actual HTTP disappearance must produce up=0 rather than an all-green
        # dashboard with silently absent tunnel series.
        (report / 'wireguard-http.prom').rename(report / 'wireguard-http.saved')
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                failed = query('up{job="cozyplane-vpn-gateways",pod="gateway-a-vpn-active"}')
                if failed and failed[0]['value'][1] == '0': break
                time.sleep(1)
            else: raise AssertionError('Failed HTTP scrape was invisible')
            assert query('min by (cluster,namespace,gateway,pod) (up{job="cozyplane-vpn-gateways"}) == 0')
        finally: (report / 'wireguard-http.saved').rename(report / 'wireguard-http.prom')
        result = {'metricInventory': inventory, 'dashboardQueries': queries, 'httpScrapeFailureDetected': True, 'haAggregationVerified': True, 'victoriaVersion': 'v1.109.0', 'scope': 'HTTP-handler outputs plus synthetic VICI/WireGuard and Kubernetes/exporter boundaries; real VictoriaMetrics scraping and query evaluation. No operator/production deployment assertion.'}
        (report / 'victoria-results.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        for name in reversed(created):
            objects = json.loads(docker('inspect', name))
            assert objects[0]['Config']['Labels'].get('cozyplane.test') == 'vpn-monitor'
            docker('rm', '-f', name)
        if owned_network: docker('network', 'rm', network)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    report = args.report.resolve()
    report.mkdir(parents=True, exist_ok=True)
    resources, dashboard = render(repo, report)
    scenarios = rule_tests(resources, report)
    result = scrape_tests(resources, dashboard, report)
    print(json.dumps({'passed': True, 'ruleScenarios': scenarios, 'dashboardQueries': len(result['dashboardQueries']), 'report': str(report)}))


if __name__ == '__main__': main()
