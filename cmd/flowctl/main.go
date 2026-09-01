// Copyright 2026 The cozyplane Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// cozyplane-flowctl reads the per-node flow endpoints the agent serves
// (docs/observability.md) and renders them for an operator: a table or NDJSON,
// one node or the whole DaemonSet fanned out and merged by time.
//
// The raw flow endpoints are bound to each node's loopback (127.0.0.1:9412),
// unreachable from any pod's netns — so flowctl reaches them by exec-ing a
// wget inside the agent container, which runs in the node's netns. That path
// needs pods/exec in the agent namespace: operator RBAC, carried by no tenant
// role (the aggregate cozyplane_flows_total is separately on :9411/metrics).
//
//	flowctl observe [--follow] [--vpc ns/name] [--namespace ns]
//	                [--verdict allow|deny] [--reason X] [--since 5m]
//	                [--node N] [--agent-namespace ns] [--json]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

const flowLoopbackURL = "http://127.0.0.1:9412"

// execWget runs `wget -qO- <flowLoopbackURL><path>?<query>` inside the agent
// container and streams stdout to w. The URL is built here from validated
// values, never from anything a request body carries.
func execWget(ctx context.Context, cfg *rest.Config, client kubernetes.Interface,
	ns, pod, path string, q url.Values, w io.Writer) error {
	target := flowLoopbackURL + path
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	req := client.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(ns).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "agent",
			Command:   []string{"wget", "-q", "-O-", target},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return err
	}
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: w, Stderr: io.Discard})
}

// flowRecord mirrors the agent's JSON (cmd/agent/flows.go). Decoded loosely on
// purpose: an older flowctl must render a newer agent's records, not choke.
type flowRecord struct {
	Time      time.Time `json:"time"`
	Verdict   string    `json:"verdict"`
	Reason    string    `json:"reason"`
	Hook      string    `json:"hook"`
	Door      string    `json:"door,omitempty"`
	Proto     string    `json:"proto"`
	Src       flowPeer  `json:"src"`
	Dst       flowPeer  `json:"dst"`
	Direction string    `json:"direction"`
	SYN       bool      `json:"syn,omitempty"`
	Forwarded bool      `json:"forwarded,omitempty"`
	TCPFlags  []string  `json:"tcp_flags,omitempty"`
	ICMPType  *uint8    `json:"icmp_type,omitempty"`
	ICMPCode  *uint8    `json:"icmp_code,omitempty"`
	Node      string    `json:"node"`
}

type flowPeer struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port,omitempty"`
	VNI  uint32 `json:"vni,omitempty"`
	VPC  string `json:"vpc,omitempty"`
	Pod  string `json:"pod,omitempty"`
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "observe" {
		fmt.Fprintln(os.Stderr, "usage: flowctl observe [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	var (
		kubeconfig = fs.String("kubeconfig", "", "path to the kubeconfig (default: the usual loading rules)")
		kcontext   = fs.String("context", "", "kubeconfig context")
		agentNS    = fs.String("agent-namespace", "kube-system", "namespace of the cozyplane-agent DaemonSet")
		node       = fs.String("node", "", "read one node's agent only")
		follow     = fs.Bool("follow", false, "stream new flows (NDJSON from /flows/stream)")
		vpc        = fs.String("vpc", "", "filter: VPC as namespace/name (either side)")
		namespace  = fs.String("namespace", "", "filter: pod or VPC namespace (either side)")
		verdict    = fs.String("verdict", "", "filter: allow or deny")
		reason     = fs.String("reason", "", "filter: reason (isolation, sg_ingress, ...)")
		since      = fs.String("since", "", "filter: only flows younger than this duration")
		jsonOut    = fs.Bool("json", false, "NDJSON output instead of the table")
	)
	_ = fs.Parse(os.Args[2:])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if *kubeconfig != "" {
		rules.ExplicitPath = *kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: *kcontext}).ClientConfig()
	if err != nil {
		fatal("kubeconfig: %v", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fatal("client: %v", err)
	}

	pods, err := client.CoreV1().Pods(*agentNS).List(ctx, metav1.ListOptions{LabelSelector: "app=cozyplane-agent"})
	if err != nil {
		fatal("list agent pods in %q: %v", *agentNS, err)
	}
	var targets []string // pod names
	for _, p := range pods.Items {
		if *node != "" && p.Spec.NodeName != *node {
			continue
		}
		if p.Status.Phase == "Running" {
			targets = append(targets, p.Name)
		}
	}
	if len(targets) == 0 {
		fatal("no running cozyplane-agent pod matched (namespace %q, node %q)", *agentNS, *node)
	}

	q := url.Values{}
	for k, v := range map[string]string{
		"vpc": *vpc, "namespace": *namespace, "verdict": *verdict,
		"reason": *reason, "since": *since,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}

	if *follow {
		var wg sync.WaitGroup
		out := make(chan flowRecord, 256)
		for _, pod := range targets {
			wg.Add(1)
			go func(pod string) {
				defer wg.Done()
				pr, pw := io.Pipe()
				go func() {
					err := execWget(ctx, cfg, client, *agentNS, pod, "/flows/stream", q, pw)
					_ = pw.CloseWithError(err)
				}()
				sc := bufio.NewScanner(pr)
				sc.Buffer(make([]byte, 64*1024), 1024*1024)
				for sc.Scan() {
					var r flowRecord
					if json.Unmarshal(sc.Bytes(), &r) == nil {
						select {
						case out <- r:
						case <-ctx.Done():
							return
						}
					}
				}
			}(pod)
		}
		go func() { wg.Wait(); close(out) }()
		if !*jsonOut {
			printHeader()
		}
		for r := range out {
			print1(&r, *jsonOut)
		}
		return
	}

	// One-shot: fetch every node, merge, sort by time.
	var all []flowRecord
	for _, pod := range targets {
		var buf strings.Builder
		if err := execWget(ctx, cfg, client, *agentNS, pod, "/flows", q, &buf); err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", pod, err)
			continue
		}
		var recs []flowRecord
		if err := json.Unmarshal([]byte(buf.String()), &recs); err != nil {
			fmt.Fprintf(os.Stderr, "decode %s: %v\n", pod, err)
			continue
		}
		all = append(all, recs...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	if !*jsonOut {
		printHeader()
	}
	for i := range all {
		print1(&all[i], *jsonOut)
	}
}

func printHeader() {
	fmt.Printf("%-12s %-6s %-4s %-11s %-24s %-40s %-6s %-5s %s\n",
		"TIME", "VERD", "DIR", "REASON", "VPC", "SRC->DST", "PROTO", "PORT", "NODE")
}

func print1(r *flowRecord, jsonOut bool) {
	if jsonOut {
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
		return
	}
	vpc := r.Dst.VPC
	if vpc == "" {
		vpc = r.Src.VPC
	}
	src := r.Src.IP
	if r.Src.Pod != "" {
		src = r.Src.Pod
	}
	dst := r.Dst.IP
	if r.Dst.Pod != "" {
		dst = r.Dst.Pod
	}
	dir := "->"
	if r.Direction == "ingress" {
		dir = "in"
	} else if r.Direction == "egress" {
		dir = "out"
	}
	fmt.Printf("%-12s %-6s %-4s %-11s %-24s %-40s %-6s %-5d %s\n",
		r.Time.Format("15:04:05.000"), r.Verdict, dir, r.Reason, vpc,
		src+" -> "+dst, r.Proto, r.Dst.Port, r.Node)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
