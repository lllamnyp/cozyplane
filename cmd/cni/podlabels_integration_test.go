package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestCNIRejectsLargePodLabelsBeforeAllocation(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires isolated Linux container for the fixed CNI kubeconfig path")
	}
	var response atomic.Pointer[corev1.Pod]
	var gets, mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/tenant/pods/workload" {
			mutations.Add(1)
			http.Error(w, "unexpected request after Pod lookup", http.StatusInternalServerError)
			return
		}
		gets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response.Load()); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	config := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{"test": {Server: server.URL}},
		Contexts: map[string]*clientcmdapi.Context{"test": {Cluster: "test"}}, CurrentContext: "test",
	}
	encoded, err := clientcmd.Write(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(datapath.PluginKubeconfig), 0700); err != nil {
		t.Fatal(err)
	}
	// Never overwrite an existing kubeconfig, even in a misconfigured test run.
	f, err := os.OpenFile(datapath.PluginKubeconfig, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(datapath.PluginKubeconfig) })
	_, writeErr := f.Write(encoded)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	for _, delegate := range []bool{false, true} {
		for _, count := range []int{15000, 2048} {
			pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{
				Name: "workload", Namespace: "tenant", UID: "pod-owner", Labels: map[string]string{},
				Annotations: map[string]string{sdnv1.AnnotationVPC: "vpc"},
			}}
			for i := range count {
				pod.Labels[fmt.Sprintf("label%05d", i)] = strings.Repeat("x", 63)
			}
			response.Store(pod)
			conf := map[string]any{"cniVersion": "1.0.0", "name": "cozyplane", "type": "cozyplane"}
			if delegate {
				conf["vpc"] = "vpc"
			}
			stdin, err := json.Marshal(conf)
			if err != nil {
				t.Fatal(err)
			}
			args := &skel.CmdArgs{ContainerID: "test-sandbox", IfName: "eth0", Args: "K8S_POD_NAMESPACE=tenant;K8S_POD_NAME=workload;K8S_POD_UID=pod-owner", StdinData: stdin}
			err = addSandbox(t.Context(), args)
			if err == nil || !strings.Contains(err.Error(), "pod-label snapshot") || len(err.Error()) > 100 {
				t.Fatal("ADD must refuse snapshot before claims or endpoint setup", delegate, count, err)
			}
		}
	}
	if gets.Load() != 4 || mutations.Load() != 0 {
		t.Fatal("oversized ADD performed work beyond one Pod lookup", gets.Load(), mutations.Load())
	}
}
