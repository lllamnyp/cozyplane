/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"errors"

	"github.com/vishvananda/netlink"
)

// dumpAttempts bounds how often a netlink dump is run when the kernel
// interrupts it (NLM_F_DUMP_INTR: the table changed mid-dump, so the result may
// be incomplete). Pod churn changes the link and address tables often enough
// for a single dump to be interrupted.
const dumpAttempts = 5

// retryDump runs a netlink dump until it completes uninterrupted, at most
// dumpAttempts times. After the last attempt it returns the possibly incomplete
// result with netlink.ErrDumpInterrupted.
func retryDump[T any](dump func() (T, error)) (T, error) {
	var v T
	var err error
	for range dumpAttempts {
		if v, err = dump(); !errors.Is(err, netlink.ErrDumpInterrupted) {
			return v, err
		}
	}
	return v, err
}

func linkList() ([]netlink.Link, error) { return retryDump(netlink.LinkList) }

func addrList(l netlink.Link, family int) ([]netlink.Addr, error) {
	return retryDump(func() ([]netlink.Addr, error) { return netlink.AddrList(l, family) })
}

func routeList(l netlink.Link, family int) ([]netlink.Route, error) {
	return retryDump(func() ([]netlink.Route, error) { return netlink.RouteList(l, family) })
}
