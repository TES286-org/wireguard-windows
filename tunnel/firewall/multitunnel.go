/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"errors"
	"log"
	"sync"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// wireGuardAdapterDescription is the adapter Description string that
// WireGuardNT assigns to every adapter it creates (the TunnelType argument
// passed to WireGuardCreateAdapter). It is the stable invariant we use to
// enumerate all WireGuard adapters on the system from any process.
const wireGuardAdapterDescription = "WireGuard"

// multiTunnelState tracks the WFP objects and permit set of the currently
// active firewall session so that PermitWireGuardInterface can add filters to
// the same session after EnableFirewall has returned.
//
// All fields are guarded by multiTunnelMutex. The WFP session itself
// (wfpSession in blocker.go) is also guarded by this mutex to keep the
// session and the bookkeeping consistent.
var (
	multiTunnelMutex    sync.Mutex
	multiTunnelActive   bool
	multiTunnelRestrict bool
	multiTunnelBase     *baseObjects
	multiTunnelPermit   = make(map[uint64]struct{})
)

// wireGuardAdapterLUIDs returns the LUIDs of all currently-present WireGuard
// network adapters, identified by their adapter Description string
// ("WireGuard"). It is the entry point used by EnableFirewall to permit
// traffic on every coexisting WireGuard tunnel interface, and by callers that
// need to refresh the permit set when a new adapter appears.
func wireGuardAdapterLUIDs() ([]uint64, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil, err
	}
	var luids []uint64
	for _, a := range adapters {
		if a.Description() != wireGuardAdapterDescription {
			continue
		}
		luids = append(luids, uint64(a.LUID))
	}
	return luids, nil
}

// IsEnabled reports whether EnableFirewall has been called and DisableFirewall
// has not been called since. It is safe for concurrent use.
func IsEnabled() bool {
	multiTunnelMutex.Lock()
	defer multiTunnelMutex.Unlock()
	return multiTunnelActive
}

// PermitWireGuardInterface adds permit filters for the given LUID to the
// currently active firewall session. It is intended to be called when a new
// WireGuard adapter appears after EnableFirewall has been called, so that
// existing kill-switch tunnels allow traffic on the new adapter too.
//
// It is a no-op (returns nil) when:
//   - the firewall is not enabled, or
//   - the firewall was enabled in non-restrict mode (doNotRestrict == true),
//     because in that mode no blockAll filter is installed and all traffic is
//     already permitted, or
//   - the LUID has already been permitted.
//
// It is safe for concurrent use.
func PermitWireGuardInterface(luid uint64) error {
	multiTunnelMutex.Lock()
	session := wfpSession
	base := multiTunnelBase
	restrict := multiTunnelRestrict
	active := multiTunnelActive
	if _, exists := multiTunnelPermit[luid]; exists {
		multiTunnelMutex.Unlock()
		return nil
	}
	multiTunnelMutex.Unlock()

	if !active || session == 0 {
		return errors.New("The firewall is not enabled")
	}
	if !restrict {
		// Kill switch is off; blockAll is not installed, so all traffic is
		// already permitted. Nothing to do.
		return nil
	}

	err := runTransaction(session, func(session uintptr) error {
		return permitTunInterface(session, base, 12, luid)
	})
	if err != nil {
		return wrapErr(err)
	}

	multiTunnelMutex.Lock()
	multiTunnelPermit[luid] = struct{}{}
	multiTunnelMutex.Unlock()
	return nil
}

// ensureWireGuardLUIDs returns the union of the LUIDs reported by
// wireGuardAdapterLUIDs and the supplied fallback LUID. The fallback is
// always present in the result so that the current tunnel's own interface is
// never accidentally left unpermitted when enumeration fails or returns empty.
//
// Errors from enumeration are logged and swallowed: the kill switch is still
// useful with only the current tunnel permitted, and a transient enumeration
// failure should not prevent the tunnel from coming up.
func ensureWireGuardLUIDs(fallback uint64) []uint64 {
	luids, err := wireGuardAdapterLUIDs()
	if err != nil {
		log.Printf("Unable to enumerate WireGuard adapters for multi-tunnel firewall permit: %v", err)
		return []uint64{fallback}
	}
	found := false
	for _, l := range luids {
		if l == fallback {
			found = true
			break
		}
	}
	if !found {
		luids = append(luids, fallback)
	}
	return luids
}
