/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"slices"
	"testing"
)

// TestEnsureWireGuardLUIDsIncludesFallback verifies that ensureWireGuardLUIDs
// always includes the supplied fallback LUID, even when adapter enumeration
// returns nothing (e.g. on a system with no WireGuard adapters) or returns a
// list that does not contain the fallback. This is the invariant that lets
// EnableFirewall guarantee the current tunnel's own interface is permitted.
func TestEnsureWireGuardLUIDsIncludesFallback(t *testing.T) {
	const fallback uint64 = 0xDEADBEEFCAFEBABE

	luids := ensureWireGuardLUIDs(fallback)
	if !slices.Contains(luids, fallback) {
		t.Errorf("ensureWireGuardLUIDs(%#x) = %v, want it to contain the fallback LUID", fallback, luids)
	}

	// The result must be non-empty regardless of what is on the system.
	if len(luids) == 0 {
		t.Errorf("ensureWireGuardLUIDs returned an empty slice; fallback must always be present")
	}
}

// TestPermitWireGuardInterfaceNoopWhenNotEnabled verifies that
// PermitWireGuardInterface refuses to add filters when no WFP session is
// active. The multi-tunnel watcher calls this whenever a new interface
// appears; if the firewall is not enabled (e.g. in non-restrict mode, or
// before EnableFirewall has run), it must be a safe no-op-ish call rather
// than crash.
func TestPermitWireGuardInterfaceNoopWhenNotEnabled(t *testing.T) {
	multiTunnelMutex.Lock()
	active := multiTunnelActive
	session := wfpSession
	multiTunnelMutex.Unlock()
	if active || session != 0 {
		t.Skip("firewall is already enabled; cannot test the not-enabled path on this system")
	}

	const luid uint64 = 0x1234
	if err := PermitWireGuardInterface(luid); err == nil {
		t.Errorf("PermitWireGuardInterface on a disabled firewall should return an error, got nil")
	}
}

// TestPermitWireGuardInterfaceNoopForAlreadyPermittedLUID verifies that
// calling PermitWireGuardInterface for a LUID that is already in the permit
// set is a no-op that does not attempt any WFP transaction. We simulate the
// "already permitted" state by pre-populating multiTunnelPermit.
func TestPermitWireGuardInterfaceNoopForAlreadyPermittedLUID(t *testing.T) {
	const luid uint64 = 0xABCD

	multiTunnelMutex.Lock()
	prevPermit := multiTunnelPermit
	prevActive := multiTunnelActive
	prevRestrict := multiTunnelRestrict
	prevBase := multiTunnelBase
	prevSession := wfpSession
	multiTunnelPermit = map[uint64]struct{}{luid: {}}
	multiTunnelActive = true
	multiTunnelRestrict = true
	multiTunnelBase = nil
	wfpSession = 0 // Force the "no real session" path; the early-out must trigger before any WFP call.
	t.Cleanup(func() {
		multiTunnelPermit = prevPermit
		multiTunnelActive = prevActive
		multiTunnelRestrict = prevRestrict
		multiTunnelBase = prevBase
		wfpSession = prevSession
	})
	multiTunnelMutex.Unlock()

	if err := PermitWireGuardInterface(luid); err != nil {
		t.Errorf("PermitWireGuardInterface for already-permitted LUID should be a no-op, got %v", err)
	}
}

// TestPermitWireGuardInterfaceNoopInNonRestrictMode verifies that when the
// firewall was enabled in non-restrict mode (doNotRestrict == true, so no
// blockAll filter is installed), PermitWireGuardInterface does nothing because
// all traffic is already permitted.
func TestPermitWireGuardInterfaceNoopInNonRestrictMode(t *testing.T) {
	const luid uint64 = 0xBEEF

	multiTunnelMutex.Lock()
	prevPermit := multiTunnelPermit
	prevActive := multiTunnelActive
	prevRestrict := multiTunnelRestrict
	prevBase := multiTunnelBase
	prevSession := wfpSession
	multiTunnelPermit = map[uint64]struct{}{}
	multiTunnelActive = true
	multiTunnelRestrict = false // non-restrict mode
	multiTunnelBase = nil
	wfpSession = 0 // Force the early-out path; non-restrict must short-circuit before any WFP call.
	t.Cleanup(func() {
		multiTunnelPermit = prevPermit
		multiTunnelActive = prevActive
		multiTunnelRestrict = prevRestrict
		multiTunnelBase = prevBase
		wfpSession = prevSession
	})
	multiTunnelMutex.Unlock()

	if err := PermitWireGuardInterface(luid); err != nil {
		t.Errorf("PermitWireGuardInterface in non-restrict mode should be a no-op, got %v", err)
	}

	multiTunnelMutex.Lock()
	_, added := multiTunnelPermit[luid]
	multiTunnelMutex.Unlock()
	if added {
		t.Errorf("PermitWireGuardInterface in non-restrict mode must not record the LUID in the permit set")
	}
}

// TestIsEnabledReflectsState verifies that IsEnabled tracks the
// multiTunnelActive flag set by EnableFirewall and cleared by DisableFirewall.
func TestIsEnabledReflectsState(t *testing.T) {
	multiTunnelMutex.Lock()
	prev := multiTunnelActive
	multiTunnelActive = false
	multiTunnelMutex.Unlock()
	t.Cleanup(func() {
		multiTunnelMutex.Lock()
		multiTunnelActive = prev
		multiTunnelMutex.Unlock()
	})

	if IsEnabled() {
		t.Errorf("IsEnabled() = true, want false (multiTunnelActive is false)")
	}

	multiTunnelMutex.Lock()
	multiTunnelActive = true
	multiTunnelMutex.Unlock()

	if !IsEnabled() {
		t.Errorf("IsEnabled() = false, want true (multiTunnelActive is true)")
	}
}
