/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package firewall

import (
	"errors"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental WireGuard specific WFP objects.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

// wfpSession is the handle of the currently active WFP session, or 0 when the
// firewall is disabled. It is guarded by multiTunnelMutex (defined in
// multitunnel.go) so that EnableFirewall, DisableFirewall and
// PermitWireGuardInterface remain consistent with each other.
var wfpSession uintptr

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("WireGuard", "WireGuard dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	bo.provider, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}
	bo.filters, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}

	//
	// Register provider.
	//
	{
		displayData, err := createWtFwpmDisplayData0("WireGuard", "WireGuard provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			// TODO: cleanup entire call chain of these if failure?
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("WireGuard filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

// EnableFirewall enables the WireGuard firewall for the current tunnel
// process.
//
// When doNotRestrict is false (the kill-switch case), the firewall blocks all
// outbound and inbound traffic except for a small allow-list: the WireGuard
// service itself, loopback, DHCP, NDP, DNS to the supplied restrictToDNSServers
// (if any), and every currently-present WireGuard tunnel interface.
//
// Permitting every WireGuard tunnel interface (not just the current tunnel's
// own LUID) is what allows multiple kill-switch tunnels to run concurrently
// without each one's blockAll filter starving the others. When a new WireGuard
// adapter appears after EnableFirewall has returned, existing tunnels extend
// their allow-list via PermitWireGuardInterface.
//
// luid is the LUID of the current tunnel's own adapter; it is always included
// in the permit set as a fallback, even if adapter enumeration fails.
func EnableFirewall(luid uint64, doNotRestrict bool, restrictToDNSServers []netip.Addr) error {
	multiTunnelMutex.Lock()
	if wfpSession != 0 {
		multiTunnelMutex.Unlock()
		return errors.New("The firewall has already been enabled")
	}
	multiTunnelMutex.Unlock()

	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}

	// Snapshot the LUIDs to permit before opening the transaction so that the
	// multiTunnelMutex is not held across the WFP transaction (which could
	// block for a long time and would also conflict with
	// PermitWireGuardInterface's own transaction attempts).
	tunnelLUIDs := ensureWireGuardLUIDs(luid)

	var installedBase *baseObjects

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}

		err = permitWireGuardService(session, baseObjects, 15)
		if err != nil {
			return wrapErr(err)
		}

		if !doNotRestrict {
			if len(restrictToDNSServers) > 0 {
				err = blockDNS(restrictToDNSServers, session, baseObjects, 15, 14)
				if err != nil {
					return wrapErr(err)
				}
			}

			err = permitLoopback(session, baseObjects, 13)
			if err != nil {
				return wrapErr(err)
			}

			// Permit traffic on every currently-present WireGuard tunnel
			// interface so that overlapping kill-switch tunnels can coexist.
			for _, tunLUID := range tunnelLUIDs {
				err = permitTunInterface(session, baseObjects, 12, tunLUID)
				if err != nil {
					return wrapErr(err)
				}
			}

			err = permitDHCPIPv4(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitDHCPIPv6(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitNdp(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			/* TODO: actually evaluate if this does anything and if we need this. It's layer 2; our other rules are layer 3.
			 *  In other words, if somebody complains, try enabling it. For now, keep it off.
			err = permitHyperV(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}
			*/

			err = blockAll(session, baseObjects, 0)
			if err != nil {
				return wrapErr(err)
			}
		}

		installedBase = baseObjects
		return nil
	}

	err = runTransaction(session, objectInstaller)
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}

	multiTunnelMutex.Lock()
	wfpSession = session
	multiTunnelActive = true
	multiTunnelRestrict = !doNotRestrict
	multiTunnelBase = installedBase
	multiTunnelPermit = make(map[uint64]struct{}, len(tunnelLUIDs))
	for _, l := range tunnelLUIDs {
		multiTunnelPermit[l] = struct{}{}
	}
	multiTunnelMutex.Unlock()
	return nil
}

// DisableFirewall tears down the WFP session owned by the current tunnel
// process. Because the session was opened with cFWPM_SESSION_FLAG_DYNAMIC,
// closing it also removes every filter and the sublayer that this process
// added, leaving other tunnels' sessions untouched.
func DisableFirewall() {
	multiTunnelMutex.Lock()
	session := wfpSession
	wfpSession = 0
	resetMultiTunnelStateLocked()
	multiTunnelMutex.Unlock()

	if session != 0 {
		fwpmEngineClose0(session)
	}
}

// resetMultiTunnelStateLocked clears all bookkeeping. Caller must hold
// multiTunnelMutex.
func resetMultiTunnelStateLocked() {
	multiTunnelActive = false
	multiTunnelRestrict = false
	multiTunnelBase = nil
	multiTunnelPermit = make(map[uint64]struct{})
}
