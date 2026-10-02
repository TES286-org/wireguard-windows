/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"log"

	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// wireGuardAdapterDescription is the adapter Description string that
// WireGuardNT assigns to every adapter it creates (the TunnelType argument
// passed to WireGuardCreateAdapter). It mirrors the constant of the same name
// in the firewall package and is the stable invariant we use to recognize
// WireGuard adapters from the tunnel side.
const wireGuardAdapterDescription = "WireGuard"

// permitWireGuardInterfaceIfApplicable checks whether the supplied LUID
// corresponds to a WireGuard adapter (Description == "WireGuard") and, if so,
// asks the firewall to permit traffic on it. It is used to extend an
// already-running tunnel's kill-switch allow-list when a new WireGuard tunnel
// comes up, so that this tunnel's blockAll filter does not starve the new
// tunnel's traffic.
//
// Errors are logged and swallowed: a failure to permit a new interface must
// not tear down the current tunnel, and the new tunnel's own firewall session
// will independently permit every existing WireGuard LUID when it calls
// EnableFirewall.
func permitWireGuardInterfaceIfApplicable(luid winipcfg.LUID) {
	row, err := luid.Interface()
	if err != nil {
		log.Printf("Unable to query interface %d for multi-tunnel firewall permit: %v", uint64(luid), err)
		return
	}
	if row.Description() != wireGuardAdapterDescription {
		return
	}
	if err := firewall.PermitWireGuardInterface(uint64(luid)); err != nil {
		log.Printf("Unable to permit new WireGuard interface %d in firewall: %v", uint64(luid), err)
	}
}
