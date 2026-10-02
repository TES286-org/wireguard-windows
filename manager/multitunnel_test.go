/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"testing"

	"golang.zx2c4.com/wireguard/windows/conf"
)

// TestStartDoesNotStopIntersectingTunnels is the regression test for the
// multi-tunnel behavior. Before commit <TBD> ("manager: allow multiple
// tunnels to run concurrently"), ManagerService.Start would identify every
// tracked tunnel whose routes or addresses intersect with the tunnel being
// started and asynchronously stop them. That behavior prevented more than one
// kill-switch tunnel from running at a time.
//
// This test verifies that Start:
//   - calls InstallTunnel with the requested tunnel's config path, and
//   - does NOT call UninstallTunnel on any already-tracked tunnel,
//     even when its routes would intersect.
//
// It runs only on Windows: it needs the real conf store (DPAPI) to materialize
// a config that conf.LoadFromName can read.
func TestStartDoesNotStopIntersectingTunnels(t *testing.T) {
	const existingTunnel = "wg-test-existing"
	const newTunnel = "wg-test-new"

	// Build two configs that would have intersected under the old logic:
	// both peers carry the default IPv4 route.
	mkConfig := func(name string) *conf.Config {
		c, err := conf.FromWgQuick(
			"[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.1/24\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\n",
			name,
		)
		if err != nil {
			t.Fatalf("build config %q: %v", name, err)
		}
		return c
	}

	existingCfg := mkConfig(existingTunnel)
	newCfg := mkConfig(newTunnel)

	// Sanity-check that the two configs DO intersect, so the test is
	// actually exercising the scenario it claims to.
	if !existingCfg.IntersectsWith(newCfg) {
		t.Fatalf("test setup invariant: %q and %q should intersect", existingTunnel, newTunnel)
	}

	// Persist the new tunnel so Start can load it by name.
	if err := newCfg.Save(true); err != nil {
		t.Fatalf("save new config: %v", err)
	}
	t.Cleanup(func() { _ = conf.DeleteName(newTunnel) })

	// Pretend the existing tunnel is already running.
	trackedTunnelsLock.Lock()
	trackedTunnels[existingTunnel] = TunnelStarted
	t.Cleanup(func() {
		trackedTunnelsLock.Lock()
		delete(trackedTunnels, existingTunnel)
		trackedTunnelsLock.Unlock()
	})
	trackedTunnelsLock.Unlock()

	// Swap InstallTunnel and UninstallTunnel for fakes that record calls.
	var installCalls []string
	uninstallCalls := make(map[string]int)
	origInstall := InstallTunnel
	origUninstall := UninstallTunnel
	InstallTunnel = func(configPath string) error {
		installCalls = append(installCalls, configPath)
		return nil
	}
	UninstallTunnel = func(name string) error {
		uninstallCalls[name]++
		return nil
	}
	t.Cleanup(func() {
		InstallTunnel = origInstall
		UninstallTunnel = origUninstall
	})

	s := &ManagerService{}
	if err := s.Start(newTunnel); err != nil {
		t.Fatalf("Start(%q): %v", newTunnel, err)
	}

	if len(installCalls) != 1 {
		t.Errorf("InstallTunnel called %d times, want exactly 1", len(installCalls))
	} else {
		wantPath, err := newCfg.Path()
		if err != nil {
			t.Fatalf("get config path: %v", err)
		}
		if installCalls[0] != wantPath {
			t.Errorf("InstallTunnel called with %q, want %q", installCalls[0], wantPath)
		}
	}

	if len(uninstallCalls) != 0 {
		t.Errorf("UninstallTunnel was called %v times during Start; multi-tunnel mode must not stop existing tunnels", uninstallCalls)
	}

	// The existing tunnel must still be tracked and untouched.
	trackedTunnelsLock.Lock()
	got := trackedTunnels[existingTunnel]
	trackedTunnelsLock.Unlock()
	if got != TunnelStarted {
		t.Errorf("trackedTunnels[%q] = %v, want TunnelStarted (Start must not mutate tracked tunnels)", existingTunnel, got)
	}
}

// TestStartPropagatesConfigLoadError verifies that Start surfaces config-load
// failures rather than silently installing a non-existent tunnel.
func TestStartPropagatesConfigLoadError(t *testing.T) {
	origInstall := InstallTunnel
	origUninstall := UninstallTunnel
	installCalled := false
	uninstallCalled := false
	InstallTunnel = func(string) error { installCalled = true; return nil }
	UninstallTunnel = func(string) error { uninstallCalled = true; return nil }
	t.Cleanup(func() {
		InstallTunnel = origInstall
		UninstallTunnel = origUninstall
	})

	s := &ManagerService{}
	err := s.Start("wg-test-nonexistent-12345")
	if err == nil {
		t.Fatal("Start with non-existent tunnel should return an error")
	}
	if installCalled {
		t.Error("InstallTunnel must not be called when config loading fails")
	}
	if uninstallCalled {
		t.Error("UninstallTunnel must not be called when config loading fails")
	}
}
