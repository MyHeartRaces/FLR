package controller

import (
	"context"
	"errors"

	"github.com/MyHeartRaces/FLR/runtime/internal/config"
	"github.com/MyHeartRaces/FLR/runtime/internal/dataplane"
	"github.com/MyHeartRaces/FLR/runtime/internal/policy"
)

func (c *Controller) startRoutingDNS() error {
	if c.vpnCancel != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(c.ctx)
	done, err := c.broker.Start(ctx, "0.0.0.0:"+c.settings.DNSPort)
	if err != nil {
		cancel()
		return err
	}
	c.vpnCancel, c.vpnDone = cancel, done
	return nil
}

func (c *Controller) stopRoutingDNS() {
	if c.vpnCancel != nil {
		c.vpnCancel()
		<-c.vpnDone
		c.vpnCancel, c.vpnDone = nil, nil
	}
}

type routingModeOps struct {
	publish   func(*policy.Policy, bool) error
	guardDNS  func() error
	nativeDNS func(bool) error
	startDNS  func() error
	stopDNS   func()
}

// apply keeps the previous forwarding policy in place until the target DNS
// listener is ready. A guarded request must also run when the operator cancels
// a failed handoff by choosing the previous mode again.
func (r routingModeOps) apply(previous, next *policy.Policy, pending *bool) error {
	if previous.Bypass() == next.Bypass() && !*pending {
		return r.publish(next, false)
	}
	recovering := *pending
	*pending = true
	if err := r.guardForwarding(previous, recovering); err != nil {
		return err
	}
	if err := r.prepareDNS(next); err != nil {
		return errors.Join(err, r.restoreDNS(previous, pending))
	}
	if err := r.publish(next, false); err != nil {
		// nft may have committed before a command lost its acknowledgement.
		// Fence DNS independently, then recover the previous forwarding mode
		// without releasing the guard until its DNS listener is restored.
		if fenceErr := r.guardForwarding(previous, true); fenceErr != nil {
			return errors.Join(err, fenceErr)
		}
		return errors.Join(err, r.restoreDNS(previous, pending))
	}
	*pending = false
	return nil
}

func (r routingModeOps) guardForwarding(previous *policy.Policy, restore bool) error {
	if err := r.guardDNS(); err != nil {
		return err
	}
	if restore {
		return r.publish(previous, true)
	}
	return nil
}

func (r routingModeOps) prepareDNS(view *policy.Policy) error {
	// The broker may own port 53. Always stop it before preparing either
	// listener, including when recovering from an interrupted handoff.
	r.stopDNS()
	if err := r.nativeDNS(view.Bypass()); err != nil {
		return err
	}
	if !view.Bypass() {
		return r.startDNS()
	}
	return nil
}

func (r routingModeOps) restoreDNS(previous *policy.Policy, pending *bool) error {
	if err := r.prepareDNS(previous); err != nil {
		return err
	}
	if err := r.publish(previous, false); err != nil {
		// The preceding transaction may have completed despite its error.
		// Re-fence until the controller can confirm a successful retry.
		return errors.Join(err, r.guardDNS())
	}
	*pending = false
	return nil
}

func (c *Controller) switchRoutingPolicy(next *policy.Policy) error {
	if next.Bypass() && !c.policy.Bypass() {
		if c.router.IsZero() {
			return errors.New("cannot switch to native DNS before the router LAN is available")
		}
		if err := config.CheckNativeRoutingDNS(); err != nil {
			return err
		}
	}
	o := c.settings.Options
	o.Net = c.router
	o.DNSPort = c.settings.DNSPort
	guard, err := dataplane.DNSHandoffBatch(c.settings.DNSPort, c.settings.LocalDNSPort)
	if err != nil {
		return err
	}
	publish := func(view *policy.Policy, keepGuard bool) error {
		batch, err := dataplane.RoutingPolicyBatch(view, o)
		if err != nil {
			return err
		}
		if keepGuard {
			batch += guard
		}
		if view.Bypass() {
			boot, err := dataplane.PrepareRoutingBootGuard(c.basePolicy, o)
			if err != nil {
				return err
			}
			batch += boot
		}
		if c.broker == nil {
			return dataplane.Nft(batch)
		}
		return c.broker.ApplyPolicy(view, batch)
	}
	guardDNS := func() error { return dataplane.Nft(guard) }
	nativeDNS := func(direct bool) error { return config.SetRoutingDNS(c.ctx, direct, c.router.Addr) }
	ops := routingModeOps{publish: publish, guardDNS: guardDNS, nativeDNS: nativeDNS, startDNS: c.startRoutingDNS, stopDNS: c.stopRoutingDNS}
	err = ops.apply(c.policy, next, &c.routingDNSHandoffPending)
	if c.routingDNSHandoffPending {
		c.mu.Lock()
		c.routingDirty = true
		c.mu.Unlock()
	}
	return err
}
