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
	publish   func(*policy.Policy) error
	nativeDNS func(bool) error
	startDNS  func() error
	stopDNS   func()
}

// apply hands off the router's DNS port when crossing the Direct boundary.
// DNS interception and packet policy are always published together.
func (r routingModeOps) apply(previous, next *policy.Policy) error {
	if previous.Bypass() == next.Bypass() {
		return r.publish(next)
	}
	if next.Bypass() {
		if err := r.publish(next); err != nil {
			return err
		}
		r.stopDNS()
		if err := r.nativeDNS(true); err != nil {
			return errors.Join(err, r.restorePolicy(previous))
		}
		return nil
	}
	if err := r.nativeDNS(false); err != nil {
		return errors.Join(err, r.nativeDNS(true))
	}
	if err := r.startDNS(); err != nil {
		return errors.Join(err, r.nativeDNS(true))
	}
	if err := r.publish(next); err != nil {
		r.stopDNS()
		return errors.Join(err, r.nativeDNS(true))
	}
	return nil
}

func (r routingModeOps) restorePolicy(previous *policy.Policy) error {
	if err := r.nativeDNS(false); err != nil {
		return err
	}
	if err := r.publish(previous); err != nil {
		return err
	}
	return r.startDNS()
}

func (c *Controller) switchRoutingPolicy(next *policy.Policy) error {
	if next.Bypass() && !c.policy.Bypass() {
		if err := config.CheckNativeRoutingDNS(); err != nil {
			return err
		}
	}
	o := c.settings.Options
	o.Net = c.router
	o.DNSPort = c.settings.DNSPort
	publish := func(view *policy.Policy) error {
		batch, err := dataplane.RoutingPolicyBatch(view, o)
		if err != nil {
			return err
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
	ops := routingModeOps{publish: publish, nativeDNS: config.SetRoutingDNS, startDNS: c.startRoutingDNS, stopDNS: c.stopRoutingDNS}
	return ops.apply(c.policy, next)
}
