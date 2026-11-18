package dns

import (
	"errors"
	"fmt"
	"github.com/MyHeartRaces/FLR/runtime/internal/contract"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentMappingsShareCommitsAndWaitForInstallation(t *testing.T) {
	k := NewKernelMappings()
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	k.apply = func(batch string) error {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil
	}
	const count = 32
	results := make(chan error, count)
	view := View{ID: "general", Class: contract.General}
	go func() {
		results <- k.Replace(view, "first.example", []AddressTTL{{IP: netip.MustParseAddr("8.8.8.8"), TTL: time.Minute}})
	}()
	<-started
	var entered sync.WaitGroup
	entered.Add(count - 1)
	for i := 1; i < count; i++ {
		go func(i int) {
			entered.Done()
			results <- k.Replace(view, fmt.Sprintf("%d.example", i), []AddressTTL{{IP: netip.MustParseAddr("9.9.9.9"), TTL: time.Minute}})
		}(i)
	}
	entered.Wait()
	time.Sleep(30 * time.Millisecond)
	select {
	case <-results:
		t.Fatal("DNS caller acknowledged before kernel commit")
	default:
	}
	close(release)
	for i := 0; i < count; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("mapping queue stalled")
		}
	}
	if n := calls.Load(); n > 3 {
		t.Fatalf("burst caused %d serialized commits", n)
	}
}

func TestMappingCommitFailureIsReturnedToCaller(t *testing.T) {
	k := NewKernelMappings()
	expected := errors.New("kernel rejected mapping")
	k.apply = func(string) error { return expected }
	if err := k.Replace(View{ID: "general", Class: contract.General}, "a.example", []AddressTTL{{IP: netip.MustParseAddr("8.8.8.8"), TTL: time.Minute}}); !errors.Is(err, expected) {
		t.Fatalf("uncommitted mapping acknowledged: %v", err)
	}
}
