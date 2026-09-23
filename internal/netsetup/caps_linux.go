//go:build linux

package netsetup

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"

	"github.com/moby/sys/capability"
)

// capNetAdmin is the capability that programs the tables. Source: linux
// include/uapi/linux/capability.h, CAP_NET_ADMIN 12.
const capNetAdmin = capability.CAP_NET_ADMIN

// prctl operations golang.org/x/sys and github.com/moby/sys/capability do
// not cover. Source: linux include/uapi/linux/prctl.h.
const (
	prSetNoNewPrivs = 38
	prGetNoNewPrivs = 39
)

// DropNetAdmin removes CAP_NET_ADMIN from the calling thread, in every set,
// and closes the one path that puts it back. It runs after the rules are
// applied and verified.
//
// The scope is the thread and not the process. capset, PR_CAPBSET_DROP and
// PR_SET_NO_NEW_PRIVS each act on the calling thread (capabilities(7),
// prctl(2)), and runtime.LockOSThread pins this goroutine to one thread
// without reaching the threads the Go runtime already started. Those threads
// keep CAP_NET_ADMIN in their permitted and bounding sets. The init
// container writes the receipt and exits as soon as this call returns, so
// nothing runs on them.
//
// Three things make the drop hold on this thread and none is enough on its
// own.
//
// capset clears the permitted, effective and inheritable sets. A capability
// dropped from the permitted set cannot be raised again, and the kernel
// clears the ambient bit with it, because a capability is ambient only while
// it is both permitted and inheritable (capabilities(7)).
//
// PR_SET_NO_NEW_PRIVS stops an execve from granting more than the process
// already holds. Without it a uid-0 process gets the bounding set union the
// inheritable set on execve of a file with no file capabilities, which hands
// CAP_NET_ADMIN straight back (linux security/commoncap.c,
// handle_privileged_root).
//
// PR_CAPBSET_DROP takes the capability out of the bounding set, which is the
// ceiling that rule draws from. It needs CAP_SETPCAP (capabilities(7)), so
// the init container holds SETPCAP alongside NET_ADMIN.
//
// The goroutine is pinned for the whole sequence, so the sets read back are
// the ones that were written.
func DropNetAdmin() error {
	// NEVER unlock: a later step running on a thread that did not drop would
	// read a state this function did not produce.
	runtime.LockOSThread()
	// no_new_privs first: it needs no capability, so it is in force even if
	// what follows fails.
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("set no_new_privs: %w", errno)
	}
	if err := capability.DropBound(capNetAdmin); err != nil {
		return fmt.Errorf("drop CAP_NET_ADMIN from the bounding set: %w. PR_CAPBSET_DROP needs CAP_SETPCAP, "+
			"so the init container needs capabilities.add [NET_ADMIN, SETPCAP]", err)
	}
	caps, err := threadCapabilities()
	if err != nil {
		return err
	}
	caps.Unset(capability.CAPS, capNetAdmin)
	if err := caps.Apply(capability.CAPS); err != nil {
		return fmt.Errorf("drop CAP_NET_ADMIN: %w", err)
	}
	return confirmDropped()
}

// confirmDropped reads every set back. A call that returned zero and left
// the capability reachable is the failure this check exists to keep from
// being reported as done.
func confirmDropped() error {
	caps, err := threadCapabilities()
	if err != nil {
		return err
	}
	for _, set := range []struct {
		which capability.CapType
		name  string
	}{
		{capability.EFFECTIVE, "effective"},
		{capability.PERMITTED, "permitted"},
		{capability.INHERITABLE, "inheritable"},
	} {
		if caps.Get(set.which, capNetAdmin) {
			return fmt.Errorf("CAP_NET_ADMIN is still in this thread's %s set after capset", set.name)
		}
	}
	bounding, err := capability.GetBound(capNetAdmin)
	if err != nil {
		return fmt.Errorf("read the capability bounding set: %w", err)
	}
	if bounding {
		return errors.New("CAP_NET_ADMIN is still in the bounding set after PR_CAPBSET_DROP, " +
			"so an execve would grant it back")
	}
	ambient, err := ambientNetAdmin()
	if err != nil {
		return err
	}
	if ambient {
		return errors.New("CAP_NET_ADMIN is still in the ambient set after capset, " +
			"so an execve would carry it into the new program")
	}
	set, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prGetNoNewPrivs, 0, 0)
	if errno != 0 {
		return fmt.Errorf("read no_new_privs: %w", errno)
	}
	if set != 1 {
		return errors.New("no_new_privs is not set after PR_SET_NO_NEW_PRIVS, " +
			"so an execve could grant privileges this process gave up")
	}
	return nil
}

// HasNetAdmin reports whether this process holds CAP_NET_ADMIN in its
// effective set.
func HasNetAdmin() (bool, error) {
	caps, err := threadCapabilities()
	if err != nil {
		return false, err
	}
	return caps.Get(capability.EFFECTIVE, capNetAdmin), nil
}

// ambientNetAdmin reports whether CAP_NET_ADMIN is in this thread's ambient
// set, which an execve carries into the new program. PR_CAP_AMBIENT arrived
// in Linux 4.3 and an older kernel answers EINVAL, where nothing is ambient.
func ambientNetAdmin() (bool, error) {
	held, err := capability.GetAmbient(capNetAdmin)
	if err != nil {
		if errors.Is(err, syscall.EINVAL) {
			return false, nil
		}
		return false, fmt.Errorf("read the ambient capability set: %w", err)
	}
	return held, nil
}

// threadCapabilities reads this thread's permitted, effective and
// inheritable sets with capget.
//
// NEVER read the bounding or ambient set through this value. Load takes
// those two from /proc/self/status, which reports the thread group leader,
// and every capability primitive here acts on the calling thread.
func threadCapabilities() (capability.Capabilities, error) {
	caps, err := capability.NewPid2(0)
	if err != nil {
		return nil, fmt.Errorf("read this process's capabilities: %w", err)
	}
	if err := caps.Load(); err != nil {
		return nil, fmt.Errorf("read this process's capabilities: %w", err)
	}
	return caps, nil
}
