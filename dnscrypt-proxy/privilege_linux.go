package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/jedisct1/dlog"
)

func (proxy *Proxy) dropPrivilege(userStr string, fds []*os.File) {
	if os.Geteuid() != 0 {
		dlog.Fatal("Root privileges are required in order to switch to a different user. Maybe try again with 'sudo'")
	}

	uid, gid, err := lookupUIDGID(userStr)
	if err != nil {
		dlog.Fatal(err)
	}

	path, args, err := resolveReexecPathAndArgs()
	if err != nil {
		dlog.Fatal(err)
	}

	// Notify service manager now: after privileges are dropped we might not be able to.
	if err := ServiceManagerReadyNotify(); err != nil {
		dlog.Fatal(err)
	}

	dlog.Notice("Dropping privileges")

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Drop supplementary groups.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETGROUPS, uintptr(0), uintptr(0), 0); errno != 0 {
		dlog.Fatalf("Unable to drop additional groups: [%s]", errno.Error())
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETGID, uintptr(gid), 0, 0); errno != 0 {
		dlog.Fatalf("Unable to drop group privileges: [%s]", errno.Error())
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETUID, uintptr(uid), 0, 0); errno != 0 {
		dlog.Fatalf("Unable to drop user privileges: [%s]", errno.Error())
	}

	// Duplicate file descriptors into the well-known inherited range.
	for i, fd := range fds {
		if fd == nil {
			continue
		}
		if fd.Fd() >= InheritedDescriptorsBase {
			dlog.Fatal("Duplicated file descriptors are above base")
		}
		if err := unix.Dup2(int(fd.Fd()), int(InheritedDescriptorsBase+uintptr(i))); err != nil {
			dlog.Fatalf("Unable to clone file descriptor: [%s]", err)
		}
		// Mark the original fds close-on-exec; the duplicated ones remain inheritable.
		if _, err := unix.FcntlInt(fd.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			dlog.Fatalf("Unable to set the close on exec flag: [%s]", err)
		}
	}

	err = unix.Exec(path, args, os.Environ())
	dlog.Fatalf("Unable to reexecute [%s]: [%s]", path, err)
	os.Exit(1)
}

func resolveReexecPathAndArgs() (string, []string, error) {
	args := append([]string(nil), os.Args...)
	if len(args) == 0 {
		return "", nil, errors.New("missing argv[0]")
	}
	// Re-exec with -child.
	args = append(args, "-child")

	execPath, err := exec.LookPath(args[0])
	if err != nil {
		return "", nil, fmt.Errorf("unable to get the path to the dnscrypt-proxy executable file: %w", err)
	}
	abs, err := filepath.Abs(execPath)
	if err != nil {
		return "", nil, err
	}
	return abs, args, nil
}

func lookupUIDGID(userStr string) (uid int, gid int, err error) {
	userInfo, lookupErr := user.Lookup(userStr)
	if lookupErr != nil {
		// Allow numeric uid fallback.
		nuid, err2 := strconv.Atoi(userStr)
		if err2 != nil || nuid <= 0 {
			return 0, 0, fmt.Errorf(
				"unable to retrieve any information about user [%s]: [%v] - remove the user_name directive from the configuration file in order to avoid identity switch",
				userStr,
				lookupErr,
			)
		}
		dlog.Warnf(
			"Unable to retrieve any information about user [%s]: [%v] - Switching to user id [%v] with the same group id, as [%v] looks like a user id. But you should remove or fix the user_name directive in the configuration file if possible",
			userStr,
			lookupErr,
			nuid,
			nuid,
		)
		return nuid, nuid, nil
	}

	uid, err = strconv.Atoi(userInfo.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err = strconv.Atoi(userInfo.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}
