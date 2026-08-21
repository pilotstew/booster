package main

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestWaitForBtrfsDevicesReady(t *testing.T) {
	orig := btrfsDevicesReady
	t.Cleanup(func() { btrfsDevicesReady = orig })

	// Short enough that a case which wrongly keeps polling fails the test
	// rather than running for the real ten minutes.
	origTimeout := btrfsTimeout
	btrfsTimeout = 5 * time.Second
	t.Cleanup(func() { btrfsTimeout = origTimeout })

	t.Run("ready at once", func(t *testing.T) {
		calls := 0
		btrfsDevicesReady = func(string) (bool, error) { calls++; return true, nil }
		require.NoError(t, waitForBtrfsDevicesReady("/dev/dm-0"))
		require.Equal(t, 1, calls, "a ready volume must not be polled twice")
	})

	t.Run("assembling then ready", func(t *testing.T) {
		calls := 0
		btrfsDevicesReady = func(string) (bool, error) {
			calls++
			return calls > 2, nil
		}
		require.NoError(t, waitForBtrfsDevicesReady("/dev/dm-0"))
		require.Equal(t, 3, calls)
	})

	t.Run("a scan failure is not waited out", func(t *testing.T) {
		calls := 0
		btrfsDevicesReady = func(string) (bool, error) {
			calls++
			return false, unix.ENOENT
		}
		err := waitForBtrfsDevicesReady("/dev/dm-0")
		require.Error(t, err)
		require.Equal(t, 1, calls, "the volume will not assemble by polling a device that cannot be scanned")
		require.ErrorIs(t, err, unix.ENOENT)
		require.Contains(t, err.Error(), "/dev/dm-0", "the message must name the device")
	})

	t.Run("errors is unwrappable through the wrapper", func(t *testing.T) {
		btrfsDevicesReady = func(string) (bool, error) { return false, unix.ENXIO }
		err := waitForBtrfsDevicesReady("/dev/dm-0")
		require.True(t, errors.Is(err, unix.ENXIO))
	})
}
