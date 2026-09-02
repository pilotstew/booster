package main

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeElfStub emits a header-only ELF file. Dependency resolution reads
// nothing past the header, so a stub of the right class and machine stands in
// for a real shared library of that architecture.
func writeElfStub(t *testing.T, path string, class elf.Class, machine elf.Machine) {
	t.Helper()

	var size, ehsize, phentsize, shentsize int
	if class == elf.ELFCLASS64 {
		size, ehsize, phentsize, shentsize = 64, 64, 56, 64
	} else {
		size, ehsize, phentsize, shentsize = 52, 52, 32, 40
	}

	b := make([]byte, size)
	copy(b, "\x7fELF")
	b[elf.EI_CLASS] = byte(class)
	b[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	b[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(b[18:], uint16(machine))
	binary.LittleEndian.PutUint32(b[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(b[ehsize-12:], uint16(ehsize))
	binary.LittleEndian.PutUint16(b[ehsize-10:], uint16(phentsize))
	binary.LittleEndian.PutUint16(b[ehsize-6:], uint16(shentsize))

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, b, 0o755))
}

// A soname does not identify a file: on a multilib host the same name exists
// once per architecture. Resolving it by name alone packs a library the
// image's own loader refuses, and the failure surfaces at boot as PID 1
// exiting 127 rather than as a build error. Both directions are pinned so
// that reordering the search path cannot pass for a fix.
func TestElfPathSkipsMismatchedArchitecture(t *testing.T) {
	dir := t.TempDir()
	lib32 := filepath.Join(dir, "lib32")
	lib64 := filepath.Join(dir, "lib64")
	writeElfStub(t, filepath.Join(lib32, "libfoo.so.1"), elf.ELFCLASS32, elf.EM_386)
	writeElfStub(t, filepath.Join(lib64, "libfoo.so.1"), elf.ELFCLASS64, elf.EM_X86_64)

	defer func(saved []string) { elfLibDir = saved }(elfLibDir)
	elfLibDir = []string{lib32, lib64}

	require.Equal(t, filepath.Join(lib64, "libfoo.so.1"),
		elfPath("libfoo.so.1", elf.ELFCLASS64, elf.EM_X86_64))
	require.Equal(t, filepath.Join(lib32, "libfoo.so.1"),
		elfPath("libfoo.so.1", elf.ELFCLASS32, elf.EM_386))
}

// A candidate of the wrong architecture is not a fallback. Reporting no match
// lets AppendElfDependencies fail the build, which is where an unsatisfiable
// dependency should surface; packing it instead defers the failure to boot,
// where it costs a kernel panic to diagnose.
func TestElfPathReportsNoMatchRatherThanWrongArchitecture(t *testing.T) {
	lib32 := filepath.Join(t.TempDir(), "lib32")
	writeElfStub(t, filepath.Join(lib32, "libfoo.so.1"), elf.ELFCLASS32, elf.EM_386)

	defer func(saved []string) { elfLibDir = saved }(elfLibDir)
	elfLibDir = []string{lib32}

	require.Empty(t, elfPath("libfoo.so.1", elf.ELFCLASS64, elf.EM_X86_64))
}
