//go:build (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64) && linux

package dhcp

import "encoding/binary"

var hostByteOrder = binary.LittleEndian
