//go:build (mips || mips64 || ppc64 || s390x) && linux

package dhcp

import "encoding/binary"

var hostByteOrder = binary.BigEndian
