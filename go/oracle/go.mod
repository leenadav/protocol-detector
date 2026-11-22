// Test-only module (PRO-127): the tshark oracle for the Go engine. Nothing here is imported by shipped code,
// and go/go.mod and go/vendor stay unchanged: this module's dependencies are pinned in its own go.sum.
module github.com/leenadav/protocol-detector/go/oracle

go 1.27.0

toolchain go1.27.4

require (
	github.com/gopacket/gopacket v1.7.7
	github.com/leenadav/protocol-detector/go v0.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.65.0
)

require (
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/leenadav/protocol-detector/go => ../
