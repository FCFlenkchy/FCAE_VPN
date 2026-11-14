module github.com/quic-go/qpack

go 1.26.0

// The same x/net the archive resolves to (tun2socks requires it); anything
// lower is dead weight here and anything higher would silently upgrade the
// whole archive.
require golang.org/x/net v0.61.0
