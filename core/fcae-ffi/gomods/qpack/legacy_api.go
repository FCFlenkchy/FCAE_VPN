package qpack

import (
	"errors"
	"io"
)

// NewDecoder returns a new Decoder.
//
// The optional emitFunc is the pre-0.6 signature: it was called for each field
// as the block was written. qpack dropped streaming in 0.6 and quic-go's own
// fork moved to `NewDecoder()`, but Psiphon's fork still passes a callback. One
// module graph can only resolve `github.com/quic-go/qpack` to one version, so
// this copy accepts both forms.
func NewDecoder(emitFunc ...func(HeaderField)) *Decoder {
	return &Decoder{}
}

// DecodeFull decodes a complete header block, the pre-0.6 entry point.
//
// It is the iterator returned by Decode, drained into a slice, so both
// generations decode through the same code path.
func (d *Decoder) DecodeFull(p []byte) ([]HeaderField, error) {
	if len(p) == 0 {
		return []HeaderField{}, nil
	}
	decode := d.Decode(p)
	var headerFields []HeaderField
	for {
		headerField, err := decode()
		if errors.Is(err, io.EOF) {
			return headerFields, nil
		}
		if err != nil {
			return nil, err
		}
		headerFields = append(headerFields, headerField)
	}
}
