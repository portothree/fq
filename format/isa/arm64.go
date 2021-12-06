package isa

import (
	"strings"

	"github.com/wader/fq/format"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/scalar"
	"golang.org/x/arch/arm64/arm64asm"
)

func init() {
	registry.MustRegister(decode.Format{
		Name:        format.ARM64,
		Description: "ARM64 instructions",
		DecodeFn:    decodeARM64,
		RootArray:   true,
		RootName:    "instructions",
	})
}

func decodeARM64(d *decode.D, in interface{}) interface{} {
	var symLookup func(uint64) (string, uint64)
	var base int64
	if xi, ok := in.(format.ARM64In); ok {
		symLookup = xi.SymLookup
		base = xi.Base
	}

	bb := d.BytesRange(0, int(d.BitsLeft()/8))
	// TODO: uint64?
	pc := base

	for !d.End() {
		d.FieldStruct("instruction", func(d *decode.D) {
			i, err := arm64asm.Decode(bb)
			if err != nil {
				d.Fatalf("failed to decode arm64 instruction: %s", err)
			}

			// TODO: other syntax
			d.FieldRawLen("opcode", int64(4)*8, scalar.Sym(arm64asm.GoSyntax(i, uint64(pc), symLookup, nil)), scalar.Hex)

			// TODO: Enc?
			d.FieldValueU("op", uint64(i.Enc), scalar.Sym(strings.ToLower(i.Op.String())), scalar.Hex)

			bb = bb[4:]
			pc += int64(4)
		})

	}

	return nil
}
