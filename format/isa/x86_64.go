package isa

import (
	"log"
	"strings"

	"github.com/wader/fq/format"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/scalar"
	"golang.org/x/arch/x86/x86asm"
)

func init() {
	registry.MustRegister(decode.Format{
		Name:        format.X86_64,
		Description: "x86-64 instructions",
		DecodeFn:    decodeX86_64,
		RootArray:   true,
		RootName:    "instructions",
	})
}

func decodeX86_64(d *decode.D, in interface{}) interface{} {
	var symLookup func(uint64) (string, uint64)
	var base int64
	if xi, ok := in.(format.X86_64In); ok {
		symLookup = xi.SymLookup
		base = xi.Base
	}

	bb := d.BytesRange(0, int(d.BitsLeft()/8))
	// TODO: uint64?
	pc := base

	for !d.End() {
		d.FieldStruct("instruction", func(d *decode.D) {
			i, err := x86asm.Decode(bb, 64)
			if err != nil {
				d.Fatalf("failed to decode x86 instruction: %s", err)
			}

			d.FieldRawLen("opcode", int64(i.Len)*8, scalar.Sym(x86asm.IntelSyntax(i, uint64(pc), symLookup)), scalar.Hex)

			log.Printf("i.Len: %#+v\n", i.Len)
			log.Printf("i.Opcode: %x\n", i.Opcode)
			log.Printf("i: %#+v\n", i)

			// TODO: rebuild op lower?
			d.FieldValueU("op", uint64(i.Opcode), scalar.Sym(strings.ToLower(i.Op.String())), scalar.Hex)

			bb = bb[i.Len:]
			pc += int64(i.Len)
		})

	}

	return nil
}
