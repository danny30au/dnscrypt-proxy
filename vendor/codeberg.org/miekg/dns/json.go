package dns

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"codeberg.org/miekg/dns/dnsjson"
	"codeberg.org/miekg/dns/pkg/pool"
	"golang.org/x/crypto/cryptobyte"
)

// MarshalJSON returns the JSON (RFC 8427) representation of [RR] as defined in [dnsjson.RR]. If more than one
// [RR] is given it is assumed this represents a [dnsjson.RRset].
func MarshalJSON(rrs ...RR) ([]byte, error) {
	if len(rrs) == 0 {
		return nil, nil
	}
	buf := jsonPool.Get()
	defer jsonPool.Put(buf)

	jrr := &dnsjson.RR{
		Name:      rrs[0].Header().Name,
		TTL:       rrs[0].Header().TTL,
		TypeName:  typeToString(RRToType(rrs[0])),
		ClassName: classToString(rrs[0].Header().Class),
	}

	switch len(rrs) {
	case 1:
		if l := rrs[0].Len(); cap(buf) < l {
			buf = make([]byte, l)
		}

		off, _ := zpack(rrs[0], buf, 0, nil)
		jrr.RdataHex = hex.EncodeToString(buf[:off])
	default:
		jrr.RRset = make([]dnsjson.RRset, len(rrs))
		for i, rr := range rrs {
			if l := rr.Len(); cap(buf) < l {
				buf = make([]byte, l)
			}

			off, _ := zpack(rr, buf, 0, nil)
			jrr.RRset[i].RdataHex = hex.EncodeToString(buf[:off])
		}
	}

	return json.Marshal(jrr)
}

// UnmarshalJSON returns the [RR] from the JSON (RFC 8427) object. If class is not set, [ClassINET] is assumed.
func UnmarshalJSON(data []byte) ([]RR, error) {
	jrr := &dnsjson.RR{}
	err := json.Unmarshal(data, jrr)
	if err != nil {
		return nil, err
	}
	rrs := []RR{}
	if len(jrr.RRset) > 0 {
		rrs = make([]RR, len(jrr.RRset))
	}

	newfn := func() RR { return nil }
	switch {
	case jrr.Type > 0:
		newfn = TypeToRR[jrr.Type]
	case jrr.TypeName != "":
		newfn = TypeToRR[StringToType[jrr.TypeName]]
	default:
		return nil, fmt.Errorf("bad RR type")
	}

	class := uint16(0)
	switch {
	case jrr.Class > 0:
		class = jrr.Class
	case jrr.ClassName != "":
		class, _ = StringToClass[jrr.ClassName]
	default:
		class = ClassINET
	}

	switch len(rrs) {
	case 1:
		rrs[0] = newfn()

		rrs[0].Header().Name = jrr.Name
		rrs[0].Header().TTL = jrr.TTL
		rrs[0].Header().Class = class

		data, err := hex.DecodeString(jrr.RdataHex)
		if err != nil {
			return nil, err
		}
		if err := zunpack(rrs[0], cryptobyte.String(data), nil); err != nil {
			return nil, err
		}
	default:
		for i := range rrs {
			rrs[i] = newfn()

			rrs[i].Header().Name = jrr.Name
			rrs[i].Header().TTL = jrr.TTL
			rrs[i].Header().Class = class

			data, err := hex.DecodeString(jrr.RRset[i].RdataHex)
			if err != nil {
				return nil, err
			}
			if err := zunpack(rrs[i], cryptobyte.String(data), nil); err != nil {
				return nil, err
			}
		}
	}

	return rrs, nil
}

// jsonPool pools allocations to encode/decode to wire format.
var jsonPool = pool.New(DefaultMsgSize)
