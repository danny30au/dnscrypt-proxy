// Package dnsjson implements the RR and RRset as defined in RFC 8427. The message type is not implemented.
// [codeberg.org/miekg/dns.MarshalJSON] and [codeberg.org/miekg/dns.UnmarshalJSON] are the primary interface of this package.
package dnsjson

// RR represents a DNS RR as specified in RFC 8427.
type RR struct {
	Name      string  `json:"NAME"`                // Name is the owner name of the RR.
	TTL       uint32  `json:"TTL"`                 // TTL is the time-to-live of the RR.
	TypeName  string  `json:"TYPEname,omitempty"`  // TypeName is the string representation of the type. If takes precedence of Type.
	Type      uint16  `json:"TYPE,omitempty"`      // Type is the type of the RR.
	ClassName string  `json:"CLASSname,omitempty"` // ClassName is the string representation of the class. It takes precedence over Class.
	Class     uint16  `json:"CLASS,omitempty"`     // Class is the class of the RR, this is not set, class IN is assumed.
	RdataHex  string  `json:"RDATAHEX,omitempty"`
	RRset     []RRset `json:"rrSet,omitempty"`
}

// RRset represents a DNS RRset as specified in RFC 8427.
type RRset struct {
	RdataHex string `json:"RDATAHEX"`
}
