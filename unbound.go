// Wrapper around lib Unbound.
//
// Has parsing for TLSA-records.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under LGPL v3 or later. See LICENSE

package unbound

// This file handles DNSSEC/DANE validation and server certificate gathering.
// Relies on libunbound (www.unbound.org) to do all the heavy lifting.

/*
 #cgo LDFLAGS: -lunbound

#include <stdlib.h>
#include <unbound.h>
*/
import "C"
import (
	"unsafe"
	"crypto/x509"
	"log"
	"fmt"
)

type UbContext struct {
	TrustAnchors []string  // ". 86400 DNSKEY 257 3 8 AwEAAagAIKlVZrpC..." DNS Root key
	Forwarders   []string  // If unset unbound resolves self recursively.
	// DebugLevel *int
	// DebugOut   *io.Writer
	
	// encapsulate the C-environment
	ubctx        *C.struct_ub_ctx // the unbound C struct used in the calls.
}

// New returns the context.
func New() (*UbContext) {
	return &Ctx
}

// UbCtxCreate creates the Unbound context
func UbCtxCreate(ctx *UbContext) {
	ubctx := C.ub_ctx_create()
	for _, ta := range ctx.TrustAnchors {
		cs := C.CString(ta)
		C.ub_ctx_add_ta(ubctx, cs)
		C.free(unsafe.Pointer(cs))
	}

	ctx.ubctx = ubctx
}

// resolve resolves the given name into a response for an rrType-RR
func (ctx *UbContext) Resolve(name string, rrType int) (*UbResult, error) {
	log.Printf("Resolving %s for type %d", name, rrType)
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))	
	
	var result *C.struct_ub_result
	retval := C.ub_resolve(ctx.ubctx, cs, C.int(rrType), 1, &result)
	
	// C returns 0 if OK
	if retval == 0 {
		return parseUbResult(result), nil
	}
	return nil, fmt.Errorf("Error resolving: %s, reason: %#v", name, result)
}

type UbResult struct {
	Qname string
	Qtype int
	Qclass int
	Data [][]byte
	CanonName string
	Rcode int
	AnswerPacket []byte
	HaveData bool
	NxDomain bool
	Secure bool
	Bogus bool
	WhyBogus string
}

func parseUbResult(ub *C.struct_ub_result) (*UbResult) {
	//log.Printf("Raw result is %#v\n", ub)
	
	var res UbResult
	res.Qname =  C.GoString(ub.qname)
	res.Qtype = int(ub.qtype)
	res.Qclass = int(ub.qclass)
	res.Qtype = int(ub.qtype)
	res.CanonName = C.GoString(ub.canonname)
	res.Rcode = int(ub.rcode)
	res.AnswerPacket = C.GoBytes(ub.answer_packet, ub.answer_len)
	res.HaveData = GoBool(ub.havedata)
	res.NxDomain = GoBool(ub.nxdomain)
	res.Secure = GoBool(ub.secure)
	res.Bogus = GoBool(ub.bogus)
	res.WhyBogus = C.GoString(ub.why_bogus)
	
	res.Data = getUbData(ub.data, ub.len)
	//log.Printf("ParseUbResult gave %#v\n", res)
	return &res
}


// getUbData reads the **ub.data structure and returns an array of byte-arrays.
// Each array ub.data[i] is ub.len[i] bytes long.
func getUbData(p **C.char, l *C.int) ([][]byte) {
        var b [][]byte
        q := uintptr(unsafe.Pointer(p)) // q is the pointer to data of p
        m := uintptr(unsafe.Pointer(l))
	for {
                p = (**C.char)(unsafe.Pointer(q)) // p is the correct type for data at q
		l = (*C.int)(unsafe.Pointer(m))
		if *p == nil || *l == 0 {
			return b
                }
 		b = append(b, C.GoBytes(unsafe.Pointer(*p), *l))
                q += unsafe.Sizeof(q) // point to next record in list.
		m += 4                // on 64bit systems, int == int64, this list is specified with int32
        }
	return b
}


// GoBool returns a Go boolean for a C.int where 0->false; otherwise->true (like C)
func GoBool(i C.int) bool {
	if i == 0 { return false }
	return true
}

// TODO: make a separate file/package. Or integrate into a DNS library. Or use one ;-) 	
type TLSA struct {
	Usage int
	Selector int
	MatchType int
	CertAssociation []byte
}

// ParseTLSAs parses multiple TLSA byte arrays from unbound into proper TLSA structs
func ParseTLSAs(bs [][]byte) (tlsa []TLSA) {
	for _, b := range bs {
		tlsa = append(tlsa, ParseTLSA(b))
	}
	return
}

// parseTLSA byte arrays to proper TLSA structs 
func ParseTLSA(b []byte) TLSA {
	tlsa := TLSA{
		Usage: int(b[0]),
		Selector: int(b[1]),
		MatchType: int(b[2]),
		CertAssociation: b[3:],
	}
	log.Printf("TLSA record: %d, %d, %d, %d\n", tlsa.Usage, tlsa.Selector, tlsa.MatchType, len(tlsa.CertAssociation))
	return tlsa
}

// TODO: move this to ecca-lib or elsewhere.
// GetCACert gets certificate from DNSSEC/DANE.
func (ctx *UbContext) GetCACert(hostname string) (*x509.Certificate, error) {
	log.Printf("GetCaCert for %s", hostname)
	
 	// res, err := ctx.Resolve("_443._tcp." + hostname, 52) // 52 is tlsa
 	res, err := ctx.Resolve(hostname, 52) // 52 is tlsa
	if err != nil {
		return nil, err
	}

 	tlsas := ParseTLSAs(res.Data)
	// Find the first full CA certificate, ie, no hash.
	for _, tlsa := range tlsas {
		if tlsa.Usage == 2 && // Own CA.  
			tlsa.Selector == 0 && // 0:  Certificate, 1: Public key
			tlsa.MatchType == 0  { // 0: Full data, 1: sha256, 2: sha512
			log.Printf("found correct TLSA-record\n")
			cert, err := x509.ParseCertificate(tlsa.CertAssociation)
			if err != nil {
				return nil, err
			}
			log.Printf("Parses to: %s ", cert.Subject.CommonName)
			return cert, nil // return the very first record....
		}
	}
	// .. or return an error if nothing matches.
	return nil, fmt.Errorf("No DANE Record with full certificates (2,0,0) found in DNSSEC for _443._tcp.%s", hostname) 
}


//-------------------- INIT -------------------------------------------
// use a global context to allow unbound to do caching.
var Ctx UbContext

func init () {
	Ctx = UbContext{
		// Forwarders: []string{"::1"},  // not needed yet, let unbound do the resolving and caching
		TrustAnchors: []string{". 86400 DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=",
	}}
	UbCtxCreate(&Ctx) // set the embedded C-context
}
