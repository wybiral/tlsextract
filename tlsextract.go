// Package tlsextract provides utilities for extracting TLS metadata from
// connections in a JSON-friendly format.
package tlsextract

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
)

const Version = "0.0.0"

// FromAddr returns TLS connection Metadata from domain:port address.
func FromAddr(addr string) (*Metadata, error) {
	// Allow all certificates (unverified)
	cfg := &tls.Config{InsecureSkipVerify: true}
	// Open TLS connection
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Extract TLS data
	return FromConn(conn)
}

// FromConn returns TLS connection Metadata from tls.Conn.
func FromConn(conn *tls.Conn) (*Metadata, error) {
	state := conn.ConnectionState()
	m := &Metadata{}
	m.CipherSuite = state.CipherSuite
	for _, p := range state.PeerCertificates {
		c := &Certificate{}
		c.Signature.Algorithm = p.SignatureAlgorithm.String()
		c.Signature.Value = p.Signature
		c.PublicKey.Algorithm = p.PublicKeyAlgorithm.String()
		b, err := x509.MarshalPKIXPublicKey(p.PublicKey)
		if err != nil {
			return nil, err
		}
		c.PublicKey.Value = b
		copyPKIX(&c.Issuer, p.Issuer)
		copyPKIX(&c.Subject, p.Subject)
		c.OCSPServer = strings.Join(p.OCSPServer, " ")
		c.IssuingCertURL = strings.Join(p.IssuingCertificateURL, " ")
		c.DNSNames = p.DNSNames
		m.Chain = append(m.Chain, c)
	}
	return m, nil
}

type Metadata struct {
	CipherSuite uint16         `json:"cipher_suite"`
	Chain       []*Certificate `json:"chain"`
}

type Certificate struct {
	Signature struct {
		Algorithm string `json:"algorithm"`
		Value     []byte `json:"value"`
	} `json:"signature"`
	PublicKey struct {
		Algorithm string `json:"algorithm"`
		Value     []byte `json:"value"`
	} `json:"public_key"`
	Issuer         Name     `json:"issuer"`
	Subject        Name     `json:"subject"`
	OCSPServer     string   `json:"ocsp_server"`
	IssuingCertURL string   `json:"issuing_cert_url,omitempty"`
	DNSNames       []string `json:"dns_names,omitempty"`
}

type Name struct {
	Country            string `json:"country,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"street_address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organization_unit,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	CommonName         string `json:"common_name,omitempty"`
}

func copyPKIX(n *Name, p pkix.Name) {
	n.Country = strings.Join(p.Country, " ")
	n.Locality = strings.Join(p.Locality, " ")
	n.Province = strings.Join(p.Province, " ")
	n.StreetAddress = strings.Join(p.StreetAddress, " ")
	n.PostalCode = strings.Join(p.PostalCode, " ")
	n.Organization = strings.Join(p.Organization, " ")
	n.OrganizationalUnit = strings.Join(p.OrganizationalUnit, " ")
	n.SerialNumber = p.SerialNumber
	n.CommonName = p.CommonName
}
