// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiacs

import (
	"bytes"
	"testing"
)

// FuzzCWMPEnvelopeParser fuzzes the TR-069 CWMP SOAP/XML envelope parser against malformed CPE payloads.
func FuzzCWMPEnvelopeParser(f *testing.F) {
	f.Add([]byte(`<Envelope><Header><ID>1</ID></Header><Body><Inform><DeviceId><Manufacturer>ZTE</Manufacturer><OUI>001122</OUI><ProductClass>F670L</ProductClass><SerialNumber>ZTEGC1</SerialNumber></DeviceId></Inform></Body></Envelope>`))
	f.Add([]byte(`<Envelope><Body><Fault><faultcode>Client</faultcode><faultstring>Bad</faultstring></Fault></Body></Envelope>`))
	f.Add([]byte(`<<<broken xml>>>`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		_, _ = ParseCWMPEnvelope(bytes.NewReader(data))
	})
}
