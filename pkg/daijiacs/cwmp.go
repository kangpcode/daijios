// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijiacs

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"strings"
)

const MaxCWMPBodyBytes = 512 * 1024

var (
	ErrUnknownCPE   = errors.New("CPE device not registered in ACS inventory")
	ErrInvalidCWMP  = errors.New("invalid or malformed CWMP SOAP envelope")
	ErrUnsafeURL    = errors.New("firmware download URL must use https:// (or explicit http:// override disabled)")
	ErrInvalidWiFi  = errors.New("invalid WiFi SSID or WPA passphrase length")
	ErrInvalidUSP   = errors.New("invalid TR-369 USP message payload")
)

// ParamValue carries one typed TR-069 ParameterValueStruct entry.
type ParamValue struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // xsd:string | xsd:unsignedInt | xsd:boolean
	Value string `json:"value"`
}

// RPCMethod identifies queued TR-069 / TR-369 device operations.
type RPCMethod string

const (
	RPCGetParamValues RPCMethod = "GetParameterValues"
	RPCSetParamValues RPCMethod = "SetParameterValues"
	RPCDownload       RPCMethod = "Download"
	RPCReboot         RPCMethod = "Reboot"
	RPCFactoryReset   RPCMethod = "FactoryReset"
)

// CPETask represents one queued provisioning, upgrade, or lifecycle command for a CPE.
type CPETask struct {
	ID         string       `json:"id"`
	Method     RPCMethod    `json:"method"`
	CommandKey string       `json:"command_key,omitempty"`
	GetPaths   []string     `json:"get_paths,omitempty"`
	SetParams  []ParamValue `json:"set_params,omitempty"`
	FileType   string       `json:"file_type,omitempty"`
	URL        string       `json:"url,omitempty"`
	FileSize   int64        `json:"file_size,omitempty"`
	Status     string       `json:"status"` // pending | sent | done | fault
	FaultCode  string       `json:"fault_code,omitempty"`
	FaultStr   string       `json:"fault_string,omitempty"`
	Summary    string       `json:"summary,omitempty"`
	CreatedAt  string       `json:"created_at"`
	UpdatedAt  string       `json:"updated_at,omitempty"`
}

// InformPayload captures parsed fields from a CWMP Inform SOAP message.
type InformPayload struct {
	ID           string
	Manufacturer string
	OUI          string
	ProductClass string
	SerialNumber string
	Events       []string
	Params       map[string]string
}

// ParsedCWMP classifies an incoming CPE SOAP envelope.
type ParsedCWMP struct {
	MessageID string
	Kind      string // Inform | SetParameterValuesResponse | GetParameterValuesResponse | DownloadResponse | RebootResponse | FactoryResetResponse | Fault
	Inform    *InformPayload
	GetValues map[string]string
	FaultCode string
	FaultStr  string
}

type xmlEnvelope struct {
	Header struct {
		ID string `xml:"ID"`
	} `xml:"Header"`
	Body struct {
		Inform *struct {
			DeviceId struct {
				Manufacturer string `xml:"Manufacturer"`
				OUI          string `xml:"OUI"`
				ProductClass string `xml:"ProductClass"`
				SerialNumber string `xml:"SerialNumber"`
			} `xml:"DeviceId"`
			Event struct {
				Events []struct {
					EventCode string `xml:"EventCode"`
				} `xml:"EventStruct"`
			} `xml:"Event"`
			ParameterList struct {
				Params []struct {
					Name  string `xml:"Name"`
					Value string `xml:"Value"`
				} `xml:"ParameterValueStruct"`
			} `xml:"ParameterList"`
		} `xml:"Inform"`

		GetParamResp *struct {
			ParameterList struct {
				Params []struct {
					Name  string `xml:"Name"`
					Value string `xml:"Value"`
				} `xml:"ParameterValueStruct"`
			} `xml:"ParameterList"`
		} `xml:"GetParameterValuesResponse"`

		SetParamResp *struct {
			Status int `xml:"Status"`
		} `xml:"SetParameterValuesResponse"`

		DownloadResp *struct {
			Status int `xml:"Status"`
		} `xml:"DownloadResponse"`

		RebootResp *struct{} `xml:"RebootResponse"`
		ResetResp  *struct{} `xml:"FactoryResetResponse"`

		Fault *struct {
			FaultCode   string `xml:"faultcode"`
			FaultString string `xml:"faultstring"`
			Detail      struct {
				CWMPFault struct {
					FaultCode   string `xml:"FaultCode"`
					FaultString string `xml:"FaultString"`
				} `xml:"Fault"`
			} `xml:"detail"`
		} `xml:"Fault"`
	} `xml:"Body"`
}

// ParseCWMPEnvelope parses a bounded TR-069 SOAP XML request from a CPE.
func ParseCWMPEnvelope(r io.Reader) (*ParsedCWMP, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxCWMPBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxCWMPBodyBytes {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrInvalidCWMP, MaxCWMPBodyBytes)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return &ParsedCWMP{Kind: "Empty"}, nil
	}

	var env xmlEnvelope
	if err := xml.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCWMP, err)
	}
	out := &ParsedCWMP{MessageID: strings.TrimSpace(env.Header.ID)}

	switch {
	case env.Body.Inform != nil:
		inf := env.Body.Inform
		if strings.TrimSpace(inf.DeviceId.SerialNumber) == "" {
			return nil, fmt.Errorf("%w: Inform missing SerialNumber", ErrInvalidCWMP)
		}
		events := make([]string, 0, len(inf.Event.Events))
		for _, e := range inf.Event.Events {
			if strings.TrimSpace(e.EventCode) != "" {
				events = append(events, strings.TrimSpace(e.EventCode))
			}
		}
		params := make(map[string]string, len(inf.ParameterList.Params))
		for _, p := range inf.ParameterList.Params {
			params[strings.TrimSpace(p.Name)] = strings.TrimSpace(p.Value)
		}
		out.Kind = "Inform"
		out.Inform = &InformPayload{
			ID:           out.MessageID,
			Manufacturer: strings.TrimSpace(inf.DeviceId.Manufacturer),
			OUI:          strings.TrimSpace(inf.DeviceId.OUI),
			ProductClass: strings.TrimSpace(inf.DeviceId.ProductClass),
			SerialNumber: strings.TrimSpace(inf.DeviceId.SerialNumber),
			Events:       events,
			Params:       params,
		}
	case env.Body.GetParamResp != nil:
		out.Kind = "GetParameterValuesResponse"
		out.GetValues = make(map[string]string, len(env.Body.GetParamResp.ParameterList.Params))
		for _, p := range env.Body.GetParamResp.ParameterList.Params {
			out.GetValues[strings.TrimSpace(p.Name)] = strings.TrimSpace(p.Value)
		}
	case env.Body.SetParamResp != nil:
		out.Kind = "SetParameterValuesResponse"
	case env.Body.DownloadResp != nil:
		out.Kind = "DownloadResponse"
	case env.Body.RebootResp != nil:
		out.Kind = "RebootResponse"
	case env.Body.ResetResp != nil:
		out.Kind = "FactoryResetResponse"
	case env.Body.Fault != nil:
		out.Kind = "Fault"
		fc := strings.TrimSpace(env.Body.Fault.Detail.CWMPFault.FaultCode)
		fs := strings.TrimSpace(env.Body.Fault.Detail.CWMPFault.FaultString)
		if fc == "" {
			fc = env.Body.Fault.FaultCode
		}
		if fs == "" {
			fs = env.Body.Fault.FaultString
		}
		out.FaultCode = fc
		out.FaultStr = fs
	default:
		return nil, fmt.Errorf("%w: unrecognized CWMP body", ErrInvalidCWMP)
	}
	return out, nil
}

// BuildInformResponse renders a standards-compliant SOAP InformResponse envelope.
func BuildInformResponse(msgID string) string {
	return wrapSOAP(msgID, `<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>`)
}

// BuildTaskEnvelope renders a TR-069 RPC SOAP request for one queued CPETask.
func BuildTaskEnvelope(msgID string, tk CPETask) string {
	switch tk.Method {
	case RPCGetParamValues:
		var b strings.Builder
		fmt.Fprintf(&b, `<cwmp:GetParameterValues><ParameterNames soap-enc:arrayType="xsd:string[%d]">`, len(tk.GetPaths))
		for _, p := range tk.GetPaths {
			fmt.Fprintf(&b, `<string>%s</string>`, xmlEscape(p))
		}
		b.WriteString(`</ParameterNames></cwmp:GetParameterValues>`)
		return wrapSOAP(msgID, b.String())

	case RPCSetParamValues:
		var b strings.Builder
		fmt.Fprintf(&b, `<cwmp:SetParameterValues><ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[%d]">`, len(tk.SetParams))
		for _, pv := range tk.SetParams {
			tp := pv.Type
			if tp == "" {
				tp = "xsd:string"
			}
			fmt.Fprintf(&b, `<ParameterValueStruct><Name>%s</Name><Value xsi:type="%s">%s</Value></ParameterValueStruct>`,
				xmlEscape(pv.Name), xmlEscape(tp), xmlEscape(pv.Value))
		}
		fmt.Fprintf(&b, `</ParameterList><ParameterKey>%s</ParameterKey></cwmp:SetParameterValues>`, xmlEscape(tk.ID))
		return wrapSOAP(msgID, b.String())

	case RPCDownload:
		ft := tk.FileType
		if ft == "" {
			ft = "1 Firmware Upgrade Image"
		}
		return wrapSOAP(msgID, fmt.Sprintf(
			`<cwmp:Download><CommandKey>%s</CommandKey><FileType>%s</FileType><URL>%s</URL><Username></Username><Password></Password><FileSize>%d</FileSize><TargetFileName></TargetFileName><DelaySeconds>0</DelaySeconds><SuccessURL></SuccessURL><FailureURL></FailureURL></cwmp:Download>`,
			xmlEscape(tk.CommandKey), xmlEscape(ft), xmlEscape(tk.URL), tk.FileSize))

	case RPCReboot:
		return wrapSOAP(msgID, fmt.Sprintf(`<cwmp:Reboot><CommandKey>%s</CommandKey></cwmp:Reboot>`, xmlEscape(tk.CommandKey)))

	case RPCFactoryReset:
		return wrapSOAP(msgID, `<cwmp:FactoryReset/>`)

	default:
		return ""
	}
}

func wrapSOAP(msgID, body string) string {
	if msgID == "" {
		msgID = newHexID("msg")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">` +
		`<soap-env:Header><cwmp:ID soap-env:mustUnderstand="1">` + xmlEscape(msgID) + `</cwmp:ID></soap-env:Header>` +
		`<soap-env:Body>` + body + `</soap-env:Body></soap-env:Envelope>`
}

func xmlEscape(s string) string {
	return html.EscapeString(s)
}

func newHexID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}
