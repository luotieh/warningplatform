package scanrunner

import (
	"encoding/json"

	sepayload "code.yt-security.com/public/scanengine/payload"

	"vulnscan-backend/pkg/payload"
)

// PayloadAdapter wraps the existing DB-backed payload.Loader to satisfy
// scanengine/payload.Provider interface.
type PayloadAdapter struct {
	loader *payload.Loader
}

func NewPayloadAdapter(loader *payload.Loader) *PayloadAdapter {
	if loader == nil {
		return &PayloadAdapter{}
	}
	return &PayloadAdapter{loader: loader}
}

func (a *PayloadAdapter) GetPayloads(category string) []sepayload.VulnPayload {
	if a.loader == nil {
		return nil
	}
	src := a.loader.GetPayloads(category)
	out := make([]sepayload.VulnPayload, len(src))
	for i, p := range src {
		out[i] = sepayload.VulnPayload{
			Category:    p.Category,
			Name:        p.Name,
			Value:       p.Value,
			Type:        p.Type,
			Databases:   p.Databases,
			Expect:      p.Expect,
			Context:     p.Context,
			Tags:        p.Tags,
			Severity:    p.Severity,
			Description: p.Description,
			Enabled:     p.Enabled,
			SortOrder:   p.SortOrder,
		}
	}
	return out
}

func (a *PayloadAdapter) GetPatterns(category string) []sepayload.PatternEntry {
	if a.loader == nil {
		return nil
	}
	src := a.loader.GetPatterns(category)
	out := make([]sepayload.PatternEntry, len(src))
	for i, p := range src {
		out[i] = sepayload.PatternEntry{
			Name:        p.Name,
			Pattern:     p.Pattern,
			Description: p.Description,
			Severity:    p.Severity,
		}
	}
	return out
}

func (a *PayloadAdapter) GetConfig(category, key string) string {
	if a.loader == nil {
		return ""
	}
	return a.loader.GetConfig(category, key)
}

// convertPayloadSet uses JSON roundtrip for structurally identical types from different packages.
func convertPayloadSet[T any](src any) *T {
	if src == nil {
		return nil
	}
	data, err := json.Marshal(src)
	if err != nil {
		return nil
	}
	var dst T
	if err := json.Unmarshal(data, &dst); err != nil {
		return nil
	}
	return &dst
}

func (a *PayloadAdapter) GetSQLi() *sepayload.SQLiPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.SQLiPayloadSet](a.loader.GetSQLi())
}

func (a *PayloadAdapter) GetXSS() *sepayload.XSSPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.XSSPayloadSet](a.loader.GetXSS())
}

func (a *PayloadAdapter) GetCRLF() *sepayload.CRLFPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.CRLFPayloadSet](a.loader.GetCRLF())
}

func (a *PayloadAdapter) GetHostHeader() *sepayload.HostHeaderPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.HostHeaderPayloadSet](a.loader.GetHostHeader())
}

func (a *PayloadAdapter) GetSSRF() *sepayload.SSRFPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.SSRFPayloadSet](a.loader.GetSSRF())
}

func (a *PayloadAdapter) GetCmdi() *sepayload.CmdiPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.CmdiPayloadSet](a.loader.GetCmdi())
}

func (a *PayloadAdapter) GetLFI() *sepayload.LFIPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.LFIPayloadSet](a.loader.GetLFI())
}

func (a *PayloadAdapter) GetSSTI() *sepayload.SSTIPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.SSTIPayloadSet](a.loader.GetSSTI())
}

func (a *PayloadAdapter) GetXXE() *sepayload.XXEPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.XXEPayloadSet](a.loader.GetXXE())
}

func (a *PayloadAdapter) GetNoSQLi() *sepayload.NoSQLiPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.NoSQLiPayloadSet](a.loader.GetNoSQLi())
}

func (a *PayloadAdapter) GetSensitiveData() *sepayload.SensitiveDataPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.SensitiveDataPayloadSet](a.loader.GetSensitiveData())
}

func (a *PayloadAdapter) GetSessionFixation() *sepayload.SessionFixationPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.SessionFixationPayloadSet](a.loader.GetSessionFixation())
}

func (a *PayloadAdapter) GetHTTPSmuggling() *sepayload.HTTPSmugglingPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.HTTPSmugglingPayloadSet](a.loader.GetHTTPSmuggling())
}

func (a *PayloadAdapter) GetXMLRPC() *sepayload.XMLRPCPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.XMLRPCPayloadSet](a.loader.GetXMLRPC())
}

func (a *PayloadAdapter) GetDirTraversal() *sepayload.DirTraversalPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.DirTraversalPayloadSet](a.loader.GetDirTraversal())
}

func (a *PayloadAdapter) GetOpenRedirect() *sepayload.OpenRedirectPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.OpenRedirectPayloadSet](a.loader.GetOpenRedirect())
}

func (a *PayloadAdapter) GetFileUpload() *sepayload.FileUploadPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.FileUploadPayloadSet](a.loader.GetFileUpload())
}

func (a *PayloadAdapter) GetDeserialization() *sepayload.DeserializationPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.DeserializationPayloadSet](a.loader.GetDeserialization())
}

func (a *PayloadAdapter) GetAuthBypass() *sepayload.AuthBypassPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.AuthBypassPayloadSet](a.loader.GetAuthBypass())
}

func (a *PayloadAdapter) GetSubdomainTakeover() *sepayload.SubdomainTakeoverPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.SubdomainTakeoverPayloadSet](a.loader.GetSubdomainTakeover())
}

func (a *PayloadAdapter) GetClickjacking() *sepayload.ClickjackingPayloadSet {
	if a.loader == nil {
		return nil
	}
	return convertPayloadSet[sepayload.ClickjackingPayloadSet](a.loader.GetClickjacking())
}
