package appid

import (
	"sort"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// LayeredView ports protocol_adapters/layers.layered_view for wire-only observations: the Go backend has
// no decrypted evidence yet, so the inner layer is always absent and the effective verdict is the outer one.
func LayeredView(pack *content.Pack, transport string, client, server *contracts.Observation, verdict *Verdict, captureQuality string) map[string]interface{} {
	outer := verdict
	var encryption *string
	for _, o := range []*contracts.Observation{client, server} {
		if o != nil && o.Encryption != nil {
			encryption = o.Encryption
			break
		}
	}
	attr := outer.Attribution
	var activityValue interface{}
	if attr != nil {
		activityValue = attr["activity"]
	}
	var outerProtocol *string
	if outer.ClientProtocol != nil {
		outerProtocol = outer.ClientProtocol
	} else {
		outerProtocol = outer.ServerProtocol
	}
	var chain []string
	add := func(l *string) {
		if l != nil && *l != "" && !containsString(chain, *l) {
			chain = append(chain, *l)
		}
	}
	add(encryption)
	if outerProtocol != nil && (encryption == nil || *outerProtocol != *encryption) {
		add(outerProtocol)
	}
	if outer.Identified(pack) {
		app := outer.App
		add(&app)
	}
	if chain == nil {
		chain = []string{}
	}
	var encryptionView interface{}
	if encryption != nil {
		alpn := map[string]bool{}
		asserted := false
		for _, o := range []*contracts.Observation{client, server} {
			if o == nil {
				continue
			}
			for _, a := range o.OfferedALPN {
				alpn[a] = true
			}
			for _, e := range o.Evidence {
				if e.Field == "hostname" {
					asserted = true
				}
			}
		}
		var names []string
		for a := range alpn {
			names = append(names, a)
		}
		sort.Strings(names)
		if names == nil {
			names = []string{}
		}
		encryptionView = map[string]interface{}{"protocol": *encryption, "offered_alpn": names, "server_name_asserted": asserted, "version": nil}
	}
	outerProtoValue := outerProtocol
	if outerProtoValue == nil {
		outerProtoValue = encryption
	}
	var provider, affiliation interface{}
	if attr != nil {
		provider, affiliation = attr["provider"], attr["kind"]
	}
	return map[string]interface{}{
		"version":    1,
		"transport":  transport,
		"outer":      map[string]interface{}{"protocol": outerProtoValue, "app": outer.App, "status": outer.Status},
		"encryption": encryptionView,
		"inner":      nil,
		"application": map[string]interface{}{"name": outer.App, "category": outer.Category, "status": outer.Status,
			"basis": identityBasis(pack, outer, client, server), "provider": provider, "affiliation": affiliation, "activity": activityValue},
		"decryption":      nil,
		"capture_quality": captureQuality,
		"chain":           chain,
		"claims":          claims(client, server),
	}
}

func identityBasis(pack *content.Pack, v *Verdict, observations ...*contracts.Observation) string {
	if v == nil || !v.Identified(pack) {
		return "none"
	}
	if containsString(v.Reasons, HostReason) {
		return "client_assertion"
	}
	if v.BaseApp != nil {
		return "configured_rule"
	}
	for _, o := range observations {
		if o == nil {
			continue
		}
		for _, e := range o.Evidence {
			if e.Strength == "configured_mapping" || e.Strength == "configured_signature" {
				return "configured_rule"
			}
		}
	}
	return "structural"
}

func claims(observations ...*contracts.Observation) []map[string]interface{} {
	seen := map[[3]string]bool{}
	out := []map[string]interface{}{}
	for _, o := range observations {
		if o == nil {
			continue
		}
		for _, e := range o.Evidence {
			if e.Strength == "asserted" || e.Strength == "offered" || e.Strength == "derived" {
				key := [3]string{e.Field, e.Source, e.Strength}
				if !seen[key] {
					seen[key] = true
					out = append(out, map[string]interface{}{"field": e.Field, "source": e.Source, "strength": e.Strength})
				}
			}
		}
	}
	return out
}
