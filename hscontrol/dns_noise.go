package hscontrol

import (
	"encoding/json"
	"fmt"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/libdns/libdns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"io"
	"net/http"
	"strings"
	"tailscale.com/tailcfg"
	"time"
)

var dnsProvider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordSetter
}

func init() {
	viper.SetDefault("acme.dns.propagation_timeout", "10s")
}

func (ns *noiseServer) NoiseSetDnsHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	body, _ := io.ReadAll(req.Body)
	setDnsRequest := tailcfg.SetDNSRequest{}
	if err := json.Unmarshal(body, &setDnsRequest); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse SetDNSRequest")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	log.Info().
		Caller().
		Str("handler", "NoiseSetDnsHandler").
		Any("headers", req.Header).
		Str("NodeKey", setDnsRequest.NodeKey.ShortString()).
		Str("Name", setDnsRequest.Name).
		Str("Type", setDnsRequest.Type).
		Str("Value", setDnsRequest.Value).
		Msg("SetDNSHandler called")

	ctx := req.Context()
	baseDomain := viper.GetString("dns.base_domain")
	dnsZone := subdomainToDomain(baseDomain)

	apiToken := viper.GetString("acme.dns.api_token")
	if apiToken == "" {
		log.Error().
			Caller().
			Msg("Missing HEADSCALE_ACME_DNS_API_TOKEN")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	if strings.HasSuffix(baseDomain, "duckdns.org") {
		dnsZone = baseDomain
		dnsProvider = &duckdns.Provider{APIToken: apiToken}
	} else {
		dnsProvider = &cloudflare.Provider{APIToken: apiToken}
	}

	// list records
	recs, err := dnsProvider.GetRecords(ctx, dnsZone)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not retrieve dns records for zone: " + baseDomain)
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	var existingRecord *libdns.Record
	relativeName := libdns.RelativeName(setDnsRequest.Name, dnsZone)

	for _, re := range recs {
		if re.Name == relativeName {
			existingRecord = &re
		}

		//log.Info().Msg(fmt.Sprintf("%s %s", re.Type, re.Name))
	}

	if existingRecord != nil {
		log.Info().Msg(fmt.Sprintf("TXT record already existed, updating: %s", setDnsRequest.Name))
		existingRecord.Value = setDnsRequest.Value
		setRecs, err := dnsProvider.SetRecords(ctx, dnsZone, []libdns.Record{*existingRecord})
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Update TXT record error")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}
		for _, re := range setRecs {
			log.Info().Msg(fmt.Sprintf("Did updated: %s -> %s", re.Name, re.Value))
		}
	} else {
		newRecs, err := dnsProvider.AppendRecords(ctx, dnsZone, []libdns.Record{
			{
				Type:  setDnsRequest.Type,
				Name:  setDnsRequest.Name,
				Value: setDnsRequest.Value,
			},
		})
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Add TXT record error")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}

		for _, re := range newRecs {
			log.Info().Msg(fmt.Sprintf("Added TXT record %s, Value %s", re.Name, re.Value))
		}
	}

	// Give Cloudflare enough time for dns propagation
	propagationTimeout := viper.GetDuration("acme.dns.propagation_timeout")
	time.Sleep(propagationTimeout)

	resp := tailcfg.SetDNSResponse{}
	respBody, _ := json.Marshal(resp)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(200)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}

func subdomainToDomain(subdomain string) string {
	split := strings.Split(subdomain, ".")
	if len(split) > 2 {
		zoneParts := split[len(split)-2:]
		return strings.Join(zoneParts, ".")
	}

	return subdomain
}
