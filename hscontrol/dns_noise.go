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
)

var provider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordSetter
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
	domain := viper.GetString("dns.base_domain")
	zone := domain
	txt := setDnsRequest.Value

	if viper.GetString("duckdns.api_token") != "" {
		provider = &duckdns.Provider{APIToken: viper.GetString("duckdns.api_token")}
	}

	if viper.GetString("cloudflare.api_token") != "" {
		zone = subdomainToDomain(domain)
		txt = fmt.Sprintf("\"%s\"", setDnsRequest.Value)
		provider = &cloudflare.Provider{APIToken: viper.GetString("cloudflare.api_token")}
	}

	if provider == nil {
		log.Error().
			Caller().
			Msg("no dns provider setup")
		http.Error(writer, "Internal error", http.StatusInternalServerError)
		return
	}

	records := []libdns.Record{
		{
			Type:  setDnsRequest.Type,
			Name:  setDnsRequest.Name,
			Value: txt,
		},
	}

	// list records
	recs, err := provider.GetRecords(ctx, zone)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not retrieve dns records for: " + domain)
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	var recordExists = false
	relativeName := libdns.RelativeName(setDnsRequest.Name, zone)
	for _, re := range recs {
		if re.Name == relativeName {
			recordExists = true
		}

		log.Info().Msg(fmt.Sprintf("%s %s", re.Type, re.Name))
	}

	if recordExists {
		log.Info().Msg(fmt.Sprintf("Record existed, overridding: %s", setDnsRequest.Name))
		setRecs, err := provider.SetRecords(ctx, zone, records)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Update TXT record error")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}
		for _, re := range setRecs {
			log.Info().Msg(fmt.Sprintf("Updated record: %s", re.Name))
		}

	} else {
		newRecs, err := provider.AppendRecords(ctx, zone, records)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Add TXT record error")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}

		for _, re := range newRecs {
			log.Info().Msg(fmt.Sprintf("Added new %s record set: %s", re.Type, re.Name))
		}
	}

	resp := tailcfg.SetDNSResponse{}
	respBody, _ := json.Marshal(resp)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
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
