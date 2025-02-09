package hscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/libdns/libdns"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"io"
	"net/http"
	"tailscale.com/tailcfg"
)

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
	zone := domain + "."
	var provider interface{}
	if viper.GetString("duckdns.api_token") != "" {
		provider = duckdns.Provider{APIToken: viper.GetString("duckdns.api_token")}
	}

	if viper.GetString("cloudflare.api_token") != "" {
		provider = cloudflare.Provider{APIToken: viper.GetString("cloudflare.api_token")}
	}

	if provider == nil {
		log.Error().
			Caller().
			Msg("no libdns provider setup")
		http.Error(writer, "Internal error", http.StatusInternalServerError)
		return
	}

	// list records
	recs, err := libdnsGetRecords(provider, ctx, zone)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Could not retrieve dns records for: " + domain)
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	var hasSet = false
	for _, re := range recs {
		if re.Value == setDnsRequest.Value {
			hasSet = true
		}

		if re.Name == setDnsRequest.Name {
			hasSet = true
		}

		log.Info().Msg(fmt.Sprintf("%s %s %s", re.Type, re.Name, re.Value))
	}

	if !hasSet {
		newRecs, err := libdnsAppendRecords(provider, ctx, zone, []libdns.Record{
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
				Msg("Can not set dns records")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			return
		}

		for _, re := range newRecs {
			log.Info().Msg(fmt.Sprintf("New %s record set: %s", re.Type, re.Name))
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

func libdnsGetRecords(provider interface{}, ctx context.Context, zone string) ([]libdns.Record, error) {
	if p, ok := provider.(libdns.RecordGetter); ok {
		return p.GetRecords(ctx, zone)
	}

	return nil, errors.New("invalid libdns provider")
}

func libdnsAppendRecords(provider interface{}, ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if p, ok := provider.(libdns.RecordAppender); ok {
		return p.AppendRecords(ctx, zone, recs)
	}

	return nil, errors.New("invalid libdns provider")
}
