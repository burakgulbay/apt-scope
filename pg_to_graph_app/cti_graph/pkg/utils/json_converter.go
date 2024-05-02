package utils

import (
	"cti_graph/app/models"
	"encoding/json"
	"errors"

	"github.com/jmoiron/sqlx/types"

	twitterscraper "github.com/n0madic/twitter-scraper"
)

func UnmarshallTwitterPayload(rawMessagePolicy types.JSONText) ([]twitterscraper.TweetResult, error) {
	var tweetResult []twitterscraper.TweetResult
	err := json.Unmarshal([]byte(rawMessagePolicy), &tweetResult)
	if err != nil {
		return nil, errors.New("twitter payload structure is malformed")
	}

	return tweetResult, nil
}

func UnmarshallSslPayload(rawMessagePolicy types.JSONText) (*models.SslProfileInfo, error) {
	var sslProfileInfo models.SslProfileInfo
	err := json.Unmarshal([]byte(rawMessagePolicy), &sslProfileInfo)
	if err != nil {
		return nil, errors.New("ssl payload structure is malformed")
	}

	return &sslProfileInfo, nil
}

func UnmarshallPortScanPayload(rawMessage types.JSONText) (*models.PortScanPayloadUnmarshalled, error) {

	var portScanPayloadUnmarshalled models.PortScanPayloadUnmarshalled
	err := json.Unmarshal([]byte(rawMessage), &portScanPayloadUnmarshalled)
	if err != nil {
		return nil, errors.New("port scan structure is malformed")
	}

	return &portScanPayloadUnmarshalled, nil
}

func UnmarshallCertStreamPayload(rawMessage types.JSONText) (*models.CertStreamCertificatePayload, error) {

	var certStreamPayloadUnmarshalled models.CertStreamCertificatePayload
	err := json.Unmarshal([]byte(rawMessage), &certStreamPayloadUnmarshalled)
	if err != nil {
		return nil, errors.New("cert stream structure is malformed")
	}

	return &certStreamPayloadUnmarshalled, nil
}
