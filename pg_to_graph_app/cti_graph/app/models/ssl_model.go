package models

import (
	"github.com/jmoiron/sqlx/types"
)

type Ssl struct {
	IoC     string         `json:"ioc"`
	Payload types.JSONText `json:"payload"`
}

type SslProfileInfo struct {
	CreationTime      int64         `json:"creation_time"`
	CreationTimestamp string        `json:"creation_timestamp"`
	SslPortInfos      []SslPortInfo `json:"ssl_port_infos"`
}

type SslPortInfo struct {
	Domain       string       `json:"domain"`
	Port         int          `json:"port"`
	Issuer       Issuer       `json:"issuer"`
	CommonNames  []string     `json:"common_names"`
	TlsVersions  []string     `json:"tls_versions"`
	Fingerprints Fingerprints `json:"fingerprints"`
	NotBefore    string       `json:"not_before"`
	NotAfter     string       `json:"not_after"`
}

type Fingerprints struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

type Issuer struct {
	Name         string `json:"name"`
	Country      string `json:"country"`
	Organization string `json:"organization"`
}
