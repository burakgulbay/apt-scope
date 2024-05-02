package models

import "github.com/jmoiron/sqlx/types"

type CertStreamItem struct {
	ID                string         `db:"id" json:"id"`
	Domain            string         `db:"domain" json:"domain"`
	Payload           types.JSONText `db:"payload" json:"payload"`
	CreationTime      int64          `db:"creation_time" json:"creation_time"`
	CreationTimestamp string         `db:"creation_timestamp" json:"creation_timestamp"`
	LastSeenTime      int64          `db:"last_seen_time" json:"last_seen_time"`
	LastSeenTimestamp string         `db:"last_seen_timestamp" json:"last_seen_timestamp"`
}

type CertStreamCertificatePayload struct {
	Seen   float64 `json:"seen"`
	Source struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	} `json:"source"`
	CertLink string `json:"cert_link"`
	LeafCert struct {
		Issuer struct {
			C          string `json:"C"`
			L          string `json:"L"`
			O          string `json:"O"`
			CN         string `json:"CN"`
			ST         string `json:"ST"`
			Aggregated string `json:"aggregated"`
		} `json:"issuer"`
		Subject struct {
			CN         string `json:"CN"`
			Aggregated string `json:"aggregated"`
		} `json:"subject"`
		NotAfter   int `json:"not_after"`
		Extensions struct {
			KeyUsage               string `json:"keyUsage"`
			SubjectAltName         string `json:"subjectAltName"`
			BasicConstraints       string `json:"basicConstraints"`
			ExtendedKeyUsage       string `json:"extendedKeyUsage"`
			AuthorityInfoAccess    string `json:"authorityInfoAccess"`
			CertificatePolicies    string `json:"certificatePolicies"`
			SubjectKeyIdentifier   string `json:"subjectKeyIdentifier"`
			AuthorityKeyIdentifier string `json:"authorityKeyIdentifier"`
		} `json:"extensions"`
		NotBefore          int      `json:"not_before"`
		AllDomains         []string `json:"all_domains"`
		Fingerprint        string   `json:"fingerprint"`
		SerialNumber       string   `json:"serial_number"`
		NotAfterStamp      string   `json:"not_after_stamp"`
		NotBeforeStamp     string   `json:"not_before_stamp"`
		SignatureAlgorithm string   `json:"signature_algorithm"`
	} `json:"leaf_cert"`
	CertIndex   int    `json:"cert_index"`
	SeenStamp   string `json:"seen_stamp"`
	UpdateType  string `json:"update_type"`
	MessageType string `json:"message_type"`
}

type CertStreamCertificate struct {
	Fingerprint        string `json:"fingerprint"`
	IssuerC            string `json:"issuer_c"`
	IssuerO            string `json:"issuer_o"`
	IssuerCN           string `json:"issuer_cn"`
	NotBeforeTimestamp string `json:"not_before_timestamp"`
	NotAfterTimestamp  string `json:"not_after_timestamp"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

type AptReport struct {
	ReportName string `json:"report_name"`
}
type AptGroup struct {
	GroupName string `json:"group_name"`
}
