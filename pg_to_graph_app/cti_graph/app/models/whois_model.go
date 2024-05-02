package models

type WhoisDomain struct {
	Id                    string `db:"id" json:"id"`
	DataYear              int    `db:"data_year" json:"data_year"`
	DataHash              string `db:"data_hash" json:"data_hash"`
	Num                   string `db:"num" json:"num"`
	DomainName            string `db:"domain_name" json:"domain_name"`
	QueryTime             string `db:"query_time" json:"query_time"`
	CreateDate            string `db:"create_date" json:"create_date"`
	UpdateDate            string `db:"update_date" json:"update_date"`
	ExpiryDate            string `db:"expiry_date" json:"expiry_date"`
	DomainRegistrarId     string `db:"domain_registrar_id" json:"domain_registrar_id"`
	DomainRegistrarName   string `db:"domain_registrar_name" json:"domain_registrar_name"`
	DomainRegistrarWhois  string `db:"domain_registrar_whois" json:"domain_registrar_whois"`
	DomainRegistrarUrl    string `db:"domain_registrar_url" json:"domain_registrar_url"`
	RegistrantName        string `db:"registrant_name" json:"registrant_name"`
	RegistrantCompany     string `db:"registrant_company" json:"registrant_company"`
	RegistrantAddress     string `db:"registrant_address" json:"registrant_address"`
	RegistrantCity        string `db:"registrant_city" json:"registrant_city"`
	RegistrantState       string `db:"registrant_state" json:"registrant_state"`
	RegistrantZip         string `db:"registrant_zip" json:"registrant_zip"`
	RegistrantCountry     string `db:"registrant_country" json:"registrant_country"`
	RegistrantEmail       string `db:"registrant_email" json:"registrant_email"`
	RegistrantPhone       string `db:"registrant_phone" json:"registrant_phone"`
	RegistrantFax         string `db:"registrant_fax" json:"registrant_fax"`
	AdministrativeName    string `db:"administrative_name" json:"administrative_name"`
	AdministrativeCompany string `db:"administrative_company" json:"administrative_company"`
	AdministrativeAddress string `db:"administrative_address" json:"administrative_address"`
	AdministrativeCity    string `db:"administrative_city" json:"administrative_city"`
	AdministrativeState   string `db:"administrative_state" json:"administrative_state"`
	AdministrativeZip     string `db:"administrative_zip" json:"administrative_zip"`
	AdministrativeCountry string `db:"administrative_country" json:"administrative_country"`
	AdministrativeEmail   string `db:"administrative_email" json:"administrative_email"`
	AdministrativePhone   string `db:"administrative_phone" json:"administrative_phone"`
	AdministrativeFax     string `db:"administrative_fax" json:"administrative_fax"`
	TechnicalName         string `db:"technical_name" json:"technical_name"`
	TechnicalCompany      string `db:"technical_company" json:"technical_company"`
	TechnicalAddress      string `db:"technical_address" json:"technical_address"`
	TechnicalCity         string `db:"technical_city" json:"technical_city"`
	TechnicalState        string `db:"technical_state" json:"technical_state"`
	TechnicalZip          string `db:"technical_zip" json:"technical_zip"`
	TechnicalCountry      string `db:"technical_country" json:"technical_country"`
	TechnicalEmail        string `db:"technical_email" json:"technical_email"`
	TechnicalPhone        string `db:"technical_phone" json:"technical_phone"`
	TechnicalFax          string `db:"technical_fax" json:"technical_fax"`
	BillingName           string `db:"billing_name" json:"billing_name"`
	BillingCompany        string `db:"billing_company" json:"billing_company"`
	BillingAddress        string `db:"billing_address" json:"billing_address"`
	BillingCity           string `db:"billing_city" json:"billing_city"`
	BillingState          string `db:"billing_state" json:"billing_state"`
	BillingZip            string `db:"billing_zip" json:"billing_zip"`
	BillingCountry        string `db:"billing_country" json:"billing_country"`
	BillingEmail          string `db:"billing_email" json:"billing_email"`
	BillingPhone          string `db:"billing_phone" json:"billing_phone"`
	BillingFax            string `db:"billing_fax" json:"billing_fax"`
	NameServer1           string `db:"name_server_1" json:"name_server_1"`
	NameServer2           string `db:"name_server_2" json:"name_server_2"`
	NameServer3           string `db:"name_server_3" json:"name_server_3"`
	NameServer4           string `db:"name_server_4" json:"name_server_4"`
	DomainStatus1         string `db:"domain_status_1" json:"domain_status_1"`
	DomainStatus2         string `db:"domain_status_2" json:"domain_status_2"`
	DomainStatus3         string `db:"domain_status_3" json:"domain_status_3"`
	DomainStatus4         string `db:"domain_status_4" json:"domain_status_4"`
	CreationTime          int64  `db:"creation_time" json:"creation_time"`
	CreationTimestamp     string `db:"creation_timestamp" json:"creation_timestamp"`
	LastSeenTime          int64  `db:"last_seen_time" json:"last_seen_time"`
	LastSeenTimestamp     string `db:"last_seen_timestamp" json:"lasr_seen_timestamp"`
}

type WhoisIp struct {
	Id                 string `json:"id"`
	DataYear           int    `json:"data_year"`
	DataHash           string `json:"data_hash"`
	IpAddress          string `json:"ipv4_address"`
	Noc                string `json:"noc"`
	Inetnum            string `json:"inetnum"`
	Netname            string `json:"netname"`
	Descr              string `json:"descr"`
	Country            string `json:"country"`
	Organization       string `json:"organization"`
	AdminC             string `json:"admin_c"`
	TechC              string `json:"tech_c"`
	MntLower           string `json:"mnt_lower"`
	Status             string `json:"status"`
	MntBy              string `json:"mnt_by"`
	Created            string `json:"created"`
	LastModified       string `json:"last_modified"`
	Source             string `json:"source"`
	MntRoutes          string `json:"mnt_routes"`
	PersonName         string `json:"person_name"`
	PersonAddress      string `json:"person_address"`
	PersonPhone        string `json:"person_phone"`
	PersonAbuseMailbox string `json:"person_abuse_mailbox"`
	PersonNicHdl       string `json:"person_nic_hdl"`
	PersonMntBy        string `json:"person_mnt_by"`
	PersonCreated      string `json:"person_created"`
	PersonLastModified string `json:"person_last_modified"`
	PersonSource       string `json:"person_source"`
	RouteRoute         string `json:"route_route"`
	RouteDescr         string `json:"route_descr"`
	RouteOrigin        string `json:"route_origin"`
	RouteMntBy         string `json:"route_mnt_by"`
	RouteCreated       string `json:"route_created"`
	RouteLastModified  string `json:"route_last_modified"`
	RouteSource        string `json:"route_source"`
	CreationTime       int64  `json:"creation_time"`
	CreationTimestamp  string `json:"creation_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}
