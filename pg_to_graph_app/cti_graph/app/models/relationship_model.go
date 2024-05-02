package models

type RelationshipImportRequest struct {
	Offset int `json:"offset"`
}

type AptReportIoCsRequest struct {
	Offset int `json:"offset"`
}

type CertStreamImportRequest struct {
	Offset            int    `json:"offset"`
	ShardingTableName string `json:"sharding_table_name"`
}

type DomainToIp struct {
	Id                string `json:"id"`
	Domain            string `json:"domain"`
	Ip                string `json:"ip"`
	CreationTimestamp string `json:"creation_timestamp"`
	CreationTime      int64  `json:"creation_time"`
}

type DomainToSubdomain struct {
	Id                string `json:"id"`
	Domain            string `json:"domain"`
	Subdomain         string `json:"subdomain"`
	CreationTimestamp string `json:"creation_timestamp"`
	CreationTime      int64  `json:"creation_time"`
}

type SubdomainToIp struct {
	Id                string `json:"id"`
	Subdomain         string `json:"subdomain"`
	Ip                string `json:"ip"`
	CreationTimestamp string `json:"creation_timestamp"`
	CreationTime      int64  `json:"creation_time"`
}

type UrlToDomain struct {
	Id                string `json:"id"`
	Url               string `json:"url"`
	Domain            string `json:"domain"`
	CreationTimestamp string `json:"creation_timestamp"`
	CreationTime      int64  `json:"creation_time"`
}

type UrlToIp struct {
	Id                string `json:"id"`
	Url               string `json:"url"`
	Ip                string `json:"ip"`
	CreationTimestamp string `json:"creation_timestamp"`
	CreationTime      int64  `json:"creation_time"`
}

type UrlToSubdomain struct {
	Id                string `json:"id"`
	Url               string `json:"url"`
	Subdomain         string `json:"subdomain"`
	CreationTimestamp string `json:"creation_timestamp"`
	CreationTime      int64  `json:"creation_time"`
}
