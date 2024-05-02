package models

import "github.com/jmoiron/sqlx/types"

type PortScanIp struct {
	ID                 string         `db:"id" json:"id"`
	IoCType            string         `db:"ioc_type" json:"ioc_type"`
	IoC                string         `db:"ioc" json:"ioc"`
	Payload            types.JSONText `db:"payload" json:"payload"`
	FirstSeenTime      int64          `db:"first_seen_time" json:"first_seen_time"`
	FirstSeenTimestamp string         `db:"first_seen_timestamp" json:"first_seen_timestamp"`
	LastSeenTime       int64          `db:"last_seen_time" json:"last_seen_time"`
	LastSeenTimestamp  string         `db:"last_seen_timestamp" json:"last_seen_timestamp"`
}

type PortScanDomain struct {
	ID                 string         `db:"id" json:"id"`
	IoCType            string         `db:"ioc_type" json:"ioc_type"`
	IoC                string         `db:"ioc" json:"ioc"`
	Payload            types.JSONText `db:"payload" json:"payload"`
	FirstSeenTime      int64          `db:"first_seen_time" json:"first_seen_time"`
	FirstSeenTimestamp string         `db:"first_seen_timestamp" json:"first_seen_timestamp"`
	LastSeenTime       int64          `db:"last_seen_time" json:"last_seen_time"`
	LastSeenTimestamp  string         `db:"last_seen_timestamp" json:"last_seen_timestamp"`
}

type PortScanPayloadUnmarshalled struct {
	XMLName struct {
		Space string `json:"Space"`
		Local string `json:"Local"`
	} `json:"XMLName"`
	Text             string `json:"Text"`
	Scanner          string `json:"Scanner"`
	Args             string `json:"Args"`
	Start            string `json:"Start"`
	Startstr         string `json:"Startstr"`
	Version          string `json:"Version"`
	Xmloutputversion string `json:"Xmloutputversion"`
	Scaninfo         struct {
		Text        string `json:"Text"`
		Type        string `json:"Type"`
		Protocol    string `json:"Protocol"`
		Numservices string `json:"Numservices"`
		Services    string `json:"Services"`
	} `json:"Scaninfo"`
	Verbose struct {
		Text  string `json:"Text"`
		Level string `json:"Level"`
	} `json:"Verbose"`
	Debugging struct {
		Text  string `json:"Text"`
		Level string `json:"Level"`
	} `json:"Debugging"`
	Host struct {
		Text      string `json:"Text"`
		Starttime string `json:"Starttime"`
		Endtime   string `json:"Endtime"`
		Status    struct {
			Text      string `json:"Text"`
			State     string `json:"State"`
			Reason    string `json:"Reason"`
			ReasonTTL string `json:"ReasonTtl"`
		} `json:"Status"`
		Address struct {
			Text     string `json:"Text"`
			Addr     string `json:"Addr"`
			Addrtype string `json:"Addrtype"`
		} `json:"Address"`
		Hostnames struct {
			Text     string `json:"Text"`
			Hostname struct {
				Text string `json:"Text"`
				Name string `json:"Name"`
				Type string `json:"Type"`
			} `json:"Hostname"`
		} `json:"Hostnames"`
		Ports struct {
			Text string `json:"Text"`
			Port []struct {
				Text     string `json:"Text"`
				Protocol string `json:"Protocol"`
				Portid   string `json:"Portid"`
				State    struct {
					Text      string `json:"Text"`
					State     string `json:"State"`
					Reason    string `json:"Reason"`
					ReasonTTL string `json:"ReasonTtl"`
				} `json:"State"`
				Service struct {
					Text      string   `json:"Text"`
					Name      string   `json:"Name"`
					Product   string   `json:"Product"`
					Version   string   `json:"Version"`
					Extrainfo string   `json:"Extrainfo"`
					Ostype    string   `json:"Ostype"`
					Method    string   `json:"Method"`
					Conf      string   `json:"Conf"`
					Cpe       []string `json:"Cpe"`
				} `json:"Service"`
				Script struct {
					Text   string `json:"Text"`
					ID     string `json:"ID"`
					Output string `json:"Output"`
					Table  struct {
						Text  string      `json:"Text"`
						Key   string      `json:"Key"`
						Table interface{} `json:"Table"`
					} `json:"Table"`
				} `json:"Script"`
			} `json:"Port"`
		} `json:"Ports"`
		Times struct {
			Text   string `json:"Text"`
			Srtt   string `json:"Srtt"`
			Rttvar string `json:"Rttvar"`
			To     string `json:"To"`
		} `json:"Times"`
	} `json:"Host"`
	Runstats struct {
		Text     string `json:"Text"`
		Finished struct {
			Text    string `json:"Text"`
			Time    string `json:"Time"`
			Timestr string `json:"Timestr"`
			Elapsed string `json:"Elapsed"`
			Summary string `json:"Summary"`
			Exit    string `json:"Exit"`
		} `json:"Finished"`
		Hosts struct {
			Text  string `json:"Text"`
			Up    string `json:"Up"`
			Down  string `json:"Down"`
			Total string `json:"Total"`
		} `json:"Hosts"`
	} `json:"Runstats"`
}

type PortScanDetail struct {
	ID             string `db:"id" json:"id"`
	Protocol       string `db:"protocol" json:"protocol"`
	PortNo         string `db:"port_no" json:"port_no"`
	ServiceName    string `db:"service_name" json:"service_name"`
	ServiceProduct string `db:"service_product" json:"service_product"`
	ServiceVersion string `db:"service_version" json:"service_version"`
	ServiceOsType  string `db:"service_os_type" json:"service_os_type"`
}
