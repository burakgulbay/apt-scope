package models

type CyberPath struct {
	Id        string `json:"id"`
	IoCSource string `json:"ioc_source"`
	Relation  string `json:"relation"`
	IoCTarget string `json:"ioc_target"`
	Time      int64  `json:"time"`
	Timestamp string `json:"timestamp"`
}
