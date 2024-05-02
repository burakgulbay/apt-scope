package models

type CyberIoC struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	IoCType   string `json:"ioc_type"`
	Time      int64  `json:"time"`
	Timestamp string `json:"timestamp"`
}
