package structs

type Report []struct {
	Filename string `json:"Filename"`
	Title    string `json:"Title"`
	Source   string `json:"Source"`
	Link     string `json:"Link"`
	SHA1     string `json:"SHA-1"`
	Date     string `json:"Date"`
	Year     string `json:"Year"`
}
