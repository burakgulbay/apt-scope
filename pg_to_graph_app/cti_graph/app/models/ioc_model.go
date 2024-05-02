package models

type IoC struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	IoCType   string `json:"ioc_type"`
	Time      int64  `json:"time"`
	Timestamp string `json:"timestamp"`
}

type AbusechBotnetIpBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type AbusechSslBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"` // aslında içinde sha1 var
	IoCType            string `json:"ioc_type"`
	ListingData        string `json:"listing_date"`
	ListingReason      string `json:"listing_reason"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type CiarmyBadguysBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type DarklistBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type DshieldTop10Blacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}
type EmergingThreatsCompromisedBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type FeodoTrackerBotnetBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	Port               int64  `json:"port"`
	Status             string `json:"status"`
	Hostname           string `json:"hostname"`
	AsNumber           int64  `json:"as_number"`
	AsName             string `json:"as_name"`
	Country            string `json:"country"`
	LastOnline         string `json:"last_online"`
	Malware            string `json:"malware"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubAnudeepAdServers struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubAnudeepCoinMiners struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubAnudeepFacebook struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubBlocklistProjectAbuseBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubBlocklistProjectAdsBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubBlocklistProjectCryptoBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubBlocklistProjectDrugsBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubBlocklistProjectFacebookBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubBlocklistProjectFraudBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubBlocklistProjectGamblingBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubEtherAdressLookupDomainBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubEtherAdressLookupURIBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type GithubAntiSocialEngineer struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type MalwareBazaarHashBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"` // aslında için sha1 var
	IoCType            string `json:"ioc_type"`
	Sha256Hash         string `json:"sha256_hash"`
	Md5Hash            string `json:"md5_hash"`
	Reporter           string `json:"reporter"`
	FileName           string `json:"file_name"`
	FileTypeGuess      string `json:"file_type_guess"`
	MimeType           string `json:"mime_type"`
	Signature          string `json:"signature"`
	Clamav             string `json:"clamav"`
	VtPercent          string `json:"vtpercent"`
	ImpHash            string `json:"imphash"`
	SsDeep             string `json:"ssdeep"`
	Tlsh               string `json:"tlsh"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

// public_dns_info_nameservers_all
type PublicDnsInfoNameservers struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type ThreatfoxBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	ThreadfoxId        string `json:"threadfox_id"`
	OperPort           string `json:"open_port"`
	ThreatType         string `json:"threat_type"`
	FkMalware          string `json:"fk_malware"`
	MalwareAlias       string `json:"malware_alias"`
	MalwarePrintable   string `json:"malware_printable"`
	ConfidenceLevel    string `json:"confidence_level"`
	Refenrece          string `json:"reference"`
	Tags               string `json:"tags"`
	Anonymous          string `json:"anonymous"`
	Reporter           string `json:"reporter"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type TorIp struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type UrlHausAbuseHostBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}

type UrlHausDistributingMalware struct {
	Id                 string  `json:"id"`
	IoC                string  `json:"ioc"`
	IoCType            *string `json:"ioc_type"`
	UrlHausId          int64   `json:"urlhaus_id"`
	DateAdded          string  `json:"dateadded"`
	IoCStatus          string  `json:"iocstatus"`
	LastOnline         string  `json:"lastonline"`
	Threat             string  `json:"threat"`
	Tags               string  `json:"tags"`
	UrlHausLink        string  `json:"urlhaus_link"`
	Reporter           string  `json:"reporter"`
	FirstSeenTime      int64   `json:"first_seen_time"`
	FirstSeenTimestamp string  `json:"first_seen_timestamp"`
	LastSeenTime       int64   `json:"last_seen_time"`
	LastSeenTimestamp  string  `json:"last_seen_timestamp"`
}

type UsomMaliciousUrlBlacklist struct {
	Id                 string `json:"id"`
	IoC                string `json:"ioc"`
	IoCType            string `json:"ioc_type"`
	UsomId             int64  `json:"usom_id"`
	Description        string `json:"description"`
	Source             string `json:"source"`
	FirstSeenTime      int64  `json:"first_seen_time"`
	FirstSeenTimestamp string `json:"first_seen_timestamp"`
	LastSeenTime       int64  `json:"last_seen_time"`
	LastSeenTimestamp  string `json:"last_seen_timestamp"`
}
