package repositories

import (
	"cti_graph/app/models"
	"cti_graph/pkg/utils"
	"strings"

	"github.com/google/uuid"
	twitterscraper "github.com/n0madic/twitter-scraper"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

var GraphRepo GraphNeo4jRepository

type GraphRepository interface {
	CreateDomain(domain string) (err error)

	CreateSubdomain(subdomain string)

	CreateIp(ip string) (err error)

	CreateIpPortScan(portScanIp *models.PortScanIp) (err error)

	CreateDomainPortScan(portScanDomain *models.PortScanDomain) (err error)

	FindIpPortScan(ipPortScanId string) (ioc *models.PortScanIp, err error)

	MergeIoCToIpPortScan(ioc string, portScanIp models.PortScanIp) (err error)

	FindDomainPortScan(domainPortScanId string) (ioc *models.PortScanDomain, err error)

	MergeIoCToDomainPortScan(ioc string, portScanDomain models.PortScanDomain) (err error)

	CreatePortScanDetail(portScanDetail *models.PortScanDetail) (err error)

	CreateUrl(url string) (err error)

	FindTwitterUser(name string) (ioc *models.CyberIoC, err error)

	FindNode(name string) (ioc *models.CyberIoC, err error)

	FindTweet(name string) (ioc *models.CyberIoC, err error)

	FindSslCertificate(name string) (ioc *models.CyberIoC, err error)

	MergeDomainToIp(domainToIp *models.DomainToIp) (err error)

	MergeDomainToSubdomain(domainToSubdomain *models.DomainToSubdomain) (err error)

	MergeSubdomainToIp(subdomainToIp *models.SubdomainToIp) (err error)

	MergeUrlToDomain(urlToDomain *models.UrlToDomain) (err error)

	MergeUrlToIp(urlToIp *models.UrlToIp) (err error)

	MergeUrlToSubdomain(urlToSubdomain *models.UrlToSubdomain) (err error)

	CreateTweet(tweet twitterscraper.TweetResult) (err error)

	CreateSslCertificate(sslPortInfo models.SslPortInfo) (err error)

	MergeIoCToTweet(ioc string, tweet twitterscraper.TweetResult) (err error)

	CreateTwitterUsername(twitterUsername string) (err error)

	MergeTweetToTwitterUsername(tweetId string, twitterUsername string) (err error)

	MergeDomainToSslCertificate(domain string, sslCertificateSha256 string) (err error)

	MergeSubdomainToSslCertificate(subdomain string, sslCertificateSha256 string) (err error)

	CreatePortOfSSL(port string) (id string, err error)

	MergePortIdAndSslSha256(portId string, sslCertificateSha256 string) (err error)

	CreateIssuerName(issuerName string) (id string, err error)

	MergeIssuerNameAndSslSha256(issuerName string, sslCertificateSha256 string) (err error)

	CreateIssuerCountry(issuerCountry string) (id string, err error)

	MergeIssuerCountryAndSslSha256(issuerCountry string, sslCertificateSha256 string) (err error)

	CreateIssuerOrganization(issuerOrganization string) (id string, err error)

	MergeIssuerOrganizationAndSslSha256(issuerOrganization string, sslCertificateSha256 string) (err error)

	FindWhoisDomain(whoisId string) (ioc *models.WhoisDomain, err error)

	CreateWhoisDomain(whois *models.WhoisDomain) (err error)

	MergeDomainToWhoisDomain(whoisId string, domain string) (err error)

	FindWhoisIp(whoisId string) (ioc *models.WhoisIp, err error)

	CreateWhoisIp(whoisIp *models.WhoisIp) (err error)

	MergeIpToWhoisIp(whoisId string, ip string) (err error)

	FindAsn(asnCode string) (asn *models.Asn, err error)

	CreateAsn(asnCode string) (err error)

	MergeIpToAsn(ip string, asnCode string) (err error)

	MergeReporterPlatformToIoC(reporterPlatform string, ioc string) (err error)

	CreateReporterPlatform(reporterPlatform string) (err error)

	FindReporterPlatform(name string) (reporterPlatform *models.ReporterPlatform, err error)

	FindIoC(name string) (ioc *models.CyberIoC, err error)

	CreateAbusechBotnetIpBlacklist(ioc models.AbusechBotnetIpBlacklist) (err error)

	CreateAbusechSslBlacklist(ioc models.AbusechSslBlacklist) (err error)

	CreateCiarmyBadguysBlacklist(ioc models.CiarmyBadguysBlacklist) (err error)

	CreateDarklistBlacklist(ioc models.DarklistBlacklist) (err error)

	CreateDshieldTop10Blacklist(ioc models.DshieldTop10Blacklist) (err error)

	CreateEmergingThreatsCompromisedBlacklist(ioc models.EmergingThreatsCompromisedBlacklist) (err error)

	CreateFeodoTrackerBotnetBlacklist(ioc models.FeodoTrackerBotnetBlacklist) (err error)

	CreateGithubAnudeepAdServers(ioc models.GithubAnudeepAdServers) (err error)

	CreateGithubAnudeepCoinMiners(ioc models.GithubAnudeepCoinMiners) (err error)

	CreateGithubAnudeepFacebook(ioc models.GithubAnudeepFacebook) (err error)

	CreateGithubBlocklistProjectAbuseBlacklist(ioc models.GithubBlocklistProjectAbuseBlacklist) (err error)

	CreateGithubBlocklistProjectAdsBlacklist(ioc models.GithubBlocklistProjectAdsBlacklist) (err error)

	CreateGithubBlocklistProjectCryptoBlacklist(ioc models.GithubBlocklistProjectCryptoBlacklist) (err error)

	CreateGithubBlocklistProjectDrugsBlacklist(ioc models.GithubBlocklistProjectDrugsBlacklist) (err error)

	CreateGithubBlocklistProjectFacebookBlacklist(ioc models.GithubBlocklistProjectFacebookBlacklist) (err error)

	CreateGithubBlocklistProjectFraudBlacklist(ioc models.GithubBlocklistProjectFraudBlacklist) (err error)

	CreateGithubBlocklistProjectGamblingBlacklist(ioc models.GithubBlocklistProjectGamblingBlacklist) (err error)

	CreateGithubEtherAdressLookupDomainBlacklist(ioc models.GithubEtherAdressLookupDomainBlacklist) (err error)

	CreateGithubEtherAdressLookupURIBlacklist(ioc models.GithubEtherAdressLookupURIBlacklist) (err error)

	CreateGithubAntiSocialEngineer(ioc models.GithubAntiSocialEngineer) (err error)

	CreateMalwareBazaarHashBlacklist(ioc models.MalwareBazaarHashBlacklist) (err error)

	CreatePublicDnsInfoNameservers(ioc models.PublicDnsInfoNameservers) (err error)

	CreateThreatfoxBlacklist(ioc models.ThreatfoxBlacklist) (err error)

	CreateTorIp(ioc models.TorIp) (err error)

	CreateUrlHausAbuseHostBlacklist(ioc models.UrlHausAbuseHostBlacklist) (err error)

	CreateUrlHausDistributingMalware(ioc models.UrlHausDistributingMalware) (err error)

	CreateUsomMaliciousUrlBlacklist(ioc models.UsomMaliciousUrlBlacklist) (err error)

	MergePortScanDetailToIpPortScan(portScanDetailId string, ipPortScanListId string) (err error)

	FindCertStreamCertificate(fingerprint string) (ioc *models.CertStreamCertificate, err error)

	CreateCertStreamCertificate(certStreamCertificate models.CertStreamCertificate) (err error)

	MergeCertStreamCertificateAndDomain(certStreamCertificate models.CertStreamCertificate, domain string) (err error)

	CreateIoC(ioc string, iocType string) (err error)

	CreateAptReport(aptReport string) (err error)

	FindIoCWithIoCType(iocname string, ioctype string) (ioc *models.IoC, err error)

	MergeAptReportToIoC(aptreport string, ioc string, ioctype string) (err error)

	FindAptReport(aptreport string) (err error)

	FindAptGroup(aptGroup string) (err error)

	MergeAptGroups(*models.AptGroup, *models.AptGroup) (err error)

	CreateAptGroup(aptGroup string) (err error)

	MergeAptReportToAptGroup(aptreport string, aptGroup string) (err error)
}

type GraphNeo4jRepository struct {
	Driver neo4j.Driver
}

func (u *GraphNeo4jRepository) CreateDomain(domain string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistDomain(tx, domain)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistDomain(tx neo4j.Transaction, domain string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $name, ioc_type: $ioc_type, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      domain,
		"ioc_type":  "domain",
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateIoC(ioc string, iocType string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistIoC(tx, ioc, iocType)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistIoC(tx neo4j.Transaction, ioc string, iocType string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $name, ioc_type: $ioc_type, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      ioc,
		"ioc_type":  iocType,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateAptReport(aptReport string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistAptReport(tx, aptReport)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistAptReport(tx neo4j.Transaction, aptReport string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:AptReport {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      aptReport,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateAptGroup(aptGroup string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistAptGroup(tx, aptGroup)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistAptGroup(tx neo4j.Transaction, aptGroup string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:AptGroup {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      aptGroup,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateSubdomain(subdomain string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistSubdomain(tx, subdomain)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistSubdomain(tx neo4j.Transaction, subdomain string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $name, ioc_type: $ioc_type, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      subdomain,
		"ioc_type":  "subdomain",
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateIp(ip string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistIp(tx, ip)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistIp(tx neo4j.Transaction, ip string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $name, ioc_type: $ioc_type, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      ip,
		"ioc_type":  "ip",
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateIpPortScan(portScanIp models.PortScanIp) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistPortScanIp(tx, portScanIp)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistPortScanIp(tx neo4j.Transaction, portScanIp models.PortScanIp) (interface{}, error) {
	query := "CREATE (:PortScanIp {id: $id, name: $name, ioc_type: $ioc_type, payload: $payload, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp: $last_seen_timestamp})"
	parameters := map[string]interface{}{
		"id":                   portScanIp.ID,
		"name":                 portScanIp.IoC,
		"ioc_type":             "ip",
		"payload":              portScanIp.Payload.String(),
		"first_seen_time":      portScanIp.FirstSeenTime,
		"first_seen_timestamp": portScanIp.FirstSeenTimestamp,
		"last_seen_time":       portScanIp.LastSeenTime,
		"last_seen_timestamp":  portScanIp.LastSeenTimestamp,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateDomainPortScan(portScanDomain models.PortScanDomain) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistPortScanDomain(tx, portScanDomain)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistPortScanDomain(tx neo4j.Transaction, portScanDomain models.PortScanDomain) (interface{}, error) {
	query := "CREATE (:PortScanDomain {id: $id, name: $name, ioc_type: $ioc_type, payload: $payload, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp: $last_seen_timestamp})"
	parameters := map[string]interface{}{
		"id":                   portScanDomain.ID,
		"name":                 portScanDomain.IoC,
		"ioc_type":             "domain",
		"payload":              portScanDomain.Payload.String(),
		"first_seen_time":      portScanDomain.FirstSeenTime,
		"first_seen_timestamp": portScanDomain.FirstSeenTimestamp,
		"last_seen_time":       portScanDomain.LastSeenTime,
		"last_seen_timestamp":  portScanDomain.LastSeenTimestamp,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateUrl(url string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistUrl(tx, url)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistUrl(tx neo4j.Transaction, url string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $name, ioc_type: $ioc_type, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      url,
		"ioc_type":  "url",
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) FindNode(name string) (ioc *models.CyberIoC, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findNode(tx, name)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.CyberIoC)
	return ioc, err
}

func (u *GraphNeo4jRepository) findNode(tx neo4j.Transaction, name string) (*models.CyberIoC, error) {

	result, err := tx.Run(
		"MATCH (i:IoC {name: $name}) RETURN i.id as id, i.name AS name, i.ioc_type AS ioc_type, i.time as time, i.timestamp as timestamp",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	iocType, _ := record.Get("ioc_type")
	if iocType == nil {
		iocType, _ = "", false
	} else {
		iocType, _ = record.Get("ioc_type")
	}
	time, _ := record.Get("time")
	timestamp, _ := record.Get("timestamp")

	return &models.CyberIoC{
		Id:        id.(string),
		Name:      name,
		IoCType:   iocType.(string),
		Time:      time.(int64),
		Timestamp: timestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindIoC(name string) (ioc *models.IoC, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findIoC(tx, name)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.IoC)
	return ioc, err
}

func (u *GraphNeo4jRepository) findIoC(tx neo4j.Transaction, name string) (*models.IoC, error) {

	result, err := tx.Run(
		"MATCH (i:IoC {name: $name}) RETURN i.id as id, i.ioc AS ioc, i.ioc_type AS ioc_type",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	iocType, _ := record.Get("ioc_type")

	return &models.IoC{
		Id:      id.(string),
		Name:    name,
		IoCType: iocType.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindIoCWithIoCType(iocname string, ioctype string) (ioc *models.IoC, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findIoCWithIoCType(tx, iocname, ioctype)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.IoC)
	return ioc, err
}

func (u *GraphNeo4jRepository) findIoCWithIoCType(tx neo4j.Transaction, name string, ioctype string) (*models.IoC, error) {

	result, err := tx.Run(
		"MATCH (i:IoC) WHERE i.name = $name AND i.ioc_type = $ioc_type RETURN i.id as id, i.ioc AS ioc, i.ioc_type AS ioc_type",
		map[string]interface{}{
			"name":     name,
			"ioc_type": ioctype,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")

	return &models.IoC{
		Id:      id.(string),
		Name:    name,
		IoCType: ioctype,
	}, nil
}

func (u *GraphNeo4jRepository) FindDns(name string) (ioc *models.PublicDnsInfoNameservers, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findDns(tx, name)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.PublicDnsInfoNameservers)
	return ioc, err
}

func (u *GraphNeo4jRepository) findDns(tx neo4j.Transaction, name string) (*models.PublicDnsInfoNameservers, error) {

	result, err := tx.Run(
		"MATCH (i:Dns {name: $name}) RETURN i.id as id, i.name AS name, i.ioc_type AS ioc_type",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	iocType, _ := record.Get("ioc_type")

	return &models.PublicDnsInfoNameservers{
		Id:      id.(string),
		IoC:     name,
		IoCType: iocType.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindTor(name string) (ioc *models.TorIp, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findTor(tx, name)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.TorIp)
	return ioc, err
}

func (u *GraphNeo4jRepository) findTor(tx neo4j.Transaction, name string) (*models.TorIp, error) {

	result, err := tx.Run(
		"MATCH (i:Tor {ioc: $name}) RETURN i.id as id, i.ioc AS ioc, i.ioc_type AS ioc_type",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	iocType, _ := record.Get("ioc_type")

	return &models.TorIp{
		Id:      id.(string),
		IoC:     name,
		IoCType: iocType.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindReporterPlatform(name string) (reporterPlatform *models.ReporterPlatform, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findReporterPlatform(tx, name)
	})
	if result == nil {
		return nil, err
	}
	reporterPlatform = result.(*models.ReporterPlatform)
	return reporterPlatform, err
}

func (u *GraphNeo4jRepository) findReporterPlatform(tx neo4j.Transaction, name string) (*models.ReporterPlatform, error) {

	result, err := tx.Run(
		"MATCH (i:ReporterPlatform {name: $name}) RETURN i.id as id, i.name AS name",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")

	return &models.ReporterPlatform{
		Id:   id.(string),
		Name: name,
	}, nil
}

func (u *GraphNeo4jRepository) CreateReporterPlatform(reporterPlatform string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistReporterPlatform(tx, reporterPlatform)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistReporterPlatform(tx neo4j.Transaction, url string) (interface{}, error) {

	query := "CREATE (:ReporterPlatform {id: $id, name: $name})"
	parameters := map[string]interface{}{
		"id":   uuid.New().String(),
		"name": url,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) MergeReporterPlatformToIoC(reporterPlatform string, ioc string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeReporterPlatformToIoC(tx, reporterPlatform, ioc)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeReporterPlatformToIoC(tx neo4j.Transaction, reporterPlatform string, ioc string) (err error) {

	_, err = tx.Run(
		"MATCH (n:ReporterPlatform {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:REPORT]-(m)",
		map[string]interface{}{
			"name1": reporterPlatform,
			"name2": ioc,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeReporterPlatformToDns(reporterPlatform string, ioc string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeReporterPlatformToDns(tx, reporterPlatform, ioc)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeReporterPlatformToDns(tx neo4j.Transaction, reporterPlatform string, dns string) (err error) {

	_, err = tx.Run(
		"MATCH (n:ReporterPlatform {name: $name1}), (m:Dns {name: $name2}) MERGE (n)-[:REPORT]-(m)",
		map[string]interface{}{
			"name1": reporterPlatform,
			"name2": dns,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeReporterPlatformToTor(reporterPlatform string, ioc string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeReporterPlatformToTor(tx, reporterPlatform, ioc)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeReporterPlatformToTor(tx neo4j.Transaction, reporterPlatform string, tor string) (err error) {

	_, err = tx.Run(
		"MATCH (n:ReporterPlatform {name: $name1}), (m:Tor {name: $name2}) MERGE (n)-[:REPORT]-(m)",
		map[string]interface{}{
			"name1": reporterPlatform,
			"name2": tor,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) CreateAbusechBotnetIpBlacklist(ioc models.AbusechBotnetIpBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistAbusechBotnetIpBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistAbusechBotnetIpBlacklist(tx neo4j.Transaction, ioc models.AbusechBotnetIpBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateAbusechSslBlacklist(ioc models.AbusechSslBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistAbusechSslBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistAbusechSslBlacklist(tx neo4j.Transaction, ioc models.AbusechSslBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateCiarmyBadguysBlacklist(ioc models.CiarmyBadguysBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistCiarmyBadguysBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistCiarmyBadguysBlacklist(tx neo4j.Transaction, ioc models.CiarmyBadguysBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateDarklistBlacklist(ioc models.DarklistBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistDarklistBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistDarklistBlacklist(tx neo4j.Transaction, ioc models.DarklistBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateDshieldTop10Blacklist(ioc models.DshieldTop10Blacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistDshieldTop10Blacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistDshieldTop10Blacklist(tx neo4j.Transaction, ioc models.DshieldTop10Blacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateEmergingThreatsCompromisedBlacklist(ioc models.EmergingThreatsCompromisedBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistEmergingThreatsCompromisedBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistEmergingThreatsCompromisedBlacklist(tx neo4j.Transaction, ioc models.EmergingThreatsCompromisedBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateFeodoTrackerBotnetBlacklist(ioc models.FeodoTrackerBotnetBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistFeodoTrackerBotnetBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistFeodoTrackerBotnetBlacklist(tx neo4j.Transaction, ioc models.FeodoTrackerBotnetBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type,port: $port, status: $status, hostname:	$hostname, as_number: $as_number, as_name: $as_name, country: $country,	last_online: $last_online, malware:	$malware, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"port":                 ioc.Port,
		"status":               ioc.Status,
		"hostname":             ioc.Hostname,
		"as_number":            ioc.AsNumber,
		"as_name":              ioc.AsName,
		"country":              ioc.Country,
		"last_online":          ioc.LastOnline,
		"malware":              ioc.Malware,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubAnudeepAdServers(ioc models.GithubAnudeepAdServers) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubAnudeepAdServers(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubAnudeepAdServers(tx neo4j.Transaction, ioc models.GithubAnudeepAdServers) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubAnudeepCoinMiners(ioc models.GithubAnudeepCoinMiners) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubAnudeepCoinMiners(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubAnudeepCoinMiners(tx neo4j.Transaction, ioc models.GithubAnudeepCoinMiners) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubAnudeepFacebook(ioc models.GithubAnudeepFacebook) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubAnudeepFacebook(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubAnudeepFacebook(tx neo4j.Transaction, ioc models.GithubAnudeepFacebook) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubBlocklistProjectAbuseBlacklist(ioc models.GithubBlocklistProjectAbuseBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubBlocklistProjectAbuseBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubBlocklistProjectAbuseBlacklist(tx neo4j.Transaction, ioc models.GithubBlocklistProjectAbuseBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubBlocklistProjectAdsBlacklist(ioc models.GithubBlocklistProjectAdsBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubBlocklistProjectAdsBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubBlocklistProjectAdsBlacklist(tx neo4j.Transaction, ioc models.GithubBlocklistProjectAdsBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubBlocklistProjectCryptoBlacklist(ioc models.GithubBlocklistProjectCryptoBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubBlocklistProjectCryptoBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubBlocklistProjectCryptoBlacklist(tx neo4j.Transaction, ioc models.GithubBlocklistProjectCryptoBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubBlocklistProjectDrugsBlacklist(ioc models.GithubBlocklistProjectDrugsBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubBlocklistProjectDrugsBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubBlocklistProjectDrugsBlacklist(tx neo4j.Transaction, ioc models.GithubBlocklistProjectDrugsBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubBlocklistProjectFacebookBlacklist(ioc models.GithubBlocklistProjectFacebookBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubBlocklistProjectFacebookBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubBlocklistProjectFacebookBlacklist(tx neo4j.Transaction, ioc models.GithubBlocklistProjectFacebookBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubBlocklistProjectFraudBlacklist(ioc models.GithubBlocklistProjectFraudBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubBlocklistProjectFraudBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubBlocklistProjectFraudBlacklist(tx neo4j.Transaction, ioc models.GithubBlocklistProjectFraudBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubBlocklistProjectGamblingBlacklist(ioc models.GithubBlocklistProjectGamblingBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubBlocklistProjectGamblingBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubBlocklistProjectGamblingBlacklist(tx neo4j.Transaction, ioc models.GithubBlocklistProjectGamblingBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubEtherAdressLookupDomainBlacklist(ioc models.GithubEtherAdressLookupDomainBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubEtherAdressLookupDomainBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubEtherAdressLookupDomainBlacklist(tx neo4j.Transaction, ioc models.GithubEtherAdressLookupDomainBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubEtherAdressLookupURIBlacklist(ioc models.GithubEtherAdressLookupURIBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubEtherAdressLookupURIBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubEtherAdressLookupURIBlacklist(tx neo4j.Transaction, ioc models.GithubEtherAdressLookupURIBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateGithubAntiSocialEngineer(ioc models.GithubAntiSocialEngineer) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistGithubAntiSocialEngineer(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistGithubAntiSocialEngineer(tx neo4j.Transaction, ioc models.GithubAntiSocialEngineer) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateMalwareBazaarHashBlacklist(ioc models.MalwareBazaarHashBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistMalwareBazaarHashBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistMalwareBazaarHashBlacklist(tx neo4j.Transaction, ioc models.MalwareBazaarHashBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, sha256_hash: $sha256_hash, md5_hash: $md5_hash, reporter: $reporter, file_name: $file_name, file_type_guess: $file_type_guess, mime_type: $mime_type, signature: $signature, clamav: $clamav, vtpercent: $vtpercent, imphash: $imphash, ssdeep: $ssdeep, tlsh: $tlsh, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"sha256_hash":          ioc.Sha256Hash,
		"md5_hash":             ioc.Md5Hash,
		"reporter":             ioc.Reporter,
		"file_name":            ioc.FileName,
		"file_type_guess":      ioc.FileTypeGuess,
		"mime_type":            ioc.MimeType,
		"signature":            ioc.Signature,
		"clamav":               ioc.Clamav,
		"vtpercent":            ioc.VtPercent,
		"imphash":              ioc.ImpHash,
		"ssdeep":               ioc.SsDeep,
		"tlsh":                 ioc.Tlsh,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreatePublicDnsInfoNameservers(ioc models.PublicDnsInfoNameservers) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistPublicDnsInfoNameservers(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistPublicDnsInfoNameservers(tx neo4j.Transaction, ioc models.PublicDnsInfoNameservers) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:Dns {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             "ip",
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateThreatfoxBlacklist(ioc models.ThreatfoxBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistThreatfoxBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistThreatfoxBlacklist(tx neo4j.Transaction, ioc models.ThreatfoxBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, threadfox_id: $threadfox_id, open_port: $open_port, threat_type: $threat_type, fk_malware: $fk_malware  ,malware_alias: $malware_alias, malware_printable: $malware_printable, confidence_level: $confidence_level, reference: $reference, tags: $tags, anonymous: $anonymous, reporter: $reporter,  first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"threadfox_id":         ioc.ThreadfoxId,
		"open_port":            ioc.OperPort,
		"threat_type":          ioc.ThreatType,
		"fk_malware":           ioc.FkMalware,
		"malware_alias":        ioc.MalwareAlias,
		"malware_printable":    ioc.MalwarePrintable,
		"confidence_level":     ioc.ConfidenceLevel,
		"reference":            ioc.Refenrece,
		"tags":                 ioc.Tags,
		"anonymous":            ioc.Anonymous,
		"reporter":             ioc.Reporter,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateTorIp(ioc models.TorIp) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistTorIp(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistTorIp(tx neo4j.Transaction, ioc models.TorIp) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:Tor {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateUrlHausAbuseHostBlacklist(ioc models.UrlHausAbuseHostBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistUrlHausAbuseHostBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistUrlHausAbuseHostBlacklist(tx neo4j.Transaction, ioc models.UrlHausAbuseHostBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateUrlHausDistributingMalware(ioc models.UrlHausDistributingMalware) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistUrlHausDistributingMalware(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistUrlHausDistributingMalware(tx neo4j.Transaction, ioc models.UrlHausDistributingMalware) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, urlhaus_id:$urlhaus_id, dateadded: $dateadded, iocstatus: $iocstatus, lastonline:$lastonline, threat:$threat, tags:$tags, urlhaus_link:$urlhaus_link, reporter:$reporter, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"urlhaus_id":           ioc.UrlHausId,
		"dateadded":            ioc.DateAdded,
		"iocstatus":            ioc.IoCStatus,
		"lastonline":           ioc.LastOnline,
		"threat":               ioc.Threat,
		"tags":                 ioc.Tags,
		"urlhaus_link":         ioc.UrlHausLink,
		"reporter":             ioc.Reporter,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateUsomMaliciousUrlBlacklist(ioc models.UsomMaliciousUrlBlacklist) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistUsomMaliciousUrlBlacklist(tx, ioc)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistUsomMaliciousUrlBlacklist(tx neo4j.Transaction, ioc models.UsomMaliciousUrlBlacklist) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:IoC {id: $id, name: $ioc, ioc_type: $ioc_type, usom_id: $usom_id, description: $usom_id, source: $usom_id, first_seen_time: $first_seen_time, first_seen_timestamp: $first_seen_timestamp, last_seen_time: $last_seen_time, last_seen_timestamp:  $last_seen_timestamp, time: $time, timestamp: $timestamp})"

	parameters := map[string]interface{}{
		"id":                   ioc.Id,
		"ioc":                  ioc.IoC,
		"ioc_type":             ioc.IoCType,
		"usom_id":              ioc.UsomId,
		"description":          ioc.Description,
		"source":               ioc.Source,
		"first_seen_time":      ioc.FirstSeenTime,
		"first_seen_timestamp": ioc.FirstSeenTimestamp,
		"last_seen_time":       ioc.LastSeenTime,
		"last_seen_timestamp":  ioc.LastSeenTimestamp,
		"time":                 timeNow,
		"timestamp":            timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) FindTwitterUser(name string) (ioc *models.CyberIoC, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findTwitterUser(tx, name)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.CyberIoC)
	return ioc, err
}

func (u *GraphNeo4jRepository) findTwitterUser(tx neo4j.Transaction, name string) (*models.CyberIoC, error) {

	result, err := tx.Run(
		"MATCH (i:TwitterUser {name: $name}) RETURN i.id as id, i.name AS name, i.time as time, i.timestamp as timestamp",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")

	time, _ := record.Get("time")
	timestamp, _ := record.Get("timestamp")

	return &models.CyberIoC{
		Id:        id.(string),
		Name:      name,
		Time:      time.(int64),
		Timestamp: timestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindTweet(name string) (ioc *models.CyberIoC, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findTweet(tx, name)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.CyberIoC)
	return ioc, err
}

func (u *GraphNeo4jRepository) findTweet(tx neo4j.Transaction, name string) (*models.CyberIoC, error) {

	result, err := tx.Run(
		"MATCH (i:Tweet {name: $name}) RETURN i.id as id, i.name AS name, i.time as time, i.timestamp as timestamp",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	time, _ := record.Get("time")
	timestamp, _ := record.Get("timestamp")

	return &models.CyberIoC{
		Id:        id.(string),
		Name:      name,
		Time:      time.(int64),
		Timestamp: timestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindIpPortScan(ipPortScanId string) (ioc *models.PortScanIp, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findPortScanIpById(tx, ipPortScanId)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.PortScanIp)
	return ioc, err
}

func (u *GraphNeo4jRepository) findPortScanIpById(tx neo4j.Transaction, ipPortScanId string) (*models.PortScanIp, error) {

	result, err := tx.Run(
		"MATCH (i:PortScanIp {id: $id}) RETURN i.id as id, i.name AS name, i.first_seen_time as first_seen_time, i.first_seen_timestamp as first_seen_timestamp, i.last_seen_time as last_seen_time, i.last_seen_timestamp as last_seen_timestamp ",
		map[string]interface{}{
			"id": ipPortScanId,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	name, _ := record.Get("name")
	firstSeenTime, _ := record.Get("first_seen_time")
	firstSeenTimestamp, _ := record.Get("first_seen_timestamp")
	lastSeenTime, _ := record.Get("last_seen_time")
	lastSeenTimestamp, _ := record.Get("last_seen_timestamp")

	return &models.PortScanIp{
		ID:                 id.(string),
		IoC:                name.(string),
		FirstSeenTime:      firstSeenTime.(int64),
		FirstSeenTimestamp: firstSeenTimestamp.(string),
		LastSeenTime:       lastSeenTime.(int64),
		LastSeenTimestamp:  lastSeenTimestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindDomainPortScan(domainPortScanId string) (ioc *models.PortScanDomain, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findPortScanDomainById(tx, domainPortScanId)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.PortScanDomain)
	return ioc, err
}

func (u *GraphNeo4jRepository) findPortScanDomainById(tx neo4j.Transaction, domainPortScanId string) (*models.PortScanDomain, error) {

	result, err := tx.Run(
		"MATCH (i:PortScanDomain {id: $id}) RETURN i.id as id, i.name AS name, i.first_seen_time as first_seen_time, i.first_seen_timestamp as first_seen_timestamp, i.last_seen_time as last_seen_time, i.last_seen_timestamp as last_seen_timestamp ",
		map[string]interface{}{
			"id": domainPortScanId,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	name, _ := record.Get("name")
	firstSeenTime, _ := record.Get("first_seen_time")
	firstSeenTimestamp, _ := record.Get("first_seen_timestamp")
	lastSeenTime, _ := record.Get("last_seen_time")
	lastSeenTimestamp, _ := record.Get("last_seen_timestamp")

	return &models.PortScanDomain{
		ID:                 id.(string),
		IoC:                name.(string),
		FirstSeenTime:      firstSeenTime.(int64),
		FirstSeenTimestamp: firstSeenTimestamp.(string),
		LastSeenTime:       lastSeenTime.(int64),
		LastSeenTimestamp:  lastSeenTimestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindCertStreamCertificate(fingerprint string) (certStreamItem *models.CertStreamCertificate, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findCertStreamItemById(tx, fingerprint)
	})
	if result == nil {
		return nil, err
	}
	certStreamItem = result.(*models.CertStreamCertificate)
	return certStreamItem, err
}

func (u *GraphNeo4jRepository) findCertStreamItemById(tx neo4j.Transaction, certificateFingerprint string) (*models.CertStreamCertificate, error) {

	result, err := tx.Run(
		"MATCH (i:CertStreamCertificate {name: $fingerprint}) RETURN  i.name AS name, i.issuer_c as issuer_c, i.issuer_o as issuer_o, i.issuer_cn as issuer_cn, i.not_before_timestamp as not_before_timestamp, i.not_after_timestamp as not_after_timestamp, i.signature_algorithm as signature_algorithm",
		map[string]interface{}{
			"fingerprint": certificateFingerprint,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	fingerprint, _ := record.Get("name")
	issuerC, _ := record.Get("issuer_c")
	issuerO, _ := record.Get("issuer_o")
	issuerCN, _ := record.Get("issuer_cn")
	notBeforeTimestamp, _ := record.Get("not_before_timestamp")
	notAfterTimestamp, _ := record.Get("not_after_timestamp")
	signatureAlgorithm, _ := record.Get("signature_algorithm")

	return &models.CertStreamCertificate{
		Fingerprint:        fingerprint.(string),
		IssuerC:            issuerC.(string),
		IssuerO:            issuerO.(string),
		IssuerCN:           issuerCN.(string),
		NotBeforeTimestamp: notBeforeTimestamp.(string),
		NotAfterTimestamp:  notAfterTimestamp.(string),
		SignatureAlgorithm: signatureAlgorithm.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindAptReport(aptreport string) (aptReport *models.AptReport, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findAptReportByName(tx, aptreport)
	})
	if result == nil {
		return nil, err
	}
	aptReport = result.(*models.AptReport)
	return aptReport, err
}

func (u *GraphNeo4jRepository) findAptReportByName(tx neo4j.Transaction, aptReportName string) (*models.AptReport, error) {

	result, err := tx.Run(
		"MATCH (i:AptReport {name: $reportname}) RETURN  i.name AS name",
		map[string]interface{}{
			"reportname": aptReportName,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	reportname, _ := record.Get("name")

	return &models.AptReport{
		ReportName: reportname.(string),
	}, nil
}

func (u *GraphNeo4jRepository) FindAptGroup(aptgroupname string) (aptGroup *models.AptGroup, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findAptGroupByName(tx, aptgroupname)
	})
	if result == nil {
		return nil, err
	}
	aptGroup = result.(*models.AptGroup)
	return aptGroup, err
}

func (u *GraphNeo4jRepository) findAptGroupByName(tx neo4j.Transaction, aptGroupName string) (*models.AptGroup, error) {

	result, err := tx.Run(
		"MATCH (i:AptGroup {name: $aptgroupname}) RETURN  i.name AS name",
		map[string]interface{}{
			"aptgroupname": aptGroupName,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	groupName, _ := record.Get("name")

	return &models.AptGroup{
		GroupName: groupName.(string),
	}, nil
}

func (u *GraphNeo4jRepository) CreateCertStreamCertificate(certStreamCertificate models.CertStreamCertificate) (err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistCertStreamCertificate(tx, certStreamCertificate)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistCertStreamCertificate(tx neo4j.Transaction, certStreamCertificate models.CertStreamCertificate) (interface{}, error) {

	query := "CREATE (:CertStreamCertificate {name: $fingerprint, issuer_c: $issuer_c, issuer_o: $issuer_o, issuer_cn: $issuer_cn, not_before_timestamp: $not_before_timestamp, not_after_timestamp: $not_after_timestamp, signature_algorithm: $signature_algorithm})"

	parameters := map[string]interface{}{
		"fingerprint":          certStreamCertificate.Fingerprint,
		"issuer_c":             certStreamCertificate.IssuerC,
		"issuer_o":             certStreamCertificate.IssuerO,
		"issuer_cn":            certStreamCertificate.IssuerCN,
		"not_before_timestamp": certStreamCertificate.NotBeforeTimestamp,
		"not_after_timestamp":  certStreamCertificate.NotAfterTimestamp,
		"signature_algorithm":  certStreamCertificate.SignatureAlgorithm,
	}
	_, err := tx.Run(query, parameters)
	return nil, err

}

func (u *GraphNeo4jRepository) MergeCertStreamCertificateAndDomain(certStreamCertificate models.CertStreamCertificate, domain string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeCertStreamCertificateAndDomain(tx, certStreamCertificate, domain)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeCertStreamCertificateAndDomain(tx neo4j.Transaction, certStreamCertificate models.CertStreamCertificate, domain string) (err error) {

	_, err = tx.Run(
		"MATCH (n:CertStreamCertificate {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:HAS_CERTIFICATE]-(m)",
		map[string]interface{}{
			"name1": certStreamCertificate.Fingerprint,
			"name2": domain,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeAptGroups(aptGroup1 *models.AptGroup, aptGroup2 *models.AptGroup) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeAptGroups(tx, aptGroup1, aptGroup2)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeAptGroups(tx neo4j.Transaction, aptGroup1 *models.AptGroup, aptGroup2 *models.AptGroup) (err error) {

	_, err = tx.Run(
		"MATCH (n:AptGroup {name: $name1}), (m:AptGroup {name: $name2}) MERGE (n)-[:KNOWN_AS]-(m)",
		map[string]interface{}{
			"name1": aptGroup1.GroupName,
			"name2": aptGroup2.GroupName,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) FindSslCertificate(name string) (ioc *models.CyberIoC, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findSslCertificate(tx, name)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.CyberIoC)
	return ioc, err
}

func (u *GraphNeo4jRepository) findSslCertificate(tx neo4j.Transaction, name string) (*models.CyberIoC, error) {

	result, err := tx.Run(
		"MATCH (i:SslCertificate {name: $name}) RETURN i.id as id, i.name AS name, i.time as time, i.timestamp as timestamp",
		map[string]interface{}{
			"name": name,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	time, _ := record.Get("time")
	timestamp, _ := record.Get("timestamp")

	return &models.CyberIoC{
		Id:        id.(string),
		Name:      name,
		Time:      time.(int64),
		Timestamp: timestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) MergeDomainToIp(domainToIp *models.DomainToIp) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeDomainToIp(tx, domainToIp)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeDomainToIp(tx neo4j.Transaction, domainToIp *models.DomainToIp) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:RESOLVES]-(m)",
		map[string]interface{}{
			"name1": domainToIp.Domain,
			"name2": domainToIp.Ip,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeDomainToSubdomain(domainToSubdomain *models.DomainToSubdomain) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeDomainToSubdomain(tx, domainToSubdomain)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeDomainToSubdomain(tx neo4j.Transaction, domainToSubdomain *models.DomainToSubdomain) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:HAS]-(m)",
		map[string]interface{}{
			"name1": domainToSubdomain.Domain,
			"name2": domainToSubdomain.Subdomain,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeSubdomainToIp(subdomainToIp *models.SubdomainToIp) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeSubdomainToIp(tx, subdomainToIp)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeSubdomainToIp(tx neo4j.Transaction, subdomainToIp *models.SubdomainToIp) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:RESOLVES]-(m)",
		map[string]interface{}{
			"name1": subdomainToIp.Subdomain,
			"name2": subdomainToIp.Ip,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeUrlToDomain(url string, domain string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeUrlToDomain(tx, url, domain)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeUrlToDomain(tx neo4j.Transaction, url string, domain string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:BELONGS]-(m)",
		map[string]interface{}{
			"name1": url,
			"name2": domain,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeUrlToIp(urlToIp *models.UrlToIp) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeUrlToIp(tx, urlToIp)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeUrlToIp(tx neo4j.Transaction, urlToIp *models.UrlToIp) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:RESOLVES]-(m)",
		map[string]interface{}{
			"name1": urlToIp.Url,
			"name2": urlToIp.Ip,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeUrlToSubdomain(urlToSubdomain *models.UrlToSubdomain) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeUrlToSubdomain(tx, urlToSubdomain)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeUrlToSubdomain(tx neo4j.Transaction, urlToSubdomain *models.UrlToSubdomain) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:IoC {name: $name2}) MERGE (n)-[:BELONGS]-(m)",
		map[string]interface{}{
			"name1": urlToSubdomain.Url,
			"name2": urlToSubdomain.Subdomain,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) CreateTweet(tweet twitterscraper.TweetResult) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistTweet(tx, tweet)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistTweet(tx neo4j.Transaction, tweet twitterscraper.TweetResult) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:Tweet {id: $id, name: $name, tweet_text: $tweet_text, tweet_html: $tweet_html, tweet_likes: $tweet_likes, tweet_time_parsed: $tweet_time_parsed, tweet_time_stamp: $tweet_time_stamp, tweet_permanent_url: $tweet_permanent_url, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":                  uuid.New().String(),
		"name":                tweet.ID,
		"tweet_text":          tweet.Text,
		"tweet_html":          tweet.HTML,
		"tweet_likes":         tweet.Likes,
		"tweet_time_parsed":   tweet.TimeParsed,
		"tweet_time_stamp":    tweet.Timestamp,
		"tweet_permanent_url": tweet.PermanentURL,
		"time":                timeNow,
		"timestamp":           timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateSslCertificate(sslPortInfo models.SslPortInfo) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistSslCertificate(tx, sslPortInfo)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistSslCertificate(tx neo4j.Transaction, sslPortInfo models.SslPortInfo) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()

	query := "CREATE (:SslCertificate {id: $id, name: $name, port: $port, issuer_name: $issuer_name, issuer_country: $issuer_country, issuer_organization: $issuer_organization, common_names: $common_names, tls_version: $tls_version, not_before: $not_before, not_after: $not_after, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":                  uuid.New().String(),
		"name":                sslPortInfo.Fingerprints.SHA256,
		"port":                sslPortInfo.Port,
		"issuer_name":         sslPortInfo.Issuer.Name,
		"issuer_country":      sslPortInfo.Issuer.Country,
		"issuer_organization": sslPortInfo.Issuer.Organization,
		"common_names":        strings.Join(sslPortInfo.CommonNames, " | "),
		"tls_version":         strings.Join(sslPortInfo.TlsVersions, " | "),
		"not_before":          sslPortInfo.NotBefore,
		"not_after":           sslPortInfo.NotAfter,
		"time":                timeNow,
		"timestamp":           timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) MergeIoCToTweet(ioc string, tweet twitterscraper.TweetResult) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIoCToTweet(tx, ioc, tweet)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIoCToTweet(tx neo4j.Transaction, ioc string, tweet twitterscraper.TweetResult) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:Tweet {name: $name2}) MERGE (n)-[:POSTED_IN]-(m)",
		map[string]interface{}{
			"name1": ioc,
			"name2": tweet.ID,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeIoCToIpPortScan(ioc string, portScanIp models.PortScanIp) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIoCToIpPortScan(tx, ioc, portScanIp)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIoCToIpPortScan(tx neo4j.Transaction, ioc string, portScanIp models.PortScanIp) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:PortScanIp {name: $name2}) MERGE (n)-[:HAS_SCAN_RESULT]-(m)",
		map[string]interface{}{
			"name1": ioc,
			"name2": portScanIp.IoC,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeIoCToDomainPortScan(ioc string, portScanDomain models.PortScanDomain) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIoCToDomainPortScan(tx, ioc, portScanDomain)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIoCToDomainPortScan(tx neo4j.Transaction, ioc string, portScanDomain models.PortScanDomain) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:PortScanDomain {name: $name2}) MERGE (n)-[:HAS_SCAN_RESULT]-(m)",
		map[string]interface{}{
			"name1": ioc,
			"name2": portScanDomain.IoC,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) CreatePortScanDetail(portScanDetail *models.PortScanDetail) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistPortScanDetail(tx, portScanDetail)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistPortScanDetail(tx neo4j.Transaction, portScanDetail *models.PortScanDetail) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:PortScanDetail {id: $id, name: $name, protocol: $protocol, port_no: $port_no, service_name: $service_name, service_product: $service_product, service_version: $service_version, service_os_type: $service_os_type, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":              portScanDetail.ID,
		"name":            portScanDetail.PortNo,
		"protocol":        portScanDetail.Protocol,
		"port_no":         portScanDetail.PortNo,
		"service_name":    portScanDetail.ServiceName,
		"service_product": portScanDetail.ServiceProduct,
		"service_version": portScanDetail.ServiceVersion,
		"service_os_type": portScanDetail.ServiceOsType,
		"time":            timeNow,
		"timestamp":       timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) CreateTwitterUsername(twitterUsername string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistTwitterUsername(tx, twitterUsername)
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) persistTwitterUsername(tx neo4j.Transaction, twitterUsername string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	query := "CREATE (:TwitterUser {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        uuid.New().String(),
		"name":      twitterUsername,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) MergeTweetToTwitterUsername(tweetId string, twitterUsername string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeTweetToTwitterUsername(tx, tweetId, twitterUsername)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeTweetToTwitterUsername(tx neo4j.Transaction, tweetId string, twitterUsername string) (err error) {

	_, err = tx.Run(
		"MATCH (n:Tweet {name: $name1}), (m:TwitterUser {name: $name2}) MERGE (n)-[:POSTED]-(m)",
		map[string]interface{}{
			"name1": tweetId,
			"name2": twitterUsername,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeDomainToSslCertificate(domain string, sslCertificateSha256 string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeDomainToSslCertificate(tx, domain, sslCertificateSha256)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeDomainToSslCertificate(tx neo4j.Transaction, domain string, sslCertificateSha256 string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:SslCertificate {name: $name2}) MERGE (n)-[:PROTECTED]-(m)",
		map[string]interface{}{
			"name1": domain,
			"name2": sslCertificateSha256,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeSubdomainToSslCertificate(subdomain string, sslCertificateSha256 string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeSubdomainToSslCertificate(tx, subdomain, sslCertificateSha256)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeSubdomainToSslCertificate(tx neo4j.Transaction, subdomain string, sslCertificateSha256 string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:SslCertificate {name: $name2}) MERGE (n)-[:PROTECTED]-(m)",
		map[string]interface{}{
			"name1": subdomain,
			"name2": sslCertificateSha256,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) CreatePortOfSSL(port string) (id string, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()

	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			idOfPort, err := u.persistPortOfSSL(tx, port)
			id = idOfPort.(string)
			return id, err

		}); err != nil {
		return "", err
	}
	return id, nil

}

func (u *GraphNeo4jRepository) persistPortOfSSL(tx neo4j.Transaction, portOfSSL string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	id := uuid.New().String()
	query := "CREATE (:SslPort {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        id,
		"name":      portOfSSL,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return id, err
}

func (u *GraphNeo4jRepository) MergePortIdAndSslSha256(portId string, sslCertificateSha256 string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergePortIdAndSslSha256(tx, portId, sslCertificateSha256)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergePortIdAndSslSha256(tx neo4j.Transaction, portId string, sslCertificateSha256 string) (err error) {

	_, err = tx.Run(
		"MATCH (n:SslPort {id: $id}), (m:SslCertificate {name: $name2}) MERGE (n)-[:SERVE]-(m)",
		map[string]interface{}{
			"id":    portId,
			"name2": sslCertificateSha256,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) CreateIssuerName(issuerName string) (id string, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()

	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			idOfPort, err := u.persistIssuerName(tx, issuerName)
			id = idOfPort.(string)
			return id, err

		}); err != nil {
		return "", err
	}
	return id, nil

}

func (u *GraphNeo4jRepository) persistIssuerName(tx neo4j.Transaction, issuerName string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	id := uuid.New().String()
	query := "CREATE (:IssuerName {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        id,
		"name":      issuerName,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return id, err
}

func (u *GraphNeo4jRepository) MergeIssuerNameAndSslSha256(issuerName string, sslCertificateSha256 string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIssuerNameIdAndSslSha256(tx, issuerName, sslCertificateSha256)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIssuerNameIdAndSslSha256(tx neo4j.Transaction, issuerNameId string, sslCertificateSha256 string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IssuerName {id: $id}), (m:SslCertificate {name: $name2}) MERGE (n)-[:ISSUE]-(m)",
		map[string]interface{}{
			"id":    issuerNameId,
			"name2": sslCertificateSha256,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) CreateIssuerCountry(issuerCountry string) (id string, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()

	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			idOfPort, err := u.persistIssuerCountry(tx, issuerCountry)
			id = idOfPort.(string)
			return id, err

		}); err != nil {
		return "", err
	}
	return id, nil

}

func (u *GraphNeo4jRepository) persistIssuerCountry(tx neo4j.Transaction, issuerCountry string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	id := uuid.New().String()
	query := "CREATE (:IssuerCountry {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        id,
		"name":      issuerCountry,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return id, err
}

func (u *GraphNeo4jRepository) MergeIssuerCountryAndSslSha256(issuerCountry string, sslCertificateSha256 string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIssuerCountryIdAndSslSha256(tx, issuerCountry, sslCertificateSha256)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIssuerCountryIdAndSslSha256(tx neo4j.Transaction, issuerCountryId string, sslCertificateSha256 string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IssuerCountry {id: $id}), (m:SslCertificate {name: $name2}) MERGE (n)-[:ISSUED_FROM]-(m)",
		map[string]interface{}{
			"id":    issuerCountryId,
			"name2": sslCertificateSha256,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) CreateIssuerOrganization(issuerOrganization string) (id string, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()

	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			idOfPort, err := u.persistIssuerOrganization(tx, issuerOrganization)
			id = idOfPort.(string)
			return id, err

		}); err != nil {
		return "", err
	}
	return id, nil

}

func (u *GraphNeo4jRepository) persistIssuerOrganization(tx neo4j.Transaction, issuerOrganization string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	id := uuid.New().String()
	query := "CREATE (:IssuerOrganization {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        id,
		"name":      issuerOrganization,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return id, err
}

func (u *GraphNeo4jRepository) MergeIssuerOrganizationAndSslSha256(issuerOrganization string, sslCertificateSha256 string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIssuerOrganizationIdAndSslSha256(tx, issuerOrganization, sslCertificateSha256)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIssuerOrganizationIdAndSslSha256(tx neo4j.Transaction, issuerOrganizationId string, sslCertificateSha256 string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IssuerOrganization {id: $id}), (m:SslCertificate {name: $name2}) MERGE (n)-[:ISSUED_BY]-(m)",
		map[string]interface{}{
			"id":    issuerOrganizationId,
			"name2": sslCertificateSha256,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) FindWhoisDomain(whoisId string) (ioc *models.WhoisDomain, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findWhoisDomainById(tx, whoisId)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.WhoisDomain)
	return ioc, err

}

func (u *GraphNeo4jRepository) findWhoisDomainById(tx neo4j.Transaction, whoisId string) (*models.WhoisDomain, error) {

	result, err := tx.Run(
		"MATCH (i:WhoisDomain {id: $id}) RETURN i.id as id, i.name AS name, i.time as time, i.timestamp as timestamp",
		map[string]interface{}{
			"Id": whoisId,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("Id")
	name, _ := record.Get("name")
	time, _ := record.Get("time")
	timestamp, _ := record.Get("timestamp")

	return &models.WhoisDomain{
		Id:                id.(string),
		DomainName:        name.(string),
		CreationTime:      time.(int64),
		CreationTimestamp: timestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) CreateWhoisDomain(whoisDomain *models.WhoisDomain) (err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()

	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistWhoisDomain(tx, whoisDomain)
		}); err != nil {
		return err
	}
	return nil

}

func (u *GraphNeo4jRepository) persistWhoisDomain(tx neo4j.Transaction, whoisDomain *models.WhoisDomain) (interface{}, error) {

	query := "CREATE (:WhoisDomain {id: $id, name: $name, expiry_date: $expiry_date, domain_registrar_name: $domain_registrar_name, domain_registrar_whois: $domain_registrar_whois, registrant_name: $registrant_name, registrant_company: $registrant_company ,registrant_address: $registrant_address,registrant_city: $registrant_city ,registrant_country: $registrant_country ,registrant_email: $registrant_email ,registrant_phone: $registrant_phone ,administrative_email: $administrative_email ,administrative_phone: $administrative_phone,name_server_1: $name_server_1 ,name_server_2: $name_server_2,name_server_3: $name_server_3 ,name_server_4: $name_server_4, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":                     whoisDomain.Id,
		"name":                   whoisDomain.DomainName,
		"expiry_date":            whoisDomain.ExpiryDate,
		"domain_registrar_name":  whoisDomain.DomainRegistrarName,
		"domain_registrar_whois": whoisDomain.DomainRegistrarWhois,
		"registrant_name":        whoisDomain.RegistrantName,
		"registrant_company":     whoisDomain.RegistrantCompany,
		"registrant_address":     whoisDomain.RegistrantAddress,
		"registrant_city":        whoisDomain.RegistrantCity,
		"registrant_country":     whoisDomain.RegistrantCountry,
		"registrant_email":       whoisDomain.RegistrantEmail,
		"registrant_phone":       whoisDomain.RegistrantPhone,
		"administrative_email":   whoisDomain.AdministrativeEmail,
		"administrative_phone":   whoisDomain.AdministrativePhone,
		"name_server_1":          whoisDomain.NameServer1,
		"name_server_2":          whoisDomain.NameServer2,
		"name_server_3":          whoisDomain.NameServer3,
		"name_server_4":          whoisDomain.NameServer4,
		"time":                   whoisDomain.CreationTime,
		"timestamp":              whoisDomain.CreationTimestamp,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) MergeDomainToWhoisDomain(whoisId string, domain string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeDomainToWhoisDomain(tx, whoisId, domain)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeDomainToWhoisDomain(tx neo4j.Transaction, whoisId string, domain string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:WhoisDomain {id: $id}) MERGE (n)-[:LOOKUP]-(m)",
		map[string]interface{}{
			"name1": domain,
			"id":    whoisId,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

// func (u *GraphNeo4jRepository) FindWhoisIp(whoisId string) (ioc *models.WhoisIp, err error)

func (u *GraphNeo4jRepository) FindWhoisIp(whoisId string) (ioc *models.WhoisIp, err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findWhoisIpById(tx, whoisId)
	})
	if result == nil {
		return nil, err
	}
	ioc = result.(*models.WhoisIp)
	return ioc, err

}

func (u *GraphNeo4jRepository) findWhoisIpById(tx neo4j.Transaction, whoisId string) (*models.WhoisIp, error) {

	result, err := tx.Run(
		"MATCH (i:WhoisIp {id: $id}) RETURN i.id as id, i.name AS name, i.time as time, i.timestamp as timestamp",
		map[string]interface{}{
			"Id": whoisId,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("Id")
	name, _ := record.Get("name")
	time, _ := record.Get("time")
	timestamp, _ := record.Get("timestamp")

	return &models.WhoisIp{
		Id:                id.(string),
		IpAddress:         name.(string),
		CreationTime:      time.(int64),
		CreationTimestamp: timestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) CreateWhoisIp(whoisIp *models.WhoisIp) (err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()

	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistWhoisIp(tx, whoisIp)
		}); err != nil {
		return err
	}
	return nil

}

func (u *GraphNeo4jRepository) persistWhoisIp(tx neo4j.Transaction, whoisIp *models.WhoisIp) (interface{}, error) {

	query := "CREATE (:WhoisIp {id: $id, name: $name, inetnum: $inetnum, netname: $netname, descr: $descr, country: $country, organization: $organization, person_name: $person_name, person_address: $person_address, person_phone: $person_phone, route_route: $route_route, route_descr: $route_descr, route_origin: $route_origin, route_created: $route_created, route_last_modified: $route_last_modified, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":                  whoisIp.Id,
		"name":                whoisIp.IpAddress,
		"inetnum":             whoisIp.Inetnum,
		"netname":             whoisIp.Netname,
		"descr":               whoisIp.Descr,
		"country":             whoisIp.Country,
		"organization":        whoisIp.Organization,
		"person_name":         whoisIp.PersonName,
		"person_address":      whoisIp.PersonAddress,
		"person_phone":        whoisIp.PersonPhone,
		"route_route":         whoisIp.RouteRoute,
		"route_descr":         whoisIp.RouteDescr,
		"route_origin":        whoisIp.RouteOrigin,
		"route_created":       whoisIp.RouteCreated,
		"route_last_modified": whoisIp.RouteLastModified,
		"time":                whoisIp.CreationTime,
		"timestamp":           whoisIp.CreationTimestamp,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) MergeIpToWhoisIp(whoisId string, ip string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIpToWhoisIp(tx, whoisId, ip)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIpToWhoisIp(tx neo4j.Transaction, whoisId string, ip string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:WhoisIp {id: $id}) MERGE (n)-[:LOOKUP]-(m)",
		map[string]interface{}{
			"name1": ip,
			"id":    whoisId,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) FindAsn(asnCode string) (asn *models.Asn, err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{})
	defer func() {
		err = session.Close()
	}()
	result, err := session.ReadTransaction(func(tx neo4j.Transaction) (interface{}, error) {
		return u.findAsn(tx, asnCode)
	})
	if result == nil {
		return nil, err
	}
	asn = result.(*models.Asn)
	return asn, err
}

func (u *GraphNeo4jRepository) findAsn(tx neo4j.Transaction, asnCode string) (*models.Asn, error) {

	result, err := tx.Run(
		"MATCH (i:Asn {name: $name}) RETURN i.id as id, i.name AS name, i.time as time, i.timestamp as timestamp",
		map[string]interface{}{
			"name": asnCode,
		},
	)
	if err != nil {
		return nil, err
	}
	record, err := result.Single()
	if err != nil {
		if err.Error() == "Result contains no more records" {
			return nil, nil
		}
		return nil, err
	}

	id, _ := record.Get("id")
	name, _ := record.Get("name")
	time, _ := record.Get("time")
	timestamp, _ := record.Get("timestamp")

	return &models.Asn{
		Id:        id.(string),
		Name:      name.(string),
		Time:      time.(int64),
		Timestamp: timestamp.(string),
	}, nil
}

func (u *GraphNeo4jRepository) CreateAsn(asnCode string) (err error) {

	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()

	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return u.persistAsn(tx, asnCode)
		}); err != nil {
		return err
	}
	return nil

}

func (u *GraphNeo4jRepository) persistAsn(tx neo4j.Transaction, asnCode string) (interface{}, error) {

	timestampNow, timeNow := utils.GetMoment()
	id := uuid.New().String()
	query := "CREATE (:Asn {id: $id, name: $name, time: $time, timestamp: $timestamp})"
	parameters := map[string]interface{}{
		"id":        id,
		"name":      asnCode,
		"time":      timeNow,
		"timestamp": timestampNow,
	}
	_, err := tx.Run(query, parameters)
	return nil, err
}

func (u *GraphNeo4jRepository) MergeIpToAsn(ip string, asnCode string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeIpToAsn(tx, ip, asnCode)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeIpToAsn(tx neo4j.Transaction, ip string, asnCode string) (err error) {

	_, err = tx.Run(
		"MATCH (n:IoC {name: $name1}), (m:Asn {name: $name2}) MERGE (n)-[:COVER]-(m)",
		map[string]interface{}{
			"name1": ip,
			"name2": asnCode,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergePortScanDetailToIpPortScan(portScanDetailId string, ipPortScanListId string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergePortScanDetailToIpPortScan(tx, portScanDetailId, ipPortScanListId)
			return nil, err
		}); err != nil {
		return err
	}
	return nil

}
func (u *GraphNeo4jRepository) mergePortScanDetailToIpPortScan(tx neo4j.Transaction, portScanDetailId string, ipPortScanListId string) (err error) {

	_, err = tx.Run(
		"MATCH (n:PortScanDetail {id: $name1}), (m:PortScanIp {id: $name2}) MERGE (n)-[:HAS_PORT]-(m)",
		map[string]interface{}{
			"name1": portScanDetailId,
			"name2": ipPortScanListId,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergePortScanDetailToDomainPortScan(portScanDetailId string, domainPortScanListId string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergePortScanDetailToDomainPortScan(tx, portScanDetailId, domainPortScanListId)
			return nil, err
		}); err != nil {
		return err
	}
	return nil

}
func (u *GraphNeo4jRepository) mergePortScanDetailToDomainPortScan(tx neo4j.Transaction, portScanDetailId string, domainPortScanListId string) (err error) {

	_, err = tx.Run(
		"MATCH (n:PortScanDetail {id: $name1}), (m:PortScanDomain {id: $name2}) MERGE (n)-[:HAS_PORT]-(m)",
		map[string]interface{}{
			"name1": portScanDetailId,
			"name2": domainPortScanListId,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeAptReportToIoC(aptreport string, ioc string, ioctype string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeAptReportToIoC(tx, aptreport, ioc, ioctype)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeAptReportToIoC(tx neo4j.Transaction, aptreport string, ioc string, ioctype string) (err error) {

	_, err = tx.Run(
		"MATCH (n:AptReport {name: $name1}), (m:IoC {name: $name2, ioc_type: $name3}) MERGE (n)-[:HAS_IOC]-(m)",
		map[string]interface{}{
			"name1": aptreport,
			"name2": ioc,
			"name3": ioctype,
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func (u *GraphNeo4jRepository) MergeAptReportToAptGroup(aptreport string, aptGroup string) (err error) {
	session := u.Driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer func() {
		err = session.Close()
	}()
	if _, err = session.
		WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			err = u.mergeAptReportToAptGroup(tx, aptreport, aptGroup)
			return nil, err
		}); err != nil {
		return err
	}
	return nil
}

func (u *GraphNeo4jRepository) mergeAptReportToAptGroup(tx neo4j.Transaction, aptreport string, aptGroup string) (err error) {

	_, err = tx.Run(
		"MATCH (n:AptReport {name: $name1}), (m:AptGroup {name: $name2}) MERGE (n)-[:HAS_APT_GROUP]-(m)",
		map[string]interface{}{
			"name1": aptreport,
			"name2": aptGroup,
		},
	)
	if err != nil {
		return err
	}

	return nil
}
