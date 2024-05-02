package routes

import (
	"cti_graph/app/controllers"

	"github.com/gofiber/fiber/v2"
)

func PublicRoutes(a *fiber.App) {
	routeV1 := a.Group("/api/v1")

	//************ BLOCKLISTS

	// import abuse.ch botnet ip list from pg to neo4j
	routeV1.Post("/import-abusech-botnet-ip", controllers.ImportAbusechBotnetIp) // DONE
	// abusech_botnet_ip_blacklist

	// import abuse.ch botnet ip list from pg to neo4j
	routeV1.Post("/import-abusech-ssl-blacklist", controllers.ImportAbusechSslBlacklist) // DONE
	// abusech_ssl_blacklist

	// import ciarmy badguys list from pg to neo4j
	routeV1.Post("/import-ciarmy-badguys-blacklist", controllers.ImportCiarmyBadguysBlacklist) // DONE
	// ciarmy_badguys

	// import darklist blacklist from pg to neo4j
	routeV1.Post("/import-darklist-blacklisted-ip-blacklist", controllers.ImportDarklistBacklist) // DONE
	// darklist_blacklisted_ip_list

	// import dshield top10 from pg to neo4j
	routeV1.Post("/import-dshield-top10-blacklist", controllers.ImportDshieldTop10Blacklist) // DONE
	// dshield_top10

	// import emerging threats compromised ips from pg to neo4j
	routeV1.Post("/import-emergingthreats-compromised-ips-blacklist", controllers.ImportEmergingThreatsCompromisedBlacklist) // DONE
	// emergingthreats_compromised_ips

	// import feodotracker botnet ips from pg to neo4j
	routeV1.Post("/import-feodotracker-botnet-ip-blacklist", controllers.ImportFeodoTrackerBotnetBlacklist) // DONE
	// feodotracker_botnet_ip_blacklist

	// import github anudeep ad servers from pg to neo4j
	routeV1.Post("/import-github-anudeep-ad-servers", controllers.ImportGithubAnudeepAdServers) // DONE
	// github_anudeep_ad_servers

	// import github anudeep coin miner from pg to neo4j
	routeV1.Post("/import-github-anudeep-coin-miner", controllers.ImportGithubAnudeepCoinMiners) // DONE
	// github_anudeep_coin_miner

	// import github anudeep facebook from pg to neo4j
	routeV1.Post("/import-github-anudeep-facebook", controllers.ImportGithubAnudeepFacebook) // DONE
	// github_anudeep_facebook

	// import github blocklist project abuse list from pg to neo4j
	routeV1.Post("/import-github-blocklistproject-abuse-list", controllers.ImportGithubBlocklistProjectAbuseBlacklist) // DONE
	// github_blocklistproject_abuse_list

	// import github blocklist project ads list from pg to neo4j
	routeV1.Post("/import-github-blocklistproject-ads-list", controllers.ImportGithubBlocklistProjectAdsBlacklist) // DONE
	// github_blocklistproject_ads_list

	// import github blocklist project crypto  list from pg to neo4j
	routeV1.Post("/import-github-blocklistproject-crypto-list", controllers.ImportGithubBlocklistProjectCryptoBlacklist) // DONE
	// github_blocklistproject_crypto_list

	// import github blocklist project drugs list from pg to neo4j
	routeV1.Post("/import-github-blocklistproject-drugs-list", controllers.ImportGithubBlocklistProjectDrugsBlacklist) // DONE
	// github_blocklistproject_drugs_list

	// import github blocklist project facebook list from pg to neo4j
	routeV1.Post("/import-github-blocklistproject-facebook-list", controllers.ImportGithubBlocklistProjectFacebookBlacklist) // DONE
	// github_blocklistproject_facebook_list

	// import github blocklist project fraud list from pg to neo4j
	routeV1.Post("/import-github-blocklistproject-fraud-list", controllers.ImportGithubBlocklistProjectFraudBlacklist) // DONE
	// github_blocklistproject_fraud_list

	// import github blocklist project gambling list from pg to neo4j
	routeV1.Post("/import-github-blocklistproject-gambling-list", controllers.ImportGithubBlocklistProjectGamblingBlacklist) // DONE
	// github_blocklistproject_gambling_list

	// import github ether address lookup domains list from pg to neo4j
	routeV1.Post("/import-github-ether-address-lookup-domains", controllers.ImportGithubEtherAdressLookupDomainBlacklist) // DONE
	// github_ether_address_lookup_domains

	// import github ether address lookup uri list from pg to neo4j
	routeV1.Post("/import-github-ether-address-lookup-uri", controllers.ImportGithubEtherAdressLookupURIBlacklist) // DONE
	// github_ether_address_lookup_uri

	// import github the anti social engineer list from pg to neo4j
	routeV1.Post("/import-github-the-anti-social-engineer", controllers.ImportGithubAntiSocialEngineer) // DONE
	// github_the_anti_social_engineer

	// import malware bazaar hash list from pg to neo4j
	routeV1.Post("/import-malware-bazaar-hash-list", controllers.ImportMalwareBazaarHashBlacklist) // DONE
	// malware_bazaar_hash_list

	// import public dns info nameservers all from pg to neo4j
	routeV1.Post("/import-public-dns-info-nameservers-all", controllers.ImportPublicDnsInfoNameserversAll) // DONE
	// public_dns_info_nameservers_all

	// import threatfox ioc list all from pg to neo4j
	routeV1.Post("/import-threatfox-ioc-list", controllers.ImportThreatfoxBlacklist) // DONE
	// threatfox_ioc_list

	// import tor ip list all from pg to neo4j
	routeV1.Post("/import-tor-ip-list", controllers.ImportTorIp) // DONE
	// tor_ip_list

	// import urlhaus abuse hosts from pg to neo4j
	routeV1.Post("/import-urlhaus-abuse-hosts", controllers.ImportUrlHausAbuseHostBlacklist) // DONE
	// urlhaus_abuse_hosts

	// import urlhaus distributing malware from pg to neo4j
	routeV1.Post("/import-urlhaus-distributing-malware", controllers.ImportUrlHausDistributingMalware) // DONE
	// urlhaus_distributing_malware

	// import usom malicious url list from pg to neo4j
	routeV1.Post("/import-usom-malicious-url-list", controllers.ImportUsomMaliciousUrlBlacklist) // DONE
	// usom_malicious_url_list

	//************ IOC TRANSFORMATION

	// import domain-to-ip from pg to neo4j
	routeV1.Post("/import-domain-to-ip", controllers.ImportDomainToIp) // DONE
	// domain_to_ip

	// import domain-to-subdomain from pg to neo4j
	routeV1.Post("/import-domain-to-subdomain", controllers.ImportDomainToSubdomain) // DONE
	// domain_to_subdomain

	// import subdomain-to-ip from pg to neo4j
	routeV1.Post("/import-subdomain-to-ip", controllers.ImportSubdomainToIp) // DONE
	// subdomain_to_ip

	// import url-to-domain from pg to neo4j
	routeV1.Post("/import-url-to-domain", controllers.ImportUrlToDomain) // DONE
	// url_to_domain

	// import url-to-ip from pg to neo4j
	routeV1.Post("/import-url-to-ip", controllers.ImportUrlToIp) // DONE
	// url_to_ip

	// import url-to-subdomain from pg to neo4j
	routeV1.Post("/import-url-to-subdomain", controllers.ImportUrlToSubdomain) // DONE
	// url_to_subdomain

	//************ TWITTER

	// import twitter from pg to neo4j
	routeV1.Post("/import-twitter", controllers.ImportTwitter) // DONE

	//************ SSL CERTIFICATE

	// import domain-ssl certificate from pg to neo4j
	routeV1.Post("/import-domain-sslcertificate", controllers.ImportDomainSslCertificate) // DONE

	routeV1.Post("/import-subdomain-sslcertificate", controllers.ImportSubdomainSslCertificate) // DONE
	// ssl_profiler

	//************ WHOIS

	// import domain-whois lookup from pg to neo4j
	routeV1.Post("/import-domain-whois", controllers.ImportDomainWhois) // DONE
	// whois_data_domain

	// import ip-whois lookup from pg to neo4j
	routeV1.Post("/import-ip-whois", controllers.ImportIpWhois) // DONE
	// whois_data_ip

	//************ SCAN

	// import ipv4 port scan from pg to neo4j
	routeV1.Post("/import-ip-port-scan", controllers.ImportIpPortScan) // DONE
	// ipv4_scanner

	// import port scan from pg to neo4j
	routeV1.Post("/import-domain-port-scan", controllers.ImportDomainPortScan) // DONE
	// domain_scanner

	// *********** APT Reports

	// import apt report sourced IoCs
	routeV1.Post("/import-apt-report-iocs", controllers.ImportAptReportIoCs) // DONE

}
