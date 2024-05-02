package queries

import (
	"cti_graph/app/models"

	"github.com/jmoiron/sqlx"
)

type BlacklistQueries struct {
	*sqlx.DB
}

func (q *BlacklistQueries) GetAbusechBotnetIpBlacklist(offset int) ([]models.AbusechBotnetIpBlacklist, error) {
	query := "SELECT  id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.abusech_botnet_ip_blacklist ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.AbusechBotnetIpBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.AbusechBotnetIpBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetAbusechSslBlacklist(offset int) ([]models.AbusechSslBlacklist, error) {
	query := "SELECT id, listing_date, sha1, ioc_type, listing_reason, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.abusech_ssl_blacklist ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.AbusechSslBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.AbusechSslBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.ListingData,
			&result.IoC,
			&result.IoCType,
			&result.ListingReason,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetCiarmyBadguysBlacklist(offset int) ([]models.CiarmyBadguysBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.ciarmy_badguys ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.CiarmyBadguysBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.CiarmyBadguysBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetDarklistBacklist(offset int) ([]models.DarklistBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.darklist_blacklisted_ip_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.DarklistBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.DarklistBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetDshieldTop10Blacklist(offset int) ([]models.DshieldTop10Blacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.dshield_top10 ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.DshieldTop10Blacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.DshieldTop10Blacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetEmergingThreatsCompromisedBlacklist(offset int) ([]models.EmergingThreatsCompromisedBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.emergingthreats_compromised_ips ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.EmergingThreatsCompromisedBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.EmergingThreatsCompromisedBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetFeodoTrackerBotnetBlacklist(offset int) ([]models.FeodoTrackerBotnetBlacklist, error) {
	query := "SELECT id, ioc, port, ioc_type, status, hostname, as_number, as_name, country, last_online, malware, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.feodotracker_botnet_ip_blacklist ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.FeodoTrackerBotnetBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.FeodoTrackerBotnetBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.Port,
			&result.IoCType,
			&result.Status,
			&result.Hostname,
			&result.AsNumber,
			&result.AsName,
			&result.Country,
			&result.LastOnline,
			&result.Malware,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubAnudeepAdServers(offset int) ([]models.GithubAnudeepAdServers, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_anudeep_ad_servers ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubAnudeepAdServers // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubAnudeepAdServers{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubAnudeepCoinMiners(offset int) ([]models.GithubAnudeepCoinMiners, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_anudeep_coin_miner ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubAnudeepCoinMiners // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubAnudeepCoinMiners{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubAnudeepFacebook(offset int) ([]models.GithubAnudeepFacebook, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_anudeep_facebook ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubAnudeepFacebook // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubAnudeepFacebook{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubBlocklistProjectAbuseBlacklist(offset int) ([]models.GithubBlocklistProjectAbuseBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_blocklistproject_abuse_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 100000"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubBlocklistProjectAbuseBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubBlocklistProjectAbuseBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubBlocklistProjectAdsBlacklist(offset int) ([]models.GithubBlocklistProjectAdsBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_blocklistproject_ads_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 100000"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubBlocklistProjectAdsBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubBlocklistProjectAdsBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubBlocklistProjectCryptoBlacklist(offset int) ([]models.GithubBlocklistProjectCryptoBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_blocklistproject_crypto_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubBlocklistProjectCryptoBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubBlocklistProjectCryptoBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubBlocklistProjectDrugsBlacklist(offset int) ([]models.GithubBlocklistProjectDrugsBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_blocklistproject_drugs_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubBlocklistProjectDrugsBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubBlocklistProjectDrugsBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubBlocklistProjectFacebookBlacklist(offset int) ([]models.GithubBlocklistProjectFacebookBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_blocklistproject_facebook_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubBlocklistProjectFacebookBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubBlocklistProjectFacebookBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubBlocklistProjectFraudBlacklist(offset int) ([]models.GithubBlocklistProjectFraudBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_blocklistproject_fraud_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 100000"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubBlocklistProjectFraudBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubBlocklistProjectFraudBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubBlocklistProjectGamblingBlacklist(offset int) ([]models.GithubBlocklistProjectGamblingBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_blocklistproject_gambling_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubBlocklistProjectGamblingBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubBlocklistProjectGamblingBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubEtherAdressLookupDomainBlacklist(offset int) ([]models.GithubEtherAdressLookupDomainBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_ether_address_lookup_domains ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubEtherAdressLookupDomainBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubEtherAdressLookupDomainBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubEtherAdressLookupURIBlacklist(offset int) ([]models.GithubEtherAdressLookupURIBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_ether_address_lookup_uri ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubEtherAdressLookupURIBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubEtherAdressLookupURIBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetGithubAntiSocialEngineer(offset int) ([]models.GithubAntiSocialEngineer, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.github_the_anti_social_engineer ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.GithubAntiSocialEngineer // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.GithubAntiSocialEngineer{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetMalwareBazaarHashBlacklist(offset int) ([]models.MalwareBazaarHashBlacklist, error) {
	query := "SELECT id, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.malware_bazaar_hash_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 100000"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.MalwareBazaarHashBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.MalwareBazaarHashBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.Sha256Hash,
			&result.Md5Hash,
			&result.IoC,
			&result.Reporter,
			&result.FileName,
			&result.FileTypeGuess,
			&result.MimeType,
			&result.Signature,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetPublicDnsInfoNameserversAll(offset int) ([]models.PublicDnsInfoNameservers, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.public_dns_info_nameservers_all ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.PublicDnsInfoNameservers // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.PublicDnsInfoNameservers{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetThreatfoxBlacklist(offset int) ([]models.ThreatfoxBlacklist, error) {
	query := "SELECT id, threadfox_id, ioc, open_port, ioc_type, threat_type, fk_malware, malware_alias, malware_printable, confidence_level, reference, tags, anonymous, reporter, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.threatfox_ioc_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 100000"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.ThreatfoxBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.ThreatfoxBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.ThreadfoxId,
			&result.IoC,
			&result.OperPort,
			&result.IoCType,
			&result.ThreatType,
			&result.FkMalware,
			&result.MalwareAlias,
			&result.MalwarePrintable,
			&result.ConfidenceLevel,
			&result.Refenrece,
			&result.Tags,
			&result.Anonymous,
			&result.Reporter,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetTorIp(offset int) ([]models.TorIp, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.tor_ip_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.TorIp // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.TorIp{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetUrlHausAbuseHostBlacklist(offset int) ([]models.UrlHausAbuseHostBlacklist, error) {
	query := "SELECT id, ioc, ioc_type, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.urlhaus_abuse_hosts ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.UrlHausAbuseHostBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.UrlHausAbuseHostBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.IoC,
			&result.IoCType,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetUrlHausDistributingMalware(offset int) ([]models.UrlHausDistributingMalware, error) {
	query := "SELECT id, urlhaus_id, dateadded, ioc, ioc_type, iocstatus, lastonline, threat, tags, urlhaus_link, reporter, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.urlhaus_distributing_malware ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.UrlHausDistributingMalware // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.UrlHausDistributingMalware{}
		err := rows.Scan(

			&result.Id,
			&result.UrlHausId,
			&result.DateAdded,
			&result.IoC,
			&result.IoCType,
			&result.IoCStatus,
			&result.LastOnline,
			&result.Threat,
			&result.Tags,
			&result.UrlHausLink,
			&result.Reporter,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}

func (q *BlacklistQueries) GetUsomMaliciousUrlBlacklist(offset int) ([]models.UsomMaliciousUrlBlacklist, error) {
	query := "SELECT id, usom_id, ioc_type, ioc, description, source, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp FROM public.usom_malicious_url_list ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.UsomMaliciousUrlBlacklist // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.UsomMaliciousUrlBlacklist{}
		err := rows.Scan(
			&result.Id,
			&result.UsomId,
			&result.IoCType,
			&result.IoC,
			&result.Description,
			&result.Source,
			&result.FirstSeenTime,
			&result.FirstSeenTimestamp,
			&result.LastSeenTime,
			&result.LastSeenTimestamp,
		)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				return nil, nil
			}
			return nil, err
		}
		results = append(results, result)
	}
	if results == nil {
		return nil, nil
	}
	return results, nil
}
