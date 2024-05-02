package queries

import (
	"cti_graph/app/models"

	"github.com/jmoiron/sqlx"
)

type CtiQueries struct {
	*sqlx.DB
}

func (q *CtiQueries) GetDomainToIpList(offset int) ([]models.DomainToIp, error) {
	query := "SELECT id, domain, ip, creation_timestamp, creation_time FROM public.domain_to_ip ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.DomainToIp // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.DomainToIp{}
		err := rows.Scan(
			&result.Id,
			&result.Domain,
			&result.Ip,
			&result.CreationTimestamp,
			&result.CreationTime,
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

func (q *CtiQueries) GetDomainToSubdomainList(offset int) ([]models.DomainToSubdomain, error) {
	// query := "SELECT id, domain, subdomain, creation_timestamp, creation_time FROM public.domain_to_subdomain ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"
	query := "SELECT id, domain, subdomain, creation_timestamp, creation_time FROM public.domain_to_subdomain ORDER BY creation_time ASC OFFSET $1 LIMIT 10000"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.DomainToSubdomain // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.DomainToSubdomain{}
		err := rows.Scan(
			&result.Id,
			&result.Domain,
			&result.Subdomain,
			&result.CreationTimestamp,
			&result.CreationTime,
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

func (q *CtiQueries) GetSubdomainToIpList(offset int) ([]models.SubdomainToIp, error) {
	query := "SELECT id, subdomain, ip, creation_timestamp, creation_time FROM public.subdomain_to_ip ORDER BY creation_time ASC OFFSET $1 LIMIT 20000"
	// query := "SELECT id, subdomain, ip, creation_timestamp, creation_time FROM public.subdomain_to_ip ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.SubdomainToIp // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.SubdomainToIp{}
		err := rows.Scan(
			&result.Id,
			&result.Subdomain,
			&result.Ip,
			&result.CreationTimestamp,
			&result.CreationTime,
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

func (q *CtiQueries) GetUrlToDomainList(offset int) ([]models.UrlToDomain, error) {
	query := "SELECT id, url, domain, creation_timestamp, creation_time FROM public.url_to_domain ORDER BY creation_time ASC OFFSET $1 LIMIT 10000"
	// query := "SELECT id, url, domain, creation_timestamp, creation_time FROM public.url_to_domain ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.UrlToDomain // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.UrlToDomain{}
		err := rows.Scan(
			&result.Id,
			&result.Url,
			&result.Domain,
			&result.CreationTimestamp,
			&result.CreationTime,
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

func (q *CtiQueries) GetUrlToIpList(offset int) ([]models.UrlToIp, error) {
	query := "SELECT id, url, ip, creation_timestamp, creation_time FROM public.url_to_ip ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.UrlToIp // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.UrlToIp{}
		err := rows.Scan(
			&result.Id,
			&result.Url,
			&result.Ip,
			&result.CreationTimestamp,
			&result.CreationTime,
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

func (q *CtiQueries) GetUrlToSubdomainList(offset int) ([]models.UrlToSubdomain, error) {
	query := "SELECT id, url, subdomain, creation_timestamp, creation_time FROM public.url_to_subdomain ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.UrlToSubdomain // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.UrlToSubdomain{}
		err := rows.Scan(
			&result.Id,
			&result.Url,
			&result.Subdomain,
			&result.CreationTimestamp,
			&result.CreationTime,
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
