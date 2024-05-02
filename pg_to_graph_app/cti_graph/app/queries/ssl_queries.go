package queries

import (
	"cti_graph/app/models"

	"github.com/jmoiron/sqlx"
)

type SSLQueries struct {
	*sqlx.DB
}

func (q *SSLQueries) GetDomainSslQueries(offset int) ([]models.Ssl, error) {
	query := "SELECT ioc, payload FROM public.ssl_profiler where ioc_type = 'domain' and payload ->> 'ssl_port_infos'::text is not null ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.Ssl // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.Ssl{}
		err := rows.Scan(
			&result.IoC,
			&result.Payload,
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

func (q *SSLQueries) GetSubdomainSslQueries(offset int) ([]models.Ssl, error) {

	query := "SELECT ioc, payload FROM public.ssl_profiler where ioc_type = 'subdomain' and payload ->> 'ssl_port_infos'::text is not null ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.Ssl // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.Ssl{}
		err := rows.Scan(
			&result.IoC,
			&result.Payload,
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
