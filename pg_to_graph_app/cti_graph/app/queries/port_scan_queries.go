package queries

import (
	"cti_graph/app/models"

	"github.com/jmoiron/sqlx"
)

type PortScanQueries struct {
	*sqlx.DB
}

func (q *PortScanQueries) GetIpPortScanList(offset int) ([]models.PortScanIp, error) {
	query := "select id, ioc_type, ioc, payload, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp from public.scanner where ioc_type = 'ip' and payload::text != 'null' ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.PortScanIp // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.PortScanIp{}
		err := rows.Scan(
			&result.ID,
			&result.IoCType,
			&result.IoC,
			&result.Payload,
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

func (q *PortScanQueries) GetDomainPortScanList(offset int) ([]models.PortScanDomain, error) {
	query := "select id, ioc_type, ioc, payload, first_seen_time, first_seen_timestamp, last_seen_time, last_seen_timestamp from public.scanner where ioc_type = 'domain' and payload::text != 'null' ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.PortScanDomain // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.PortScanDomain{}
		err := rows.Scan(
			&result.ID,
			&result.IoCType,
			&result.IoC,
			&result.Payload,
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
