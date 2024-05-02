package queries

import (
	"cti_graph/app/models"

	"github.com/jmoiron/sqlx"
)

type CertStreamQueries struct {
	*sqlx.DB
}

func (q *CertStreamQueries) GetCertStreamList(offset int, shardingTableName string) ([]models.CertStreamItem, error) {

	query := "select id, domain, payload, creation_time, creation_timestamp, last_seen_time, last_seen_timestamp from public." + shardingTableName + " where payload::text != 'null' ORDER BY creation_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.CertStreamItem // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.CertStreamItem{}
		err := rows.Scan(
			&result.ID,
			&result.Domain,
			&result.Payload,
			&result.CreationTime,
			&result.CreationTimestamp,
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
