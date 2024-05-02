package queries

import (
	"cti_graph/app/models"

	"github.com/jmoiron/sqlx"
)

type TwitterQueries struct {
	*sqlx.DB
}

func (q *TwitterQueries) GetTweetPosts(offset int) ([]models.Twitter, error) {
	query := "select ioc, payload from public.twitter_posts WHERE json_typeof(payload) != 'null' ORDER BY first_seen_time ASC OFFSET $1 LIMIT 999999999"

	rows, err := q.Query(query, offset)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var results []models.Twitter // bu listenin içinde zaten bir tane element olmak zorunda
	for rows.Next() {
		result := models.Twitter{}
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
