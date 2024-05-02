package database

import (
	"cti_graph/app/queries"
)

type Queries struct {
	*queries.CtiQueries
	*queries.TwitterQueries
	*queries.SSLQueries
	*queries.WhoisQueries
	*queries.BlacklistQueries
	*queries.PortScanQueries
	*queries.CertStreamQueries
}

func GetDBConnection() (*Queries, error) {

	return &Queries{
		CtiQueries:        &queries.CtiQueries{DB: DbRelationship},
		TwitterQueries:    &queries.TwitterQueries{DB: DbTwitter},
		SSLQueries:        &queries.SSLQueries{DB: DbSSL},
		WhoisQueries:      &queries.WhoisQueries{DB: DbWhois},
		BlacklistQueries:  &queries.BlacklistQueries{DB: DbBlacklist},
		PortScanQueries:   &queries.PortScanQueries{DB: DbPortScan},
		CertStreamQueries: &queries.CertStreamQueries{DB: DbCertStream},
	}, nil
}
