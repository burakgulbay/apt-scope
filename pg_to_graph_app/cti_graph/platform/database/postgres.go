package database

import (
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib" // load pgx driver for PostgreSQL
	"github.com/jmoiron/sqlx"

	"cti_graph/pkg/repositories"
)

var DbRelationship *sqlx.DB
var DbTwitter *sqlx.DB
var DbSSL *sqlx.DB
var DbWhois *sqlx.DB
var DbBlacklist *sqlx.DB
var DbPortScan *sqlx.DB
var DbCertStream *sqlx.DB

func PostgreSQLConnectionRelationship() error {

	// Define database connection settings.

	maxConn, _ := strconv.Atoi(os.Getenv("RELATIONSHIP_POSTGRES_MAX_CONNECTIONS"))
	maxIdleConn, _ := strconv.Atoi(os.Getenv("RELATIONSHIP_POSTGRES_MAX_IDLE_CONNECTIONS"))
	maxLifetimeConn, _ := strconv.Atoi(os.Getenv("RELATIONSHIP_POSTGRES_MAX_LIFETIME_CONNECTIONS"))

	// Build PostgreSQL connection URL.
	postgresConnURL, err := repositories.ConnectionURLBuilder("postgres_relationship")
	if err != nil {
		return err
	}

	// Define database connection for PostgreSQL.
	DbRelationship, err = sqlx.Connect("pgx", postgresConnURL)
	if err != nil {
		return fmt.Errorf("error, not connected to database, %w", err)
	}

	// Set database connection settings:
	DbRelationship.SetMaxOpenConns(maxConn)                           // the default is 0 (unlimited)
	DbRelationship.SetMaxIdleConns(maxIdleConn)                       // defaultMaxIdleConns = 2
	DbRelationship.SetConnMaxLifetime(time.Duration(maxLifetimeConn)) // 0, connections are reused forever

	// Try to ping database.
	if err := DbRelationship.Ping(); err != nil {
		defer DbRelationship.Close() // close database connection
		return fmt.Errorf("error, not sent ping to database, %w", err)
	}

	return nil

}

func PostgreSQLConnectionTwitter() error {

	// Define database connection settings.

	maxConn, _ := strconv.Atoi(os.Getenv("TWITTER_POSTGRES_MAX_CONNECTIONS"))
	maxIdleConn, _ := strconv.Atoi(os.Getenv("TWITTER_POSTGRES_MAX_IDLE_CONNECTIONS"))
	maxLifetimeConn, _ := strconv.Atoi(os.Getenv("TWITTER_POSTGRES_MAX_LIFETIME_CONNECTIONS"))

	// Build PostgreSQL connection URL.
	postgresConnURL, err := repositories.ConnectionURLBuilder("postgres_twitter")
	if err != nil {
		return err
	}

	// Define database connection for PostgreSQL.
	DbTwitter, err = sqlx.Connect("pgx", postgresConnURL)
	if err != nil {
		return fmt.Errorf("error, not connected to database, %w", err)
	}

	// Set database connection settings:
	DbTwitter.SetMaxOpenConns(maxConn)                           // the default is 0 (unlimited)
	DbTwitter.SetMaxIdleConns(maxIdleConn)                       // defaultMaxIdleConns = 2
	DbTwitter.SetConnMaxLifetime(time.Duration(maxLifetimeConn)) // 0, connections are reused forever

	// Try to ping database.
	if err := DbTwitter.Ping(); err != nil {
		defer DbTwitter.Close() // close database connection
		return fmt.Errorf("error, not sent ping to database, %w", err)
	}

	return nil

}

func PostgreSQLConnectionSSL() error {

	// Define database connection settings.

	maxConn, _ := strconv.Atoi(os.Getenv("SSL_POSTGRES_MAX_CONNECTIONS"))
	maxIdleConn, _ := strconv.Atoi(os.Getenv("SSL_POSTGRES_MAX_IDLE_CONNECTIONS"))
	maxLifetimeConn, _ := strconv.Atoi(os.Getenv("SSL_POSTGRES_MAX_LIFETIME_CONNECTIONS"))

	// Build PostgreSQL connection URL.
	postgresConnURL, err := repositories.ConnectionURLBuilder("postgres_ssl")
	if err != nil {
		return err
	}

	// Define database connection for PostgreSQL.
	DbSSL, err = sqlx.Connect("pgx", postgresConnURL)
	if err != nil {
		return fmt.Errorf("error, not connected to database, %w", err)
	}

	// Set database connection settings:
	DbSSL.SetMaxOpenConns(maxConn)                           // the default is 0 (unlimited)
	DbSSL.SetMaxIdleConns(maxIdleConn)                       // defaultMaxIdleConns = 2
	DbSSL.SetConnMaxLifetime(time.Duration(maxLifetimeConn)) // 0, connections are reused forever

	// Try to ping database.
	if err := DbSSL.Ping(); err != nil {
		defer DbSSL.Close() // close database connection
		return fmt.Errorf("error, not sent ping to database, %w", err)
	}

	return nil

}

func PostgreSQLConnectionWhois() error {

	// Define database connection settings.

	maxConn, _ := strconv.Atoi(os.Getenv("WHOIS_POSTGRES_MAX_CONNECTIONS"))
	maxIdleConn, _ := strconv.Atoi(os.Getenv("WHOIS_POSTGRES_MAX_IDLE_CONNECTIONS"))
	maxLifetimeConn, _ := strconv.Atoi(os.Getenv("WHOIS_POSTGRES_MAX_LIFETIME_CONNECTIONS"))

	// Build PostgreSQL connection URL.
	postgresConnURL, err := repositories.ConnectionURLBuilder("postgres_whois")
	if err != nil {
		return err
	}

	// Define database connection for PostgreSQL.
	DbWhois, err = sqlx.Connect("pgx", postgresConnURL)
	if err != nil {
		return fmt.Errorf("error, not connected to database, %w", err)
	}

	// Set database connection settings:
	DbWhois.SetMaxOpenConns(maxConn)                           // the default is 0 (unlimited)
	DbWhois.SetMaxIdleConns(maxIdleConn)                       // defaultMaxIdleConns = 2
	DbWhois.SetConnMaxLifetime(time.Duration(maxLifetimeConn)) // 0, connections are reused forever

	// Try to ping database.
	if err := DbWhois.Ping(); err != nil {
		defer DbWhois.Close() // close database connection
		return fmt.Errorf("error, not sent ping to database, %w", err)
	}

	return nil

}

func PostgreSQLConnectionBlocklists() error {

	maxConn, _ := strconv.Atoi(os.Getenv("BLOCKLIST_POSTGRES_MAX_CONNECTIONS"))
	maxIdleConn, _ := strconv.Atoi(os.Getenv("BLOCKLIST_POSTGRES_MAX_IDLE_CONNECTIONS"))
	maxLifetimeConn, _ := strconv.Atoi(os.Getenv("BLOCKLIST_POSTGRES_MAX_LIFETIME_CONNECTIONS"))

	// Build PostgreSQL connection URL.
	postgresConnURL, err := repositories.ConnectionURLBuilder("postgres_blacklist")
	if err != nil {
		return err
	}

	// Define database connection for PostgreSQL.
	DbBlacklist, err = sqlx.Connect("pgx", postgresConnURL)
	if err != nil {
		return fmt.Errorf("error, not connected to database, %w", err)
	}

	// Set database connection settings:
	DbBlacklist.SetMaxOpenConns(maxConn)                           // the default is 0 (unlimited)
	DbBlacklist.SetMaxIdleConns(maxIdleConn)                       // defaultMaxIdleConns = 2
	DbBlacklist.SetConnMaxLifetime(time.Duration(maxLifetimeConn)) // 0, connections are reused forever

	// Try to ping database.
	if err := DbBlacklist.Ping(); err != nil {
		defer DbBlacklist.Close() // close database connection
		return fmt.Errorf("error, not sent ping to database, %w", err)
	}

	return nil

}

func PostgreSQLConnectionPortScan() error {

	maxConn, _ := strconv.Atoi(os.Getenv("PORTSCAN_POSTGRES_MAX_CONNECTIONS"))
	maxIdleConn, _ := strconv.Atoi(os.Getenv("PORTSCAN_POSTGRES_MAX_IDLE_CONNECTIONS"))
	maxLifetimeConn, _ := strconv.Atoi(os.Getenv("PORTSCAN_POSTGRES_MAX_LIFETIME_CONNECTIONS"))

	// Build PostgreSQL connection URL.
	postgresConnURL, err := repositories.ConnectionURLBuilder("postgres_portscan")
	if err != nil {
		return err
	}

	// Define database connection for PostgreSQL.
	DbPortScan, err = sqlx.Connect("pgx", postgresConnURL)
	if err != nil {
		return fmt.Errorf("error, not connected to database, %w", err)
	}

	// Set database connection settings:
	DbPortScan.SetMaxOpenConns(maxConn)                           // the default is 0 (unlimited)
	DbPortScan.SetMaxIdleConns(maxIdleConn)                       // defaultMaxIdleConns = 2
	DbPortScan.SetConnMaxLifetime(time.Duration(maxLifetimeConn)) // 0, connections are reused forever

	// Try to ping database.
	if err := DbPortScan.Ping(); err != nil {
		defer DbPortScan.Close() // close database connection
		return fmt.Errorf("error, not sent ping to database, %w", err)
	}

	return nil
}

func PostgreSQLConnectionCertStream() error {

	maxConn, _ := strconv.Atoi(os.Getenv("CERT_STREAM_POSTGRES_MAX_CONNECTIONS"))
	maxIdleConn, _ := strconv.Atoi(os.Getenv("CERT_STREAM_POSTGRES_MAX_IDLE_CONNECTIONS"))
	maxLifetimeConn, _ := strconv.Atoi(os.Getenv("CERT_STREAM_POSTGRES_MAX_LIFETIME_CONNECTIONS"))

	// Build PostgreSQL connection URL.
	postgresConnURL, err := repositories.ConnectionURLBuilder("postgres_certstream")
	if err != nil {
		return err
	}

	// Define database connection for PostgreSQL.
	DbCertStream, err = sqlx.Connect("pgx", postgresConnURL)
	if err != nil {
		return fmt.Errorf("error, not connected to database, %w", err)
	}

	// Set database connection settings:
	DbCertStream.SetMaxOpenConns(maxConn)                           // the default is 0 (unlimited)
	DbCertStream.SetMaxIdleConns(maxIdleConn)                       // defaultMaxIdleConns = 2
	DbCertStream.SetConnMaxLifetime(time.Duration(maxLifetimeConn)) // 0, connections are reused forever

	// Try to ping database.
	if err := DbCertStream.Ping(); err != nil {
		defer DbCertStream.Close() // close database connection
		return fmt.Errorf("error, not sent ping to database, %w", err)
	}

	return nil
}
