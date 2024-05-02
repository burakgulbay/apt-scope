package repositories

import (
	"fmt"
	"os"
)

// ConnectionURLBuilder func for building URL connection.
func ConnectionURLBuilder(n string) (string, error) {
	// Define URL to connection.
	var url string

	// Switch given names.
	switch n {
	case "postgres_relationship":
		// URL for PostgreSQL connection.

		dbHost := os.Getenv("RELATIONSHIP_POSTGRES_HOST")
		dbPort := os.Getenv("RELATIONSHIP_POSTGRES_PORT")
		dbUser := os.Getenv("RELATIONSHIP_POSTGRES_USER")
		dbPassword := os.Getenv("RELATIONSHIP_POSTGRES_PASS")
		dbName := os.Getenv("RELATIONSHIP_POSTGRES_DB")
		dbSslMode := os.Getenv("RELATIONSHIP_POSTGRES_SSL_MODE")

		url = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			dbSslMode,
		)
	case "postgres_twitter":
		// URL for PostgreSQL connection.

		dbHost := os.Getenv("TWITTER_POSTGRES_HOST")
		dbPort := os.Getenv("TWITTER_POSTGRES_PORT")
		dbUser := os.Getenv("TWITTER_POSTGRES_USER")
		dbPassword := os.Getenv("TWITTER_POSTGRES_PASS")
		dbName := os.Getenv("TWITTER_POSTGRES_DB")
		dbSslMode := os.Getenv("TWITTER_POSTGRES_SSL_MODE")

		url = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			dbSslMode,
		)
	case "postgres_ssl":
		// URL for PostgreSQL connection.

		dbHost := os.Getenv("SSL_POSTGRES_HOST")
		dbPort := os.Getenv("SSL_POSTGRES_PORT")
		dbUser := os.Getenv("SSL_POSTGRES_USER")
		dbPassword := os.Getenv("SSL_POSTGRES_PASS")
		dbName := os.Getenv("SSL_POSTGRES_DB")
		dbSslMode := os.Getenv("SSL_POSTGRES_SSL_MODE")

		url = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			dbSslMode,
		)

	case "postgres_whois":
		// URL for PostgreSQL connection.

		dbHost := os.Getenv("WHOIS_POSTGRES_HOST")
		dbPort := os.Getenv("WHOIS_POSTGRES_PORT")
		dbUser := os.Getenv("WHOIS_POSTGRES_USER")
		dbPassword := os.Getenv("WHOIS_POSTGRES_PASS")
		dbName := os.Getenv("WHOIS_POSTGRES_DB")
		dbSslMode := os.Getenv("WHOIS_POSTGRES_SSL_MODE")

		url = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			dbSslMode,
		)
	case "postgres_blacklist":
		dbHost := os.Getenv("BLOCKLIST_POSTGRES_HOST")
		dbPort := os.Getenv("BLOCKLIST_POSTGRES_PORT")
		dbUser := os.Getenv("BLOCKLIST_POSTGRES_USER")
		dbPassword := os.Getenv("BLOCKLIST_POSTGRES_PASS")
		dbName := os.Getenv("BLOCKLIST_POSTGRES_DB")
		dbSslMode := os.Getenv("BLOCKLIST_POSTGRES_SSL_MODE")

		url = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			dbSslMode,
		)

	case "postgres_portscan":
		dbHost := os.Getenv("PORTSCAN_POSTGRES_HOST")
		dbPort := os.Getenv("PORTSCAN_POSTGRES_PORT")
		dbUser := os.Getenv("PORTSCAN_POSTGRES_USER")
		dbPassword := os.Getenv("PORTSCAN_POSTGRES_PASS")
		dbName := os.Getenv("PORTSCAN_POSTGRES_DB")
		dbSslMode := os.Getenv("PORTSCAN_POSTGRES_SSL_MODE")

		url = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			dbSslMode,
		)

	case "postgres_certstream":
		dbHost := os.Getenv("CERT_STREAM_POSTGRES_HOST")
		dbPort := os.Getenv("CERT_STREAM_POSTGRES_PORT")
		dbUser := os.Getenv("CERT_STREAM_POSTGRES_USER")
		dbPassword := os.Getenv("CERT_STREAM_POSTGRES_PASS")
		dbName := os.Getenv("CERT_STREAM_POSTGRES_DB")
		dbSslMode := os.Getenv("CERT_STREAM_POSTGRES_SSL_MODE")

		url = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			dbHost,
			dbPort,
			dbUser,
			dbPassword,
			dbName,
			dbSslMode,
		)

	default:
		// Return error message.
		return "", fmt.Errorf("connection name '%v' is not supported", n)
	}

	// Return connection URL.
	return url, nil
}
