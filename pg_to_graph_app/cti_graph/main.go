package main

import (
	"cti_graph/pkg/configs"
	"cti_graph/pkg/middlewares"
	"cti_graph/pkg/repositories"
	"cti_graph/pkg/routes"
	"cti_graph/pkg/utils"
	"cti_graph/platform/database"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func init() {
	godotenv.Load()

	repositories.GraphRepo.Driver = driver(os.Getenv("NEO4J_URI"), neo4j.BasicAuth(os.Getenv("NEO4J_USERNAME"), os.Getenv("NEO4J_PASSWORD"), ""))

	err := database.PostgreSQLConnectionRelationship()
	if err != nil {
		// TODO:  call log service
		panic(err)
	}

	err = database.PostgreSQLConnectionTwitter()
	if err != nil {
		// TODO:  call log service
		panic(err)
	}

	err = database.PostgreSQLConnectionSSL()
	if err != nil {
		// TODO:  call log service
		panic(err)
	}

	err = database.PostgreSQLConnectionWhois()
	if err != nil {
		// TODO:  call log service
		panic(err)
	}

	err = database.PostgreSQLConnectionBlocklists()
	if err != nil {
		// TODO:  call log service
		panic(err)
	}

	err = database.PostgreSQLConnectionPortScan()
	if err != nil {
		// TODO:  call log service
		panic(err)
	}

	// err = database.PostgreSQLConnectionCertStream()
	// if err != nil {
	// 	// TODO:  call log service
	// 	panic(err)
	// }

}

func main() {
	config := configs.FiberConfig()
	config.BodyLimit = 1024 * 1024 * 1024 // 1 GB file upload permitted
	// config.StreamRequestBody !!!!! bu konuyu araştır.
	// Define new Fiber app with config here:
	app := fiber.New(config)

	// Middlewares here:
	middlewares.FiberMiddleware(app) // Register Fiber's middleware for app.

	// Routes here:
	// routes.SwaggerRoute(app)  // Register a route for API Docs (Swagger).
	routes.PublicRoutes(app) // Register a public routes for app.

	routes.NotFoundRoute(app) // Register route for 404 Error.

	// Start fiber server (with graceful shutdown).
	utils.StartServerWithGracefulShutdown(app)
}

func driver(target string, token neo4j.AuthToken) neo4j.Driver {
	result, err := neo4j.NewDriver(target, token)
	if err != nil {
		panic(err)
	}
	return result
}
