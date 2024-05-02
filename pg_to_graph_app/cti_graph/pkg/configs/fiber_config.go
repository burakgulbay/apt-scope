package configs

import (
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
)

func FiberConfig() fiber.Config {
	// Define server settings.
	readDurationInt64, err := strconv.ParseInt(os.Getenv("FIBER_READ_TIMEOUT"), 10, 64)
	if err != nil {
		panic(err)
	}

	writeDurationInt64, err := strconv.ParseInt(os.Getenv("FIBER_WRITE_TIMEOUT"), 10, 64)
	if err != nil {
		panic(err)
	}

	// Return Fiber configuration.
	return fiber.Config{
		ReadTimeout:  time.Second * time.Duration(readDurationInt64),
		WriteTimeout: time.Second * time.Duration(writeDurationInt64),
	}

}
