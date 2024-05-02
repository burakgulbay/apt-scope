package models

import (
	"github.com/jmoiron/sqlx/types"
)

type Twitter struct {
	IoC     string         `json:"ioc"`
	Payload types.JSONText `json:"payload"`
}
