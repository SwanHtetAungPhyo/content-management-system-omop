package main

import (
	"encoding/json"
	"github.com/orgs/one-project-one-month/repositories/cms/apigateway/internal/types"
	"log"
	"os"
)

func main() {
	config := loadConfig()
	gateway := types.NewGateway(config)
	log.Fatal(gateway.Start())
}

func loadConfig() *types.Config {
	data, err := os.ReadFile("config.json")
	if err != nil {
		panic(err.Error())
	}
	var config *types.Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatal(err.Error())
		return nil
	}

	return config
}
