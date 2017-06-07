package main

import (
	"flag"
	"os"
	"os/signal"

	log "github.com/ReviveNetwork/GoRevive/Log"
	"github.com/ReviveNetwork/GoRevive/core"
)

var (
	// BuildTime of the build provided by the build command
	BuildTime = "Not provided"
	// GitHash of build provided by the build command
	GitHash = "Not provided"
	// GitBranch of the build provided by the build command
	GitBranch = "Not provided"
	// compileVersion we are receiving by the build command
	CompileVersion = "0"
	// Version of the Application
	Version = "0.0.1"

	// MyConfig Default configuration
	MyConfig = Config{
		MysqlServer: "localhost:3306",
		MysqlUser:   "loginserver",
		MysqlDb:     "loginserver",
		MysqlPw:     "",
	}
)

func main() {
	var (
		configPath = flag.String("config", "config.yml", "Path to yml configuration file")
		logLevel   = flag.String("loglevel", "error", "LogLevel [error|warning|note|debug]")
	)
	flag.Parse()

	if CompileVersion != "0" {
		Version = Version + "." + CompileVersion
	}

	log.SetLevel(*logLevel)
	log.Notef("Starting up v%s - %s %s %s", Version, BuildTime, GitBranch, GitHash)

	MyConfig.Load(*configPath)
	// Startup done

	metricConnection := new(core.InfluxDB)
	err := metricConnection.New(MyConfig.InfluxDBHost, MyConfig.InfluxDBDatabase, MyConfig.InfluxDBUser, MyConfig.InfluxDBPassword)
	if err != nil {
		log.Fatalln("Error connecting to MetricsDB:", err)
	}

	dbConnection := new(core.DB)
	dbSQL, err := dbConnection.New(MyConfig.MysqlServer, MyConfig.MysqlDb, MyConfig.MysqlUser, MyConfig.MysqlPw)
	if err != nil {
		log.Fatalln("Error connecting to DB:", err)
	}

	loggingDBConnection := new(core.DB)
	loggingDBSQL, err := loggingDBConnection.New(MyConfig.MysqlLoggingServer, MyConfig.MysqlLoggingDb, MyConfig.MysqlLoggingUser, MyConfig.MysqlLoggingPw)
	if err != nil {
		log.Fatalln("Error connecting to logging DB:", err)
	}

	searchProvider := new(SearchProvider)
	searchProvider.New("SP", dbSQL, metricConnection)

	clientManager := new(ClientManager)
	clientManager.New("CM", dbSQL, loggingDBSQL, metricConnection)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for sig := range c {
		log.Noteln("Captured" + sig.String() + ". Shutting down.")
		os.Exit(0)
	}
}
