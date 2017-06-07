package main

import (
	"database/sql"
	"strconv"
	"time"

	gs "github.com/ReviveNetwork/GoRevive/GameSpy"
	log "github.com/ReviveNetwork/GoRevive/Log"
	"github.com/ReviveNetwork/GoRevive/core"
)

type SearchProvider struct {
	name          string
	socket        *gs.Socket
	eventsChannel chan gs.SocketEvent
	db            *sql.DB
	iDB           *core.InfluxDB
	batchTicker   *time.Ticker
}

// New creates and starts a new SearchProvider
func (sP *SearchProvider) New(name string, db *sql.DB, iDB *core.InfluxDB) {
	var err error

	sP.socket = new(gs.Socket)
	sP.name = name
	sP.db = db
	sP.iDB = iDB
	sP.eventsChannel, err = sP.socket.New(sP.name, "29901")

	if err != nil {
		log.Errorln(err)
	}

	// Collect metrics every 10 seconds
	sP.batchTicker = time.NewTicker(time.Second * 1)
	go func() {
		for range sP.batchTicker.C {
			sP.collectMetrics()
		}
	}()

	go sP.run()
}

func (sP *SearchProvider) collectMetrics() {
	// Create a point and add to batch
	tags := map[string]string{"clients": "clients-total", "server": "SearchProvider", "version": Version}
	fields := map[string]interface{}{
		"clients": len(sP.socket.Clients),
	}

	sP.iDB.AddMetric("clients_total", tags, fields)
}

func (sP *SearchProvider) run() {
	for {
		select {
		case event := <-sP.eventsChannel:
			switch {
			case event.Name == "client.command.nicks":
				go sP.nicks(event.Data.(gs.EventClientCommand))
			case event.Name == "client.command.check":
				go sP.check(event.Data.(gs.EventClientCommand))
			default:
				log.Debugln(event)
			}
		}
	}
}

func (sP *SearchProvider) check(event gs.EventClientCommand) {
	nick, okNick := event.Command.Message["nick"]
	if !okNick {
		event.Client.WriteError("0", "Invalid query!")
		return
	}

	log.Noteln("Check\t", nick, event.Client.IpAddr)

	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	stmt, err := sP.db.Prepare("SELECT pid FROM revive_soldiers WHERE nickname=? AND game=?")
	defer stmt.Close()
	if err != nil {
		event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		return
	}

	var pid int

	err = stmt.QueryRow(nick, "battlefield2").Scan(&pid)
	if err != nil {
		event.Client.WriteError("256", "Invalid username. Account does not exist!")
		return
	}

	event.Client.Write("\\cur\\0\\pid\\" + strconv.Itoa(pid) + "\\final\\")
}

func (sP *SearchProvider) nicks(event gs.EventClientCommand) {
	var passMD5 string

	email, okEmail := event.Command.Message["email"]
	pass, okPass := event.Command.Message["pass"]
	passenc, okPassenc := event.Command.Message["passenc"]
	if !okEmail || (!okPass && !okPassenc) {
		event.Client.WriteError("0", "Invalid query!")
		return
	}

	if okPass {
		passMD5 = gs.Hash(pass)
	} else if okPassenc {
		decodedPass, err := gs.DecodePassword(passenc)
		if err != nil {
			event.Client.WriteError("0", "Invalid password!")
			return
		}
		passMD5 = gs.Hash(decodedPass)
	}

	log.Noteln("Nicks\t", email, event.Client.IpAddr)

	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	stmt, err := sP.db.Prepare("SELECT username FROM web_users WHERE email=? AND password=?")
	defer stmt.Close()
	if err != nil {
		event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		return
	}

	rows, err := stmt.Query(email, passMD5)
	if err != nil {
		event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		return
	}

	var usernames []string
	for rows.Next() {
		var username string
		err := rows.Scan(&username)
		if err != nil {
			event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
			return
		}
		usernames = append(usernames, username)
	}

	var out = "\\nr\\" + strconv.Itoa(len(usernames))

	for _, user := range usernames {
		out = out + "\\nick\\" + user + "\\uniquenick\\" + user
	}

	out = out + "\\ndone\\final\\"
	event.Client.Write(out)
}
