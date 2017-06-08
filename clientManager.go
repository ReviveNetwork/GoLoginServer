package main

import (
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	gs "github.com/ReviveNetwork/GoRevive/GameSpy"
	log "github.com/ReviveNetwork/GoRevive/Log"
	"github.com/ReviveNetwork/GoRevive/core"
)

type LogEnum string

const (
	LOG_LOGIN             LogEnum = "login"
	LOG_LOGIN_BANNED      LogEnum = "login_banned"
	LOG_LOGIN_UNCONFIRMED LogEnum = "login_unconfirmed"
	LOG_LOGIN_FAILED      LogEnum = "login_failed"
	LOG_LOGOUT            LogEnum = "logout"
	LOG_CLOSE             LogEnum = "close"
	LOG_CLOSE_ERROR       LogEnum = "close_error"
)

func (s *LogEnum) Scan(src interface{}) error {
	if src == nil {
		return errors.New("This field cannot be NULL")
	}

	if stringStatus, ok := src.([]byte); ok {
		*s = LogEnum(string(stringStatus[:]))

		return nil
	}

	return errors.New("Cannot convert enum to string")
}

func (s LogEnum) Value() (driver.Value, error) {
	return []byte(s), nil
}

type ClientManager struct {
	name          string
	socket        *gs.Socket
	eventsChannel chan gs.SocketEvent
	db            *sql.DB
	loggingDB     *sql.DB
	iDB           *core.InfluxDB
	batchTicker   *time.Ticker
}

// New creates and starts a new ClientManager
func (cM *ClientManager) New(name string, db *sql.DB, loggingDB *sql.DB, iDB *core.InfluxDB) {
	var err error

	cM.socket = new(gs.Socket)
	cM.name = name
	cM.db = db
	cM.loggingDB = loggingDB
	cM.iDB = iDB
	cM.eventsChannel, err = cM.socket.New(cM.name, "29900")

	if err != nil {
		log.Errorln(err)
	}

	// Collect metrics every 10 seconds
	cM.batchTicker = time.NewTicker(time.Second * 1)
	go func() {
		for range cM.batchTicker.C {
			cM.collectMetrics()
		}
	}()

	go cM.run()
}

func (cM *ClientManager) collectMetrics() {
	// Create a point and add to batch
	tags := map[string]string{"clients": "clients-total", "server": "ClientManager", "version": Version}
	fields := map[string]interface{}{
		"clients": len(cM.socket.Clients),
	}

	cM.iDB.AddMetric("clients_total", tags, fields)
}

func (cM *ClientManager) run() {
	for {
		select {
		case event := <-cM.eventsChannel:
			switch {
			case event.Name == "newClient":
				go cM.newClient(event.Data.(gs.EventNewClient))
			case event.Name == "client.command.login":
				go cM.login(event.Data.(gs.EventClientCommand))
			case event.Name == "client.command.getprofile":
				go cM.getProfile(event.Data.(gs.EventClientCommand))
			case event.Name == "client.command.updatepro":
				go cM.updatePro(event.Data.(gs.EventClientCommand))
			case event.Name == "client.command.logout":
				go cM.logout(event.Data.(gs.EventClientCommand))
			case event.Name == "client.command.newuser":
				go cM.newUser(event.Data.(gs.EventClientCommand))
			case event.Name == "client.close":
				go cM.close(event.Data.(gs.EventClientClose))
			default:
				log.Debugln(event)
			}
		default:
			runtime.Gosched()
		}
	}
}

func (cM *ClientManager) insertLog(uid int, pid int, ip string, username string, log_type LogEnum) {
	stmt, err := cM.loggingDB.Prepare("INSERT INTO logs_gamespy_auth (uid, pid, ip, username, log_type, shard) VALUES (?, ?, INET_ATON(?), ?, ?, ?)")
	defer stmt.Close()
	if err != nil {
		log.Errorln("Error with logging DB: ", err)
		return
	}
	_, err = stmt.Exec(uid, pid, ip, username, log_type, "0-0")
	if err != nil {
		log.Errorln("Error with logging DB: ", err)
		return
	}
}

func (cM *ClientManager) heartBeat(event gs.EventNewClient) {
	if !event.Client.IsActive {
		event.Client.State.HeartTicker.Stop()
		return
	}

	event.Client.Write("revive")
}

func (cM *ClientManager) newClient(event gs.EventNewClient) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	log.Noteln("Client connecting")

	event.Client.State.ServerChallenge = hex.EncodeToString([]byte(gs.BF2RandomUnsafe(5)))
	event.Client.Write("\\lc\\1\\challenge\\" + event.Client.State.ServerChallenge + "\\id\\1\\final\\")

	// Start Heartbeat
	event.Client.State.HeartTicker = time.NewTicker(time.Second * 10)
	go func() {
		for range event.Client.State.HeartTicker.C {
			cM.heartBeat(event)
		}
	}()
}

func (cM *ClientManager) login(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	challenge, okChallenge := event.Command.Message["challenge"]
	response, okResponse := event.Command.Message["response"]
	uniqueNick, okUniqueNick := event.Command.Message["uniquenick"]

	if !okChallenge || !okResponse || !okUniqueNick {
		err := event.Client.WriteError("0", "Login query missing a variable.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}

	event.Client.State.ClientChallenge = challenge
	event.Client.State.ClientResponse = response

	stmt, err := cM.db.Prepare("SELECT t1.web_id, t1.pid, t2.username, t2.password, t2.game_country, t2.email, t2.banned, t2.confirmed_em FROM revive_soldiers t1 LEFT JOIN web_users t2 ON t1.web_id=t2.id WHERE t1.nickname = ? AND game = ?")
	defer stmt.Close()
	if err != nil {
		err := event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}

	var password string

	err = stmt.QueryRow(uniqueNick, "battlefield2").Scan(&event.Client.State.BattlelogID, &event.Client.State.PlyPid, &event.Client.State.Username, &password, &event.Client.State.PlyCountry, &event.Client.State.PlyEmail, &event.Client.State.Banned, &event.Client.State.Confirmed)
	if err != nil {
		err := event.Client.WriteError("256", "The username provided is not registered.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}
	event.Client.State.PlyName = event.Client.State.Username

	responseVerify := password + strings.Repeat(" ", 48) + uniqueNick + event.Client.State.ClientChallenge + event.Client.State.ServerChallenge + password
	responseVerify = gs.Hash(responseVerify)

	if event.Client.State.ClientResponse != responseVerify {
		log.Noteln("Login Failure", event.Client.IpAddr, event.Client.State.PlyName, "Password: "+password)
		cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP.String(), event.Client.State.Username, LOG_LOGIN_FAILED)
		err := event.Client.WriteError("256", "Incorrect password. Visit www.battlelog.co if you forgot your password.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}

	// Generate session key I fucking hate this thing
	var len = len(event.Client.State.PlyName)
	var nameIndex = 0
	var session rune
	runeName := []rune(event.Client.State.PlyName)

	for {
		len = len - 1
		if len < 0 {
			break
		}
		tmpSession := session >> 8
		session = gs.CrcLookup[((runeName[nameIndex]^session)&0xff)%256] ^ (tmpSession)
		nameIndex = nameIndex + 1
	}

	log.Noteln("Login Success", event.Client.IpAddr, event.Client.State.PlyName)
	responseVerify2 := password + strings.Repeat(" ", 48) + uniqueNick + event.Client.State.ServerChallenge + event.Client.State.ClientChallenge + password
	responseVerify2 = gs.Hash(responseVerify2)
	err = event.Client.Write("\\lc\\2\\sesskey\\" + strconv.Itoa(int(session)) + "\\proof\\" + responseVerify2 + "\\userid\\" + strconv.Itoa(event.Client.State.PlyPid) + "\\profileid\\" + strconv.Itoa(event.Client.State.PlyPid) + "\\uniquenick\\" + event.Client.State.PlyName + "\\lt\\" + gs.BF2RandomUnsafe(22) + "__\\id\\1\\final\\")
	if err != nil {
		log.Noteln("Client left during writing error")
	}

	if !event.Client.State.Confirmed {
		confirmedTimer := time.NewTimer(time.Second)
		go func() {
			<-confirmedTimer.C
			cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP.String(), event.Client.State.Username, LOG_LOGIN_UNCONFIRMED)
			err := event.Client.WriteError("256", "Sorry! You must confirm your Revive BF2 account before you can play Battlefield 2. Check your email for a confirmation link. If you did not recieve it, please login at https://battlelog.co to request a new one.")
			if err != nil {
				log.Noteln("Client left during writing error")
			}
		}()

		return
	}

	if event.Client.State.Banned {
		bannedTimer := time.NewTimer(time.Second)
		go func() {
			<-bannedTimer.C
			cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP.String(), event.Client.State.Username, LOG_LOGIN_BANNED)
			err := event.Client.WriteError("256", "Sorry! Your account has been banned from Revive BF2. Please visit battlelog.co to appeal.")
			if err != nil {
				log.Noteln("Client left during writing error")
			}
		}()

		return
	}

	// Login Successful
	cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP.String(), event.Client.State.Username, LOG_LOGIN)

	stmt, err = cM.db.Prepare("UPDATE revive_soldiers SET online = 1, ip = INET_ATON(?) WHERE pid=? AND game=?")
	defer stmt.Close()
	if err != nil {
		err := event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}
	_, err = stmt.Exec(event.Client.IpAddr.(*net.TCPAddr).IP.String(), event.Client.State.PlyPid, "battlefield2")
	if err != nil {
		err := event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}

	event.Client.State.HasLogin = true
}

func (cM *ClientManager) getProfile(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	pID := 2
	if event.Client.State.ProfileSent {
		pID = 5
	}

	log.Noteln("GetProfile", event.Client.IpAddr, event.Client.State.PlyName)
	event.Client.Write("\\pi\\\\profileid\\" + strconv.Itoa(event.Client.State.PlyPid) +
		"\\nick\\" + event.Client.State.PlyName +
		"\\userid\\" + strconv.Itoa(event.Client.State.PlyPid) +
		"\\email\\" + event.Client.State.PlyEmail +
		"\\sig\\" + gs.BF2RandomUnsafe(32) +
		"\\uniquenick\\" + event.Client.State.PlyName +
		"\\pid\\0\\firstname\\\\lastname\\" +
		"\\countrycode\\" + event.Client.State.PlyCountry +
		"\\birthday\\16844722\\lon\\0.000000\\lat\\0.000000\\loc\\" +
		"\\id\\" + strconv.Itoa(pID) +
		"\\\\final\\")
}

func (cM *ClientManager) updatePro(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	countryCode, okCountryCode := event.Command.Message["countrycode"]

	if !okCountryCode {
		event.Client.WriteError("0", "Invalid query! No country code specified.")
		return
	}

	log.Noteln("UpdateProfile", event.Client.IpAddr, event.Client.State.PlyName)
	stmt, err := cM.db.Prepare("UPDATE web_users SET game_country=? WHERE id=?")
	defer stmt.Close()
	if err != nil {
		log.Errorln("Error with DB: ", err)
		return
	}
	_, err = stmt.Exec(countryCode, event.Client.State.BattlelogID)
	if err != nil {
		log.Errorln("Error with DB: ", err)
		return
	}
}

func (cM *ClientManager) logout(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	event.Client.State.LoggedOut = true
	cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP.String(), event.Client.State.Username, LOG_LOGOUT)
	event.Client.Close()
}

func (cM *ClientManager) newUser(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	event.Client.WriteError("516", "In-game registration is not available. Please visit battlelog.co to register.")
}

func (cM *ClientManager) close(event gs.EventClientClose) {
	if !event.Client.State.HasLogin {
		return
	}

	cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP.String(), event.Client.State.Username, LOG_CLOSE)

	stmt, err := cM.db.Prepare("UPDATE revive_soldiers SET online = 0 WHERE pid=? AND game=?")
	defer stmt.Close()
	if err != nil {
		log.Errorln("Error with DB: ", err)
		return
	}
	_, err = stmt.Exec(event.Client.State.PlyPid, "battlefield2")
	if err != nil {
		log.Errorln("Error with DB: ", err)
		return
	}

	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}
}

func (cM *ClientManager) error(event gs.EventClientError) {
	log.Noteln("Client threw an error: ", event.Error)
}
