package main

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	gs "github.com/ReviveNetwork/GoRevive/GameSpy"
	log "github.com/ReviveNetwork/GoRevive/Log"
)

type LogEnum string

const (
	LOG_LOGIN             LogEnum = "login"
	LOG_LOGIN_BANNED      LogEnum = "login_banned"
	LOG_LOGIN_UNCONFIRMED LogEnum = "login_unconfirmed"
	LOG_LOGIN_FAILED      LogEnum = "login_failed"
	LOG_LOGOUT            LogEnum = "logout"
	LOG_CLOSE             LogEnum = "close"
	LOG_CLOSE_ERRPR       LogEnum = "close_error"
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
}

// New creates and starts a new ClientManager
func (cM *ClientManager) New(name string, db *sql.DB, loggingDB *sql.DB) {
	var err error

	cM.socket = new(gs.Socket)
	cM.name = name
	cM.db = db
	cM.loggingDB = loggingDB
	cM.eventsChannel, err = cM.socket.New(cM.name, "29900")

	if err != nil {
		log.Errorln(err)
	}

	go cM.run()
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
		}
	}
}

func (cM *ClientManager) insertLog(uid int, pid int, ip string, username string, log_type LogEnum) {
	stmt, err := cM.loggingDB.Prepare("INSERT INTO logs_gamespy_auth (uid, pid, ip, username, log_type, shard) VALUES (?, ?, INET_ATON(?), ?, ?, ?)")
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

func (cM *ClientManager) newClient(event gs.EventNewClient) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

	event.Client.State.ClientChallenge = gs.BF2RandomUnsafe(5)
	event.Client.Write("\\lc\\1\\challenge\\" + event.Client.State.ClientChallenge + "\\id\\1\\final\\")
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

	if challenge != event.Client.State.ClientChallenge {
		err := event.Client.WriteError("0", "Wrong challenge.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}
	event.Client.State.ClientResponse = response

	stmt, err := cM.db.Prepare("SELECT t1.web_id, t1.pid, t2.username, t2.password, t2.game_country, t2.email, t2.banned, t2.confirmed_em FROM revive_soldiers t1 LEFT JOIN web_users t2 ON t1.web_id=t2.id WHERE t1.nickname = ? AND game = ?")
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

	responseVerify := password + strings.Repeat(" ", 50) + uniqueNick + event.Client.State.ClientChallenge + password
	responseVerify = gs.Hash(responseVerify)

	if event.Client.State.ClientResponse != responseVerify {
		log.Noteln("Login Failure", event.Client.IpAddr, event.Client.State.PlyName, "Password: "+password)
		cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP, event.Client.State.Username, LOG_LOGIN_FAILED)
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
		fmt.Println("Char: ", runeName[nameIndex])
		fmt.Println("Index: ", ((runeName[nameIndex]^session)&0xff)%256)
		fmt.Println("Operator: ", (session >> 8))
		fmt.Println("Crc: ", gs.CrcLookup[((runeName[nameIndex]^session)&0xff)%256])
		tmpSession := session >> 8
		session = gs.CrcLookup[((runeName[nameIndex]^session)&0xff)%256] ^ (tmpSession)
		fmt.Println("Result:", session)

		nameIndex = nameIndex + 1
	}

	log.Noteln("Login Success", event.Client.IpAddr, event.Client.State.PlyName)
	err = event.Client.Write("\\lc\\2\\sesskey\\" + string(session) + " \\proof\\" + responseVerify + "\\userid\\" + strconv.Itoa(event.Client.State.PlyPid) + "\\profileid\\" + strconv.Itoa(event.Client.State.PlyPid) + "\\uniquenick\\" + event.Client.State.PlyName + "\\lt\\" + gs.BF2RandomUnsafe(22) + "__\\id\\1\\final\\")
	if err != nil {
		log.Noteln("Client left during writing error")
	}

	if !event.Client.State.Confirmed {
		confirmedTimer := time.NewTimer(time.Second)
		go func() {
			<-confirmedTimer.C
			cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP, event.Client.State.Username, LOG_LOGIN_UNCONFIRMED)
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
			cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP, event.Client.State.Username, LOG_LOGIN_BANNED)
			err := event.Client.WriteError("256", "Sorry! Your account has been banned from Revive BF2. Please visit battlelog.co to appeal.")
			if err != nil {
				log.Noteln("Client left during writing error")
			}
		}()

		return
	}

	// Login Successful
	cM.insertLog(event.Client.State.BattlelogID, event.Client.State.PlyPid, event.Client.IpAddr.(*net.TCPAddr).IP, event.Client.State.Username, LOG_LOGIN)

	stmt, err = cM.db.Prepare("UPDATE revive_soldiers SET online = 1, ip = INET_ATON(?) WHERE pid=? AND game=?")
	if err != nil {
		err := event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}
	_, err = stmt.Exec(event.Client.IpAddr.(*net.TCPAddr).IP, event.Client.State.PlyPid, "battlefield2")
	if err != nil {
		err := event.Client.WriteError("0", "The login service is having an issue reaching the database. Please try again in a few minutes.")
		if err != nil {
			log.Noteln("Client left during writing error")
		}
		return
	}
}

func (cM *ClientManager) getProfile(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}

}

func (cM *ClientManager) updatePro(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}
}

func (cM *ClientManager) logout(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}
}

func (cM *ClientManager) newUser(event gs.EventClientCommand) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}
}

func (cM *ClientManager) close(event gs.EventClientClose) {
	if !event.Client.IsActive {
		log.Noteln("Client left")
		return
	}
}
