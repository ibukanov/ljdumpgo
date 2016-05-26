package main

import (
	"bytes"
	"bufio"
	"crypto/md5"
	"encoding/json"
	"encoding/xml"
	"fmt"
	//"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kolo/xmlrpc"
	"github.com/hydrogen18/stalecucumber"
)

func log(format string, a ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, a...))
}

func logerr(err error, format string, a ...interface{}) {
	var s = fmt.Sprintf(format, a...)
	if s == "" {
		if err == nil {
			panic("format cannot be empty when err is nil")
		}
		s = err.Error()
		err = nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s - %s\n", s, err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", s)
	}
}

func fuseErr(err, err2 error) error {
	if err == nil {
		return err2
	}
	if err2 == nil {
		return err
	}
	return fmt.Errorf("%s; %s", err.Error(), err2.Error())
}

type Report struct {
	message string
	err error
	combined []*Report
}

func ReportMsg(format string, a ...interface{}) *Report {
	return &Report{
		fmt.Sprintf(format, a...),
		nil,
		nil,
	}
}

func WrapErr(err error, format string, a ...interface{}) *Report {
	if err == nil {
		panic("err cannot be nil")
	}
	return &Report{
		fmt.Sprintf(format, a...),
		err,
		nil,
	}
}

func CombineReports(r1, r2 *Report) *Report {
	if r1 == nil {
		return r2
	}
	if r2 == nil {
		return r1
	}
	return &Report{
		"",
		nil,
		[]*Report{r1, r2},
	}
}

func (r *Report) AsText() string {
	if r.combined != nil {
		s := ""
		for _, r2 := range(r.combined) {
			s += r2.AsText()
		}
		return s
	}
	if r.err != nil {
		return fmt.Sprintf("ERROR: %s - %s\n", r.message, r.err.Error())
	}
	return fmt.Sprintf("ERROR: %s\n", r.message)
}

func writeFileTempRename(filePath string, data []byte) error {
	tmp := filePath + ".tmp"
	if err := ioutil.WriteFile(tmp, data, 0666); err != nil {
		return err
	}
	if err := os.Rename(tmp, filePath); err != nil {
		return err
	}
	return nil
}


const defaultConfigFile = "ljdump.config"

// Use dot so it never coinside with LJ journal name
const accountDataDirName = "account.data"
const accountDataDBFileName = "account.json"

type Config struct {
	server string
	username string
	journals []string
	password string
	dumpDir string
	accountDataDir string
}

type StoredConfig struct {
	Server string `xml:"server"`
	Username string `xml:"username"`
	Journals []string `xml:"journal"`
	Password *string `xml:"password"`
	PasswordFile *string `xml:"passwordFile"`
}

func loadConfig() (*Config, *Report) {

	var configFile = os.Getenv("LJDUMP_CONFIG")
	if configFile == "" {
		configFile = defaultConfigFile
	}
	
	configBytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, WrapErr(err, "failed to read %s", defaultConfigFile)
	}

	var storedConfig StoredConfig
	err = xml.Unmarshal(configBytes, &storedConfig)
	if err != nil {
		return nil, WrapErr(err, "failed to parse %s as JSON", defaultConfigFile)
	}
	var config = new(Config)

	const urlCompabilitySuffix = "/interface/xmlrpc"
	if strings.HasSuffix(storedConfig.Server, urlCompabilitySuffix) {
		storedConfig.Server = storedConfig.Server[0 : len(storedConfig.Server) - len(urlCompabilitySuffix)]
	}
	if storedConfig.Server == "" {
		return nil, ReportMsg("server is empty string")
	}	
	config.server = storedConfig.Server

	if storedConfig.Username == "" {
		return nil, ReportMsg("username is empty string")
	}
	config.username = storedConfig.Username

	if len(storedConfig.Journals) == 0 {
		config.journals = []string { config.username }
	} else {
		for i, journal := range(storedConfig.Journals) {
			if journal == "" {
				return nil, ReportMsg("journal %d is empty string", i + 1)
			}
		}
		config.journals = storedConfig.Journals
	}

	if storedConfig.Password != nil {
		config.password = *storedConfig.Password
	} else if storedConfig.PasswordFile != nil {
		var file = *storedConfig.PasswordFile
		var passwordBytes []byte
		if file == "-" {
			log("reading password from stdin (on tty it is echoed)")
			passwordBytes, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				return nil, WrapErr(err, "failed to read password from stdin")
			}
		} else {
			passwordBytes, err = ioutil.ReadFile(file)
			if err != nil {
				return nil, WrapErr(err, "failed to read password from %s", file)
			}
		}
		config.password = strings.TrimRight(string(passwordBytes), "\r\n")
	} else {
		return nil, ReportMsg("one of password or passwordFile must be given")
	}

	config.dumpDir = "."
	config.accountDataDir = filepath.Join(config.dumpDir, accountDataDirName)
	
	return config, nil
}

type JournalContext struct {
    config *Config
	session *ljSession
	name string
	dir string
	db JournalDB
	shouldWriteDB bool
	origDbLastSync string
	newEntries int
	newComments int
}

const journalDBFileName = "db.json"

func NewJournalContext(session *ljSession, journalName string) *JournalContext {
	dir := filepath.Join(session.config.dumpDir, journalName)
	jcx := &JournalContext{
		config: session.config,
		session: session,
		name: journalName,
		dir: dir,
	}
	return jcx
}

type CommentId int64
type UserId int64

type CommentMeta struct {
	posterId UserId
	state string
}

type accountData struct {
	fileCounter int
	pictureDefaultUrl string
	pictureUrlFileMap map[string]string
	pictureKeywordUrlMap map[string]string
}

type storedAccountData struct {
	
	FileCounter int `json:"fileCounter"`

	PictureDefaultUrl string `json:"pictureDefaultUrl"`
	
	// Store user info map as separated arrays for compactness and sorted order
	PictureUrlFileMap struct {
		Url []string `json:"url"`
		Filename []string `json:"filename"`
	} `json:"pictureUrlFileMap"`

	PictureKeywordUrlMap struct {
		Keyword []string `json:"keyword"`
		Url []string `json:"url"`
	} `json:"pictureKeywordUrlMap"`
}

type JournalDB struct {
	lastSync string
	userMap map[UserId]string
	commentMap map[CommentId]CommentMeta
}


type StoredJournalDB struct {
	LastSync string `json:"lastSync"`
	
	// Store user info map as separated arrays for compactness and stable order
	Users struct {
		Id []UserId `json:"id"`
		User []string `json:"user"`
	} `json:"users"`

	// Store comments map as separated arrays for compactness and stable order
	CommentMeta struct {
		Id []CommentId `json:"id"`
		PosterId []UserId `json:"posterid"`
		State []string `json:"state"`
	} `json:"commentMeta"`
}

type SortUsersById struct { *StoredJournalDB }

func (a SortUsersById) Len() int { return len(a.Users.Id) }
func (a SortUsersById) Less(i, j int) bool { return a.Users.Id[i] < a.Users.Id[j] }
func (a SortUsersById) Swap(i, j int) {
	a.Users.Id[i], a.Users.Id[j] = a.Users.Id[j], a.Users.Id[i]
	a.Users.User[i], a.Users.User[j] = a.Users.User[j], a.Users.User[i]
}

type SortCommentMeta struct { *StoredJournalDB }

func (a SortCommentMeta) Len() int { return len(a.CommentMeta.Id) }
func (a SortCommentMeta) Less(i, j int) bool { return a.CommentMeta.Id[i] < a.CommentMeta.Id[j] }
func (a SortCommentMeta) Swap(i, j int) {
	a.CommentMeta.Id[i], a.CommentMeta.Id[j] = a.CommentMeta.Id[j], a.CommentMeta.Id[i]
	a.CommentMeta.PosterId[i], a.CommentMeta.PosterId[j] = a.CommentMeta.PosterId[j], a.CommentMeta.PosterId[i]
	a.CommentMeta.State[i], a.CommentMeta.State[j] = a.CommentMeta.State[j], a.CommentMeta.State[i]
}

func parseUserId(idstr string) (UserId, error) {
	if idstr == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(idstr, 10, 64)
	if err != nil {
		err = fmt.Errorf("failed to parse user id string as int64 - %s", err.Error())
	}
	return UserId(id), err
}

func getSortedMapKeyValueArrays(m map[string]string) (keys []string, values []string) {
	keyValues := make([]string, len(m) * 2)
	keys = keyValues[ : len(m)]
	values = keyValues[len(m) : ]
	i := 0
	for key := range(m) {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	for i, key := range(keys) {
		values[i] = m[key]
	}
	return
}

func getMapFromKeyValueArrays(keys []string, values []string) (map[string]string, *Report) {
	if len(keys) != len(values) {
		return nil, ReportMsg("map key and value array have different length, %d != %d", len(keys), len(values))
	}
	m := make(map[string]string, len(keys))
	for i, key := range(keys) {
		m[key] = values[i]
	}
	return m, nil
}

func writeAccountData(accountData *accountData, config *Config) *Report {
	var store storedAccountData
	store.FileCounter = accountData.fileCounter
	store.PictureDefaultUrl = accountData.pictureDefaultUrl
	
	store.PictureUrlFileMap.Url, store.PictureUrlFileMap.Filename =
		getSortedMapKeyValueArrays(accountData.pictureUrlFileMap)

	store.PictureKeywordUrlMap.Keyword, store.PictureKeywordUrlMap.Url =
		getSortedMapKeyValueArrays(accountData.pictureKeywordUrlMap)

	data, err := json.Marshal(&store)
	if err != nil {
		panic(err)
	}

	dbpath := filepath.Join(config.accountDataDir, accountDataDBFileName)
	if err := writeFileTempRename(dbpath, data); err != nil {
		return WrapErr(err, "failed to write account data db file %s", dbpath)
	}
	return nil
}

func readAccountData(config *Config) (*accountData, *Report) {
	accountData := &accountData{}
	dbpath := filepath.Join(config.accountDataDir, accountDataDBFileName)
	dbdata, err := ioutil.ReadFile(dbpath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, WrapErr(err, "")
		}
		// Initialize maps so entries can be added
		accountData.pictureUrlFileMap = make(map[string]string)
		accountData.pictureKeywordUrlMap = make(map[string]string)
		return accountData, nil
	}
	var store storedAccountData
	if err := json.Unmarshal(dbdata, &store); err != nil {
		return nil, WrapErr(err, "error while parsing account data db %s as JSON data", dbpath)
	}
	accountData.fileCounter = store.FileCounter
	accountData.pictureDefaultUrl = store.PictureDefaultUrl

	var r *Report
	accountData.pictureUrlFileMap, r = getMapFromKeyValueArrays(
		store.PictureUrlFileMap.Url,
		store.PictureUrlFileMap.Filename,
	)
	if r != nil {
		return nil, r
	}
	accountData.pictureKeywordUrlMap, r = getMapFromKeyValueArrays(
		store.PictureKeywordUrlMap.Keyword,
		store.PictureKeywordUrlMap.Url,
	)
	if r != nil {
		return nil, r
	}
	return accountData, nil
}


func writeJournalDB(jcx *JournalContext) *Report {
	var store StoredJournalDB
	store.LastSync = jcx.db.lastSync

	store.Users.Id = make([]UserId, len(jcx.db.userMap))
	store.Users.User = make([]string, len(jcx.db.userMap))
	
	var i = 0
	for userId, user := range(jcx.db.userMap) {
		store.Users.Id[i] = userId
		store.Users.User[i] = user
		i++
	}
	sort.Stable(SortUsersById{&store})

	store.CommentMeta.Id = make([]CommentId, len(jcx.db.commentMap))
	store.CommentMeta.PosterId = make([]UserId, len(jcx.db.commentMap))
	store.CommentMeta.State = make([]string, len(jcx.db.commentMap))
	
	i = 0
	for id, value := range(jcx.db.commentMap) {
		store.CommentMeta.Id[i] = id
		store.CommentMeta.PosterId[i] = value.posterId
		store.CommentMeta.State[i] = value.state
		i++
	}
	sort.Stable(SortCommentMeta{&store})

	data, err := json.Marshal(&store)
	if err != nil {
		panic(err)
	}

	var dbpath = filepath.Join(jcx.dir, journalDBFileName)
	if err := writeFileTempRename(dbpath, data); err != nil {
		return WrapErr(err, "failed to write journal db file %s", dbpath)
	}
	return nil
}

func readJournalDB(jcx *JournalContext) *Report {
	var dbpath = filepath.Join(jcx.dir, journalDBFileName)
	dbdata, err := ioutil.ReadFile(dbpath)
	if err != nil {
		if !os.IsNotExist(err) {
			return WrapErr(err, "")
		}
	}
	if len(dbdata) == 0 {
		log("Converting Python Journal DB into %s", dbpath)
		err = readPythonLastRunFile(jcx)
		if err == nil {
			err = readPythonCommentMeta(jcx)
			if err == nil {
				err = readPythonUserMap(jcx)
			}
		}
		if err != nil {
			return WrapErr(err, "error while reading old python-generated DB files for journal %s", jcx.name)
		}
		if r := writeJournalDB(jcx); r != nil {
			return r
		}
	} else {
		var store StoredJournalDB
		err = json.Unmarshal(dbdata, &store)
		if err != nil {
			return WrapErr(err, "error while parsing journal db %s as JSON data", dbpath)
		}
		if len(store.Users.User) != len(store.Users.Id) {
			return ReportMsg("length mismatch between users.user(%d) and user.id(%d) in %s",
				len(store.Users.User), len(store.Users.Id), dbpath)
		}
		if len(store.CommentMeta.PosterId) != len(store.CommentMeta.Id) {
			return ReportMsg("length mismatch between commentMeta.posterId(%d) and commentMeta.Id(%d) in %s",
				len(store.CommentMeta.PosterId), len(store.CommentMeta.Id), dbpath)
		}
		if len(store.CommentMeta.State) != len(store.CommentMeta.Id) {
			return ReportMsg("length mismatch between commentMeta.stats(%d) and commentMeta.Id(%d) in %s",
				len(store.CommentMeta.State), len(store.CommentMeta.Id), dbpath)
		}

		jcx.db.lastSync = store.LastSync

		jcx.db.userMap = make(map[UserId]string, len(store.Users.Id))
		for i := range(store.Users.Id) {
			jcx.db.userMap[store.Users.Id[i]] = store.Users.User[i]
		}

		jcx.db.commentMap = make(map[CommentId]CommentMeta, len(store.CommentMeta.Id))
		for i := range(store.CommentMeta.Id) {
			var commentId = store.CommentMeta.Id[i]
			jcx.db.commentMap[commentId] = CommentMeta{
				store.CommentMeta.PosterId[i],
				store.CommentMeta.State[i],
			}
		}
	}
	jcx.origDbLastSync = jcx.db.lastSync
	return nil
}

func readPythonLastRunFile(jcx *JournalContext) error {
	jcx.db.lastSync = ""
	
	var p = filepath.Join(jcx.dir, ".last")
	var f, err = os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return err
	}

	// Read only first line with time sync as maxid is derived from comments meta data
	var s = bufio.NewScanner(f)
	if s.Scan() {
		jcx.db.lastSync = s.Text()
	}
	return fuseErr(s.Err(), f.Close())
}


func readPythonCommentMeta(jcx *JournalContext) error {
	var p = filepath.Join(jcx.dir, "comment.meta")
	var file, err = os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return err
	}

	var pythonData map[interface{}]interface{}
	pythonData, err = stalecucumber.Dict(stalecucumber.Unpickle(file))
	if err == nil {
		jcx.db.commentMap = make(map[CommentId]CommentMeta, len(pythonData))
		for key, value := range(pythonData) {
			var idnum, keyOk = key.(int64)
			if !keyOk {
				err = fmt.Errorf("Unexpected key type %T in %s", key, p)
				break
			} 
			var structValue, valueOk = value.(map[interface{}]interface{})
			if !valueOk {
				err = fmt.Errorf("Unexpected value type %T in %s", value, p)
				break
			}
			var posterIdStr, posterIdOk = structValue["posterid"].(string)
			if !posterIdOk {
				err = fmt.Errorf("Unexpected posterid type %T in %s", structValue["posterid"], p)
				break
			}
			var state, stateOk = structValue["state"].(string)
			if !stateOk {
				err = fmt.Errorf("Unexpected state type %T in %s", structValue["state"], p)
				break
			}
			var posterId UserId
			posterId, err = parseUserId(posterIdStr)
			if err != nil {
				break
			}
			
			var id = CommentId(idnum)
			jcx.db.commentMap[id] = CommentMeta{posterId, state}
		}
	}
	return fuseErr(err, file.Close())
}

func readPythonUserMap(jcx *JournalContext) error {
	var p = filepath.Join(jcx.dir, "user.map")
	var file, err = os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return err
	}

	var pythonData map[string]interface{}
	pythonData, err = stalecucumber.DictString(stalecucumber.Unpickle(file))
	if err == nil {
		jcx.db.userMap = make(map[UserId]string, len(pythonData))
		for userIdStr, userValue := range(pythonData) {
			var user, userOk = userValue.(string)
			if !userOk {
				err = fmt.Errorf("Unexpected user name type %T in %s", userValue, p)
				break
			}
			var userId UserId
			userId, err = parseUserId(userIdStr)
			if err != nil {
				break
			}
			jcx.db.userMap[userId] = user
		}
	}
	return fuseErr(err, file.Close())
}

func writeLJEventDump(jcx *JournalContext, eventType byte, itemId int64,  event map[string]interface{}) *Report {

	buf := bytes.NewBufferString(xml.Header)
	var tmparea []byte

	var serializeTagValue func (tag string, v interface{}) *Report

	// For now allow valid XML names with only ascii characters
	isValidXmlTagName := func(s string) bool {
		for j, c := range(s) {
			if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || c == '_' {
				continue
			}
			if j != 0 {
				if ('0' <= c && c <= '9') || c == '-' || c == '.' {
					continue
				}
			}
			return false
		}
		return true
	}

	// xml.EscapeText escapes way too much
	addEscapeXmlValue := func(s []byte) {
		for _, b := range(s) {
			replace := ""
			switch (b) {
			case '<':
				replace = "&lt;"
			case '>':
				replace = "&gt;"
			case '&':
				replace = "&amp;"
			default:
				buf.WriteByte(b)
				continue
			}
			buf.WriteString(replace)
		}
	}

	serializeMap := func(m map[string]interface{}) *Report {
		keys := make([]string, len(m))
		i := 0
		for key := range(m) {
			if !isValidXmlTagName(key) {
				return ReportMsg("cannot serialize map key '%s' as XML name", key)
			}
			keys[i] = key
			i++
		}

		// Ensure key order independent from the runtime presentation of map
		sort.Strings(keys)
		for _, key := range(keys) {
			value := m[key]
			if array, isArray := value.([]interface{}); isArray {
				for _, elem := range(array) {
					serializeTagValue(key, elem)
				}
			} else {
				serializeTagValue(key, value)
			}
		}
		return nil
	}

	serializeTagValue = func (tag string, value interface{}) *Report {
		buf.WriteByte('<')
		buf.WriteString(tag)
		if value == nil {
			buf.WriteString("/>\n")
			return nil
		}
		buf.WriteByte('>')
		switch v := value.(type) {
		case int:
			tmparea = strconv.AppendInt(tmparea[0:0], int64(v), 10)
			buf.Write(tmparea)
		case int64:
			tmparea = strconv.AppendInt(tmparea[0:0], v, 10)
			buf.Write(tmparea)
		case string:
			tmparea = append(tmparea[0:0], v...)
			addEscapeXmlValue(tmparea)
		case map[string]interface{}:
			buf.WriteByte('\n')
			if r := serializeMap(v); r != nil {
				return r
			}
		default:
			return ReportMsg("unsupported %T type in received LJEvent", v)
		}
		buf.WriteString("</")
		buf.WriteString(tag)
		buf.WriteString(">\n")
		return nil
	}

	buf.WriteString("<event>\n")
	if r := serializeMap(event); r != nil {
		return r
	}
	buf.WriteString("</event>\n")

	eventPath := filepath.Join(jcx.dir, fmt.Sprintf("%c-%d", eventType, itemId))
	if err := writeFileTempRename(eventPath, buf.Bytes()); err != nil {
		return WrapErr(err, "")
	}
	return nil
}

type ljSession struct {
	config *Config
	client http.Client
	lastRequestTime time.Time
	loginCookie string
}

// Get LJ session cookie,
// http://www.livejournal.com/doc/server/ljp.csp.flat.protocol.html
func openLJSession(config *Config) (*ljSession, *Report) {
	session := &ljSession{
		config: config,
	}
	session.client.Transport = session	

	calculateChallengeResponse := func(challenge string) string {
		var passhash = fmt.Sprintf("%x", md5.Sum([]byte(config.password)))
		return fmt.Sprintf("%x", md5.Sum([]byte(challenge + passhash)))
	}

	v := url.Values{}
	v.Set("mode", "getchallenge")
	responseMap, r := callLJFlatInterface(session, v)
	if r != nil {
		return nil, r
	}
	challenge := responseMap["challenge"]
	if challenge == "" {
		return nil, ReportMsg("no challenge is resposne")
	}
	v = url.Values{}
	v.Set("mode", "sessiongenerate")
	v.Set("user", config.username)
	v.Set("auth_method", "challenge")
	v.Set("auth_challenge", challenge)
	v.Set("auth_response", calculateChallengeResponse(challenge))
	v.Set("ipfixed", "1")

	log("Logging in to %s", config.server)
	responseMap, r = callLJFlatInterface(session, v)
	if r != nil {
		return nil, r
	}

    session.loginCookie = responseMap["ljsession"]
	if session.loginCookie == "" {
		return nil, ReportMsg("failed to login to %s, perhaps the password was invalid", config.server)
	}
	return session, nil
}

func callLJFlatInterface(session *ljSession, values url.Values) (map[string]string, *Report) {
	posturl := session.config.server + "/interface/flat"	
	resp, err := session.client.PostForm(posturl, values)
	if err != nil {
		return nil, WrapErr(err, "")
	}

	s := bufio.NewScanner(resp.Body)
	nameValueMap := make(map[string]string)
	name := ""
	firstLine := ""
	for s.Scan() {
		if name == "" {
			name = s.Text()
			if name == "" {
				break
			}
			if firstLine == "" {
				firstLine = name
			}
		} else {
			nameValueMap[name] = s.Text()
			name = ""
		}
	}
	err = fuseErr(s.Err(), resp.Body.Close())
	if err != nil {
		return nil, WrapErr(err, "")
	}

	status := nameValueMap["success"]
	if status != "OK" {
		errmsg := nameValueMap["errmsg"]
		if errmsg == "" {
			return nil, ReportMsg(
				"Server Error with flat protocol, try again later. mode=%s status=%s\n\t%s",
				values.Get("mode"), status, firstLine,
			)
		} else {
			return nil, ReportMsg(
				"Server reported error with flat protocol mode=%s status=%s\n\t%s",
				values.Get("mode"), status, errmsg,
			)
		}
	}
	return nameValueMap, nil
}

func callLJFlatMathod(
	method string, session *ljSession, nameValuePairs ...string,
) (map[string]string, *Report) {
	v := url.Values{}
	v.Set("mode", method)
	v.Set("ver", "1")
	v.Set("user", session.config.username)
	v.Set("auth_method", "cookie")
	for i := 0; i != len(nameValuePairs); i+=2 {
		v.Set(nameValuePairs[i], nameValuePairs[i + 1])
	}
	return callLJFlatInterface(session, v)
}

func getLJFlatArray(arrayName string, m map[string]string) ([]string, *Report) {
	key := arrayName+"_count"
	countStr := m[key]
	if countStr == "" {
		return nil, ReportMsg("no %s key in LJ flat response", key)
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return nil, WrapErr(err, "value '%s' for %s key in LJ flat response is not an integer", countStr, key)
	}
	if count < 0 {
		return nil, ReportMsg("value '%s' for %s key in LJ flat response is negative", countStr, key)
	}
	a := make([]string, count)
	for i := 0; i < count; i++ {
		key = fmt.Sprintf("%s_%d", arrayName, i + 1)
		value, present := m[key]
		if !present {
			return nil, ReportMsg("no %s key in LJ flat response", key)
		}
		a[i] = value
	}
	return a, nil
}

func (session *ljSession) RoundTrip(req *http.Request) (*http.Response, error) {
	// Remove the referer that http.Client sets on redirect as lj will
	// reports with it.
	req.Header.Del("Referer")

	// Set login and agent headers. Doing it here also avoids
	// https://github.com/golang/go/issues/4800

	req.Header.Set("User-Agent", "ljdump-port-to-golang; igor@mir2.org")
	if session.loginCookie != "" {
		req.Header.Set("Cookie", "ljsession="+session.loginCookie)
		req.Header.Set("X-LJ-Auth", "cookie")
	}

	if false {
		s, _ := httputil.DumpRequestOut(req, true)
		fmt.Println(string(s))
	}

	// rate-limit number of requests to avoid blacklisting by IP
	const minimalTimeBetweenRequests = 200 * time.Millisecond
	newRequestTime := time.Now()
	if !session.lastRequestTime.IsZero() {
		sinceLastRequest := newRequestTime.Sub(session.lastRequestTime)
		if sinceLastRequest < minimalTimeBetweenRequests {
			time.Sleep(minimalTimeBetweenRequests - sinceLastRequest)
		}
	}
	session.lastRequestTime = newRequestTime
		
	res, err := http.DefaultTransport.RoundTrip(req)
	if false {
		s, _ := httputil.DumpResponse(res, true)
		fmt.Println(string(s))
	}
	
	return res, err
}

// Only Unicode letters, digits, dashes and underscores
var blacklistedPictureFilenameChars = regexp.MustCompile(`[^\p{L}\p{N}_-]`)

func convertPictureKeywordToFilename(keyword string) string {
	return blacklistedPictureFilenameChars.ReplaceAllString(keyword, "_")
}

func dumpAccountData(session *ljSession) *Report {

	log("Fetching user info for: %s", session.config.username)

	if err := os.MkdirAll(session.config.accountDataDir, 0777); err != nil {
		return WrapErr(err, "failed to create directory for account data %s", session.config.accountDataDir)
	}

	accountData, r := readAccountData(session.config)
	if r != nil {
		return r
	}
	updated := false
	
	responseMap, r := callLJFlatMathod(
		"login", session,
		"getpickws", "1",
		"getpickwurls", "1",
	)
	if r != nil {
		return r
	}
	keywordArrayName, urlsArrayName := "pickw", "pickwurl"
	
	keywords, r := getLJFlatArray(keywordArrayName, responseMap)
	if r != nil {
		return r
	}
	urls, r := getLJFlatArray(urlsArrayName, responseMap)
	if r != nil {
		return r
	}
	if len(keywords) != len(urls) {
		return ReportMsg(
			"%s and %s arrays in LJ flat response have different lengths, %sd != %d",
			keywordArrayName, urlsArrayName, len(keywords) != len(urls),
		)
	}

	// For deafult picture keywordIndex is -1
	fetchAnsStorePictureUrl := func(keywordIndex int, url string) *Report {

		// Fetch only unknown URLS
		if url == "" || accountData.pictureUrlFileMap[url] != "" {
			return nil 
		}
		
		keyword := ""
		if keywordIndex >= 0 {
			keyword = keywords[keywordIndex]
			if keyword == "" {
				log("WARNING: got empty keyword for user picture %s", url)
				return nil
			}
		}
		if keyword == "" {
			log("Fetching new default user picture %s", url)
		} else {
			log("Fetching new '%s' user picture %s", keyword, url)
		}
		
		// Use default client, not a custom, to avoid appliing cookie etc headers.
		// Also ignore any download-related errors
		res, err := http.Get(url)
		if err == nil {
			var data []byte
			data, err = ioutil.ReadAll(res.Body)
			err2 := res.Body.Close()
			if err == nil {
				err = err2
			}
			if err == nil {
				extension := ".bin"
				contentType := res.Header.Get("Content-Type")
				if contentType != "" {
					extensions, err2 := mime.ExtensionsByType(contentType)
					if err2 == nil && len(extensions) != 0 {
						extension = extensions[0]
					}
				}
				separator, fileName := "", ""
				if keyword != "" {
					separator = "-"
					fileName = convertPictureKeywordToFilename(keyword)
				}
				accountData.fileCounter++
				picturePath := filepath.Join(session.config.accountDataDir, fmt.Sprintf(
					"user-picture-%d%s%s%s", accountData.fileCounter, separator, fileName, extension,
				))
				if err := writeFileTempRename(picturePath, data); err != nil {
					return WrapErr(err, "")
				}
				accountData.pictureUrlFileMap[url] = picturePath
				if keyword == "" {
					accountData.pictureDefaultUrl = url
				} else {
					accountData.pictureKeywordUrlMap[keyword] = url
					
				}
				updated = true
			}
		}
		if err != nil {
			log("WARNING: failed to download userpic %s", url)
		}
		return nil
	}

	if r := fetchAnsStorePictureUrl(-1, responseMap["defaultpicurl"]); r != nil {
		return r
	}
	for i, url := range(urls) {
		if r := fetchAnsStorePictureUrl(i, url); r != nil {
			return r
		}
	}

	if updated {
		if r := writeAccountData(accountData, session.config); r != nil {
			return r
		}
	}
	
	return nil
}

func dumpJournalPosts(jcx *JournalContext) *Report {

	log("Fetching journal entries for: %s", jcx.name)

	type LJLoginResult struct {
		Pickws []string `xmlrpc:"pickws"`
		Pickwurls []string `xmlrpc:"pickwurls"`
		Defaultpicurl string `xmlrpc:"defaultpicurl"`
	}
	
	type LJSyncItem struct {
		Item string `xmlrpc:"item"`
		Action string `xmlrpc:"action"`
		Time string `xmlrpc:"time"`
	}
	
	type LJSyncItemsResult struct {
		SyncItems []LJSyncItem `xmlrpc:"syncitems"`
	}

	/*
	type LJEvent struct {
		ItemId int64 `xmlrpc:"itemid"`
		EventTime string `xmlrpc:"eventtime"`
		Security string `xmlrpc:"security"`
		AllowMask string `xmlrpc:"allowmask"`
		Subject string `xmlrpc:"subject"`
		Event string `xmlrpc:"event"`
		Anum string `xmlrpc:"anum"`
		Url string `xmlrpc:"url"`
		Poster string `xmlrpc:"poster"`
		Props []LJProp `xmlrpc:"props"`
	}
    */

	type LJEvent map[string]interface{}
	
	type LJGeteventsResult struct {
		Events []LJEvent `xmlrpc:"events"`
	}

	var client, err = xmlrpc.NewClient(
		jcx.config.server+"/interface/xmlrpc",
		jcx.session.client.Transport,
	)
	if err != nil {
		return WrapErr(err, "")
	}
	defer client.Close()
	
	callWithLogin := func(method string, input map[string]interface{}, result interface{}) *Report {
		input["username"] = jcx.config.username
		input["ver"] = 1
		input["auth_method"] = "cookie"
		
		err := client.Call("LJ.XMLRPC." + method, input, result)
		if err != nil {
			return WrapErr(err, "")
		}
		return nil
	}

	for {
		var syncItemsParams = map[string]interface{}{
			"lastsync": jcx.db.lastSync,
			"usejournal": jcx.name,
		}
		var syncItemsResult LJSyncItemsResult
		if r := callWithLogin("syncitems", syncItemsParams, &syncItemsResult); r != nil {
			return r
		}
        if len(syncItemsResult.SyncItems) == 0 {
            break
		}

		// Use slow fetch one-by-one loop as bulk retrival of events
		// through getevents with selecttype=syncitems fails as the
		// server rejects repeated calls to get more items and
		// http://www.livejournal.com/doc/server/ljp.csp.xml-rpc.getevents.html
		// is very unclear.

		for _, item := range(syncItemsResult.SyncItems) {
			// check that Item is in TypeLetter-Number format as we use that as a file path.
			if len(item.Item) < 3 || item.Item[1] != '-' {
				log("WARNING: invalid SyncItems id %s", item.Item[1])
				continue
			}
			itemid, err := strconv.ParseInt(item.Item[2:], 10, 64)
			if err != nil {
				log("WARNING: invalid SyncItems id %s", item.Item[1])
				continue
			}
            if item.Item[0] == 'L' {
                log("Fetching journal entry %s (%s)", item.Item, item.Action)

				var geteventsParams = map[string]interface{}{
					"selecttype": "one",
					"itemid": itemid,
					"usejournal": jcx.name,
					"lineendings": "unix",
				}
				var geteventsResult LJGeteventsResult
				if r := callWithLogin("getevents", geteventsParams, &geteventsResult); r != nil {
					return r
				}
				if len(geteventsResult.Events) == 0 {
					return ReportMsg("Unexpected empty item %s", item.Item)
				}
				if r := writeLJEventDump(jcx, item.Item[0], itemid, geteventsResult.Events[0]); r != nil {
					return r
				}
				jcx.newEntries++
			}
            jcx.db.lastSync = item.Time
			jcx.shouldWriteDB = true
		}
	}
	return nil
}

// See http://www.livejournal.com/doc/server/ljp.csp.export_comments.html
func dumpJournalComments(jcx *JournalContext) *Report {
    log("Fetching journal comments for: %s", jcx.name)

	var authas = ""
    if jcx.config.username != jcx.name {
        authas = fmt.Sprintf("&authas=%s", url.QueryEscape(jcx.name))
	}

	type LJCommentMeta struct {
		Id CommentId `xml:"id,attr"`
		PosterId UserId `xml:"posterid,attr"`		
		State string `xml:"state,attr"`
	}

	type LJComment struct {
		Id CommentId `xml:"id,attr"`
		PosterId UserId `xml:"posterid,attr"`		
		State string `xml:"state,attr"`
		JItemId int64 `xml:"jitemid,attr"`

		// Use string, not CommentId, as this can be empty
		ParentId string `xml:"parentid,attr"`
		Subject string `xml:"subject"`
		Body string `xml:"body"`
		Date string `xml:"date"`
	}

	type LJUserMap struct {
		Id UserId `xml:"id,attr"`
		User string `xml:"user,attr"`
	}

	type LJCommentMetaChunk struct {
		XMLName xml.Name `xml:"livejournal"`
		MaxId CommentId `xml:"maxid"`
		Comments []LJCommentMeta `xml:"comments>comment"`
		UserMaps []LJUserMap `xml:"usermaps>usermap"`
	}

	type LJCommentChunk struct {
		XMLName xml.Name `xml:"livejournal"`
		Comments []LJComment `xml:"comments>comment"`
	}

	type CommentRecord struct {
		Id CommentId `xml:"id"`
		State string `xml:"state"`
		User string `xml:"user"`

		// Use string, not CommentId, as this can be empty
		ParentId string `xml:"parentid"`
		Date string `xml:"date"`
		Subject string `xml:"subject"`
		Body string `xml:"body"`
	}

	type CommentFile struct {
		XMLName xml.Name `xml:"comments"`
		Comments []CommentRecord `xml:"comment"`
	}

	newComments := make(map[CommentId]CommentMeta)
	newCommentUsers := make(map[UserId]string)

	var maxStoredCommentId CommentId = -1
	for id := range(jcx.db.commentMap) {
		if maxStoredCommentId < id {
			maxStoredCommentId = id
		}
	}

	// TODO Check if we have some missing comments and downloads those
	// as well rather than assuming that we have everything betwen 1
	// and maxStoredCommentId.
	
	fetchCommentData := func(kind string, maxid CommentId, v interface{}) *Report {
		geturl := fmt.Sprintf(
			"%s/export_comments.bml?get=comment_%s&startid=%d%s",
			jcx.config.server,
			kind,
			maxid + 1,
			authas,
		)
		resp, err := jcx.session.client.Get(geturl)
		var data []byte
		if err == nil {
			data, err = ioutil.ReadAll(resp.Body)
			err = fuseErr(err, resp.Body.Close())
		}
		if err != nil {
			return WrapErr(err, "failed to read comment_%s response", kind)
		}

		err = xml.Unmarshal(data, v)
		if err != nil {
			return WrapErr(err, "failed to process comments_%s response, possibly not community maintainer?", kind)
		}
		return nil
	}

	newMaxId := maxStoredCommentId
	for {
		var metaChunk LJCommentMetaChunk
		if r := fetchCommentData("meta", newMaxId, &metaChunk); r != nil {
			return r
		}

		for i := range(metaChunk.Comments) {
			c := &metaChunk.Comments[i]
			newComments[c.Id] = CommentMeta{posterId: c.PosterId, state: c.State}
			if newMaxId < c.Id {
				newMaxId = c.Id
			}
		}
		for _, u := range(metaChunk.UserMaps) {
			newCommentUsers[u.Id] = u.User
		}
		if newMaxId >= metaChunk.MaxId {
			// We fetched all comment updates
			break
		}
	}

	maxFetchedId := maxStoredCommentId
	for {
		var chunk LJCommentChunk
		if r := fetchCommentData("body", maxFetchedId, &chunk); r != nil {
			return r
		}

		for i := range(chunk.Comments) {
			c := &chunk.Comments[i]
			var record = CommentRecord {
				Id: c.Id,
				ParentId: c.ParentId,
				Subject: c.Subject,
				Date: c.Date,
				Body: c.Body,
				State: c.State,
			}
			if record.State == "" {
				if commentMeta, present := newComments[c.Id]; present {
					record.State = commentMeta.state
				} else if commentMeta, present := jcx.db.commentMap[c.Id]; present {
					record.State = commentMeta.state
				}
			}
			if c.PosterId != 0 {
				if user, present := newCommentUsers[c.PosterId]; present {
					record.User = user
				} else if user, present := jcx.db.userMap[c.PosterId]; present {
					record.User = user
				}
			}
			if maxFetchedId < c.Id {
				maxFetchedId = c.Id
			}

			commentFilePath := filepath.Join(jcx.dir, fmt.Sprintf("C-%d", c.JItemId))
			olddata, err := ioutil.ReadFile(commentFilePath)

			var stored CommentFile
			if err != nil {
				if !os.IsNotExist(err) {
					return WrapErr(err, "error while reading old comments from %s", commentFilePath)
				}
			} else {
				err = xml.Unmarshal(olddata, &stored)
				if err != nil {
					return WrapErr(err, "failed to parse old comments from %s", commentFilePath)
				}
			}
			foundDup := false
			shouldStore := true
			for i := range(stored.Comments) {
				if stored.Comments[i].Id == record.Id {
					if stored.Comments[i] == record {
						log("comment id %d was already downloaded in %s",
							record.Id, commentFilePath)
						shouldStore = false
					} else {
						log("Warning: downloaded duplicate comment id %d with different content in %s",
							record.Id, commentFilePath)
						stored.Comments[i] = record
					}
					foundDup = true
					break
				}
			}
			if !foundDup {
				stored.Comments = append(stored.Comments, record)
			}
			if shouldStore {
				b := bytes.NewBufferString(xml.Header)
				enc := xml.NewEncoder(b)

				enc.Indent("", " ")
				if err := enc.Encode(&stored); err != nil {
					panic(err)
				}
				b.WriteByte('\n')
				if err = writeFileTempRename(commentFilePath, b.Bytes()); err != nil {
					return WrapErr(err, "")
				}
				jcx.newComments++
			}
		}
		if maxFetchedId >= newMaxId {
			break
		}
	}

	if len(newComments) != 0 || len(newCommentUsers) != 0 {
		// We succsefully downloaded new comments, update the meta now
		for commentId, commentMeta := range(newComments) {
			jcx.db.commentMap[commentId] = commentMeta
		}
		for userId, user := range(newCommentUsers) {
			jcx.db.userMap[userId] = user
		}
		jcx.shouldWriteDB = true
	}
	return nil
}

func dumpJournal(jcx *JournalContext) *Report {
	if r := readJournalDB(jcx); r != nil {
		return r
	}

	if err := os.MkdirAll(jcx.dir, 0777); err != nil {
		return WrapErr(err, "failed to create directory for journal %s", jcx.dir)
	}

	r := dumpJournalPosts(jcx) 
	if r == nil {
		r = dumpJournalComments(jcx)
	}
	if jcx.shouldWriteDB {
		r = CombineReports(r, writeJournalDB(jcx))
	}
	if r == nil {
		if jcx.origDbLastSync != "" {
			log("%d new entries, %d new comments (since %s)", jcx.newEntries, jcx.newComments, jcx.origDbLastSync)
		} else {
			log("%d new entries, %d new comments", jcx.newEntries, jcx.newComments)
		}
	}
	return r
}

func mainImpl() *Report {
	config, r := loadConfig()
	if r != nil {
		return r
	}
	session, r := openLJSession(config)
	if r != nil {
		return r
	}

	if r := dumpAccountData(session); r != nil {
		return r
	}
	
	for _, journal := range(config.journals) {
		if r := dumpJournal(NewJournalContext(session, journal)); r != nil {
			return r
		}
	}
	return nil
}


func main() {

	if r := mainImpl(); r != nil {
		fmt.Fprintf(os.Stderr, "%s", r.AsText())
		os.Exit(1)
	}
}
