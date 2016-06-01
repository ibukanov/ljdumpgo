package linedb

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type encoderState int

const (
	encoderNewElem encoderState = 1 << iota
	encoderScalar
	encoderRowStart
	encoderRowAfterStart
)

type Encoder struct {
	state             encoderState
	error             error
	writer            io.Writer
	buffer            []byte
	tableFirstRowSize int
	tableRowSize      int
}

func NewByteEncoder() *Encoder {
	return NewEncoder(nil)
}

func NewEncoder(writer io.Writer) *Encoder {
	return &Encoder{
		state:  encoderNewElem,
		writer: writer,
		buffer: make([]byte, 0, 1024),
	}
}

var validNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z_0-9]*$`)

func isValidName(name string) bool {
	return validNamePattern.MatchString(name)
}

func checkValidName(name string) {
	if !isValidName(name) {
		panic(fmt.Errorf("'%s' does not match %s, the pattern for valid linedb names", name, validNamePattern))
	}
}

func (e *Encoder) checkState(stateBitset encoderState) {
	if e.state&stateBitset == 0 {
		panic(fmt.Errorf("unexpected state %d", e.state))
	}
}

func (e *Encoder) GetError() error {
	return e.error
}

func (e *Encoder) GetBytes() []byte {
	if e.writer != nil {
		panic("GetBytes can only be used with encoder without a Writer")
	}
	return e.buffer
}

func (e *Encoder) Flush() {
	e.checkState(encoderNewElem)
	if e.writer != nil && len(e.buffer) != 0 && e.error == nil {
		_, e.error = e.writer.Write(e.buffer)
		e.buffer = e.buffer[:0]
	}
}

func (e *Encoder) EmptyLine() {
	e.checkState(encoderNewElem)
	e.addLineEnd()
}

func (e *Encoder) Comment(text string) {
	if strings.IndexAny(text, "\r\n") >= 0 {
		panic("comment string cannoy contain line break chars")
	}
	e.checkState(encoderNewElem)
	e.buffer = append(e.buffer, "# "...)
	e.buffer = append(e.buffer, text...)
	e.addLineEnd()
}

func (e *Encoder) Scalar(name string) *Encoder {
	e.checkState(encoderNewElem)
	e.buffer = append(e.buffer, name...)
	e.buffer = append(e.buffer, ' ')
	e.state = encoderScalar
	return e
}

func (e *Encoder) Table(name string) {
	e.checkState(encoderNewElem)
	e.buffer = append(e.buffer, "@table "...)
	e.buffer = append(e.buffer, name...)
	e.addLineEnd()
	e.state = encoderRowStart
	e.tableFirstRowSize = -1
	e.tableRowSize = 0
}

func (e *Encoder) EndRow() {
	if e.state == encoderRowStart {
		panic("table cannot have empty rows")
	} else {
		e.checkState(encoderRowAfterStart)
	}
	if e.tableFirstRowSize < 0 {
		e.tableFirstRowSize = e.tableRowSize
	} else if e.tableFirstRowSize != e.tableRowSize {
		panic("Attempt to write a table row with less elements than in the first row")
	}
	e.addLineEnd()
	e.tableRowSize = 0
	e.state = encoderRowStart
}

func (e *Encoder) EndTable() {
	if e.state == encoderRowAfterStart {
		panic("missing EndRow call")
	} else {
		e.checkState(encoderRowStart)
	}
	e.buffer = append(e.buffer, "@end"...)
	e.addLineEnd()
	e.state = encoderNewElem
}

func (e *Encoder) AddInt(i int) *Encoder {
	return e.AddInt64(int64(i))
}

func (e *Encoder) AddInt64(i int64) *Encoder {
	e.beforeValueWrite()
	e.buffer = strconv.AppendInt(e.buffer, i, 10)
	e.afterValueWrite()
	return e
}

func (e *Encoder) AddString(s string) *Encoder {
	e.beforeValueWrite()
	shouldQuote := true
	if s != "" {
		firstRune, _ := utf8.DecodeRuneInString(s)
		if unicode.IsLetter(firstRune) || firstRune == '_' {
			if strings.IndexFunc(s, unicode.IsSpace) < 0 {
				e.buffer = append(e.buffer, s...)
				shouldQuote = false
			}
		}
	}
	if shouldQuote {
		e.buffer = strconv.AppendQuote(e.buffer, s)
	}
	e.afterValueWrite()
	return e
}

func (e *Encoder) addLineEnd() {
	e.buffer = append(e.buffer, '\n')
	if e.writer != nil && len(e.buffer) > 4096 && e.error == nil {
		_, e.error = e.writer.Write(e.buffer)
		e.buffer = e.buffer[:0]
	}
}

func (e *Encoder) beforeValueWrite() {
	if e.state == encoderRowAfterStart {
		e.buffer = append(e.buffer, ' ')
	} else if e.state == encoderRowStart {
		e.state = encoderRowAfterStart
	} else {
		e.checkState(encoderScalar)
	}
}

func (e *Encoder) afterValueWrite() {
	if e.state == encoderScalar {
		e.addLineEnd()
		e.state = encoderNewElem
	} else if e.state == encoderRowAfterStart {
		e.tableRowSize++
		if e.tableFirstRowSize >= 0 && e.tableFirstRowSize < e.tableRowSize {
			panic("Attempt to write more table row elements than in the first row")
		}
	}
}

type ItemKind int

const (
	NoItemKind ItemKind = iota
	ScalarItem
	TableItem
)

type Decoder struct {
	ItemKind
	ItemName     string
	error        error
	data         []byte
	currentLine  []byte
	insideScalar bool
	insideRow    bool
	atRowStart   bool
	rowCounter   int
}

func NewByteDecoder(data []byte) *Decoder {
	return &Decoder{
		data: data,
	}
}

func (d *Decoder) GetError() error {
	return d.error
}

func (d *Decoder) NextItem() bool {
	if d.error != nil {
		return false
	}
	if !d.readLine() {
		return false
	}
	token := d.nextCharsWithoutSpace()
	if token[0] == '@' {
		if string(token) != "@table" {
			d.error = fmt.Errorf("Unknown line keyword '%s'", token)
			return false
		}
		if len(d.currentLine) == 0 {
			d.error = fmt.Errorf("%s is not followed by name", token)
			return false
		}
		name := d.nextCharsWithoutSpace()
		if !isValidName(d.ItemName) {
			d.error = fmt.Errorf("%s %s is not a valid table name", token, name)
			return false
		}
		if len(d.currentLine) != 0 {
			d.error = fmt.Errorf("unexpected extra characters after %s %s", token, name)
			return false
		}
		d.ItemKind = TableItem
		d.ItemName = string(name)
		d.rowCounter = 0
		return true
	}
	d.ItemName = string(token)
	if !isValidName(d.ItemName) {
		d.error = fmt.Errorf("'%s' is not a valid scalar name", token)
		return false
	}
	if len(d.currentLine) == 0 {
		d.error = fmt.Errorf("scalar %s is not followed by a value", token)
		return false
	}
	d.ItemKind = ScalarItem
	d.insideScalar = true
	return true
}

func (d *Decoder) RowCounter() int {
	if d.ItemKind != TableItem {
		panic("call outside table context")
	}
	return d.rowCounter
}

func (d *Decoder) NextRow() bool {
	if d.ItemKind != TableItem {
		panic("call outside table context")
	}

	// If the current line is not read report an error unless we are
	// at the start of the first item. This allows to skip unknown for
	// application tables.
	if len(d.currentLine) != 0 && !d.atRowStart {
		d.error = fmt.Errorf("Unread row element")
		return false
	}
	if !d.readLine() {
		if d.error == nil {
			d.error = fmt.Errorf("Unterminated table")
		}
		return false
	}
	if d.currentLine[0] == '@' {
		token := d.nextCharsWithoutSpace()
		if string(token) != "@end" || len(d.currentLine) != 0 {
			d.error = fmt.Errorf("invalid table terminator format")
		}
		d.insideRow = false
		d.ItemKind = NoItemKind
		return false
	}
	d.insideRow = true
	d.atRowStart = true
	d.rowCounter++
	return true
}

func (d *Decoder) GetInt() int {
	i64 := d.GetInt64()
	i := int(i64)
	if int64(i) != i64 {
		d.error = fmt.Errorf("%d is outside int range", i64)
		i = 0
	}
	return i
}

func (d *Decoder) GetInt64() int64 {
	if !d.beforeValueRead() {
		return 0
	}
	token := d.nextCharsWithoutSpace()
	i, err := strconv.ParseInt(string(token), 10, 64)
	if err != nil {
		d.error = err
		return 0
	}
	d.afterValueRead()
	return i
}

func (d *Decoder) GetString() string {
	if !d.beforeValueRead() {
		return ""
	}
	var s string
	if d.currentLine[0] != '"' {
		firstRune, _ := utf8.DecodeRune(d.currentLine)
		if !unicode.IsLetter(firstRune) && firstRune != '_' {
			d.error = fmt.Errorf("String values must strt with unless they starts with letter or underscore")
			return ""
		}
		s = string(d.nextCharsWithoutSpace())
	} else {
		// Find the terminating quote
		i := 1
		for {
			if i == len(d.currentLine) {
				d.error = fmt.Errorf("unterminated string literal")
				return ""
			}
			if d.currentLine[i] == '"' {
				break
			}
			if d.currentLine[i] == '\\' {
				i++
				if i == len(d.currentLine) {
					d.error = fmt.Errorf("unterminated string literal")
					return ""
				}
			}
			_, n := utf8.DecodeRune(d.currentLine[i:])
			i += n
		}
		s = string(d.currentLine[0 : i+1])
		d.currentLine = d.currentLine[i+1:]
		d.skipLineWhitespace()

		s, d.error = strconv.Unquote(s)
		if d.error != nil {
			return ""
		}
	}
	d.afterValueRead()
	return s
}

// find next non-empty line that is not a comment.
func (d *Decoder) readLine() bool {
	if d.error != nil {
		return false
	}
	for len(d.data) != 0 {
		i := bytes.IndexByte(d.data, '\n')
		if i < 0 {
			d.currentLine = d.data
			d.data = nil
		} else {
			d.currentLine = d.data[0:i]
			d.data = d.data[i+1:]
		}
		if !utf8.Valid(d.currentLine) {
			d.error = fmt.Errorf(
				"input is not a valid UTF8, use string with \\x escapes to encode arbitrary binary data",
			)
			return false
		}
		d.skipLineWhitespace()

		// Ignore empty line or comments
		if len(d.currentLine) != 0 && d.currentLine[0] != '#' {
			return true
		}
	}
	return false
}

func (d *Decoder) beforeValueRead() bool {
	if d.error != nil {
		return false
	}
	if d.insideRow {
		d.atRowStart = false
	} else if !d.insideScalar {
		panic("Can only be called for scalar or row")
	}
	if len(d.currentLine) == 0 {
		d.error = fmt.Errorf("unexpected line end while looking for value")
		return false
	}
	
	return true
}

func (d *Decoder) afterValueRead() {
	if d.error != nil {
		return
	}
	if d.insideScalar {
		if len(d.currentLine) != 0 {
			d.error = fmt.Errorf("unexpected extra characters after scalar value")
			return
		}
		d.insideScalar = false
		d.ItemKind = NoItemKind
	}
}

func (d *Decoder) skipLineWhitespace() {
	d.currentLine = bytes.TrimLeftFunc(d.currentLine, unicode.IsSpace)
}

func (d *Decoder) nextCharsWithoutSpace() []byte {
	i := bytes.IndexFunc(d.currentLine, unicode.IsSpace)
	var s []byte
	if i < 0 {
		s = d.currentLine
		d.currentLine = nil
		return s
	}
	s = d.currentLine[0:i]
	d.currentLine = d.currentLine[i+1:]
	d.skipLineWhitespace()
	return s
}
