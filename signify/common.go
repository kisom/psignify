package signify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"strings"
)

const commentPrefix = "untrusted comment: "

type dataFile struct {
	comment string
	data    []byte
}

func (dataFile *dataFile) Encode() []byte {
	buf := bytes.NewBufferString(dataFile.comment)
	buf.WriteByte('\n')
	buf.Write(dataFile.data)
	buf.WriteByte('\n')
	return buf.Bytes()
}

func readDataFileBytes(data []byte) (*dataFile, error) {
	var line string

	dat := &dataFile{}
	buf := bytes.NewBuffer(data)
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line = scanner.Text()
		// TODO: strip prefix
		if strings.HasPrefix(line, commentPrefix) {
			dat.comment += strings.TrimPrefix(line, commentPrefix)
			continue
		}
		break
	}

	var err error
	dat.data, err = base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, err
	}

	return dat, nil
}

func writeDataFile(path, comment string, data []byte) error {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	dataFile := &dataFile{
		comment: comment,
		data:    encoded,
	}

	return ioutil.WriteFile(path, dataFile.Encode(), 0644)
}
