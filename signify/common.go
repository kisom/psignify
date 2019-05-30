package signify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"strings"
)

const commentPrefix = "untrusted comment: "

type dataFile struct {
	comment string
	data    []byte
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
