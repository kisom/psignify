// Package base64 implements base64 encoding with line breaks.
package base64

import (
	"encoding/base64"
	"io"
)

const (
	decodedSize = 54
	encodedSize = 72
)

// Encoder is a base64 encoder that introduces newlines at 72
// characters.
type Encoder struct {
	line  int
	w     io.Writer
	buf   []byte
	index int
}

func NewEncoder(w io.Writer) io.WriteCloser {
	return &Encoder{
		w:   w,
		buf: make([]byte, 3),
	}
}

func (w *Encoder) Close() error {
	if w.index > 0 {
		out := make([]byte, base64.StdEncoding.EncodedLen(w.index))
		base64.StdEncoding.Encode(out, w.buf[:w.index])
		_, err := w.w.Write(out)
		if err != nil {
			return err
		}

		w.index = 0
		w.line = 0
	}
	_, err := w.w.Write([]byte("\n"))
	return err
}

func (w *Encoder) Write(p []byte) (int, error) {
	out := make([]byte, 4)
	written := 0

	for i := range p {
		w.buf[w.index] = p[i]
		w.index++
		if w.index == 3 {
			w.index = 0
			base64.StdEncoding.Encode(out, w.buf)
			_, err := w.w.Write(out)
			if err != nil {
				return written, err
			}
			w.line += 3
			w.buf[0] = 0
			w.buf[1] = 0
			w.buf[2] = 0

			if w.line == decodedSize {
				_, err = w.w.Write([]byte("\n"))
				if err != nil {
					return written, err
				}
				w.line = 0
			}
			written += 3
		}
	}

	return written, nil
}

// Decoder is a base64 decoder that handles sources with newlines.
type Decoder struct {
	r io.Reader
}

// NewDecoder returns a new Decoder over a Reader.
func NewDecoder(r io.Reader) io.ReadCloser {
	return &Decoder{
		r: r,
	}
}

func (r *Decoder) Close() error {
	return nil
}

func (r *Decoder) Read(p []byte) (int, error) {
	enclen := base64.StdEncoding.EncodedLen(len(p))
	buf := make([]byte, 0, enclen)
	c := make([]byte, 1)
	n := 0

	for {
		if n == enclen {
			break
		}

		_, err := r.r.Read(c)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}

		if c[0] == 0xa {
			continue
		}

		buf = append(buf, c[0])
		n++
	}

	return base64.StdEncoding.Decode(p, buf)
}
