package stl

import "io"

func getRandBytes(reader io.Reader, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(reader, b); err != nil {
		panic(err)
	}
	return b
}
