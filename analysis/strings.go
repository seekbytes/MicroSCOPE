package analysis

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
)

func ExtractStrings(file *os.File, min, max int, ascii bool) []string {
	// Optimize the function
	_, err := file.Seek(1000, io.SeekStart)
	if err != nil {
		fmt.Println("Impossibile fare il seek per il seguente motivo: " + err.Error())
	}
	content, _ := io.ReadAll(file)
	in := bytes.NewReader(content)

	str := make([]rune, 0, max)
	var res []string
	next := func() {
		if len(str) >= min {
			res = append(res, string(str))
		}
		str = str[0:0]
	}

	// One string per loop.
	for {
		ch, _, err := in.ReadRune()
		if err != nil {
			if err != io.EOF {
				fmt.Println(err.Error())
			}
			return res
		}
		if !strconv.IsPrint(ch) || ascii && ch >= 0xFF {
			next()
			continue
		}
		// It's printable. Keep it.
		if len(str) >= max {
			next()
		}
		str = append(str, ch)
	}
}

func ExtractHTTPAddress() {

}
