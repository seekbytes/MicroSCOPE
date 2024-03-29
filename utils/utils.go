package utils

import (
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
)

func ReadString(b []byte) string {
	return ReadStringFrom(b, 0)
}

func ReadStringFrom(b []byte, start int) string {
	for i := start; i < len(b); i++ {
		if b[i] == 0x0 {
			return string(b[start:i])
		}
	}
	return string(b)
}

func ReadStringUTF16(b []byte) string {
	stringUTF := make([]uint16, (len(b)+1)/2)
	for i := 0; i+1 < len(b); i += 2 {
		stringUTF[i/2] = binary.LittleEndian.Uint16(b[i:])
	}
	return string(utf16.Decode(stringUTF))
}

var magicTable = map[string]string{
	"\xd0\xcf\x11":                        "doc/office",
	"BM":                                  "image/bmp",
	"\xff\xd8\xff":                        "image/jpeg",
	"\x00\x00\x00\x0c":                    "image/jpeg2000",
	"\xff\xf4\xff\x51":                    "image/jpeg2000",
	"\x89PNG\r\n\x1a\n":                   "image/png",
	"GIF87a":                              "image/gif",
	"GIF89a":                              "image/gif",
	"\x00\x00\x01\x00":                    "image/ico",
	"\x4d\x4d\x00\x21":                    "image/tiff",
	"MThd":                                "sound/midi",
	"FORM":                                "sound/AIFF",
	"RIFF":                                "sound/wav",
	"<?xml":                               "text/xml",
	"<html>":                              "text/html",
	"\x25\x50\x44\x46":                    "doc/pdf",
	"-----BEGIN CERTIFICATE-----":         "misc/crt",
	"-----BEGIN CERTIFICATE REQUEST-----": "misc/csrt",
	"-----BEGIN PRIVATE KEY-----":         "misc/key",
	"MZ":                                  "binary/pe",
	"ZM":                                  "binary/pe",
	"ELF":                                 "binary/elf",
	"\x42\x5a":                            "file/bzip",
	"\x1f\x8b":                            "file/gzip",
	"\x75\x73\x74\x61\x62":                "file/tar",
	"OTTO":                                "font/openttype",
	"\x50\x4b\x03\x04":                    "file/zip",
	"KWAJ":                                "file/compressedWin3",
	"SZDD":                                "file/compressedWin9x",
	"PMOCCMOC":                            "win/settings",
	"\x53\x51\x4c\x69":                    "db/sqlite",
	"\x69\x63\x6e\x73":                    "image/icns",
	"\x50\x33\x0a":                        "image/ppa", // portable pixmap ascii
	"\x50\x35\x0a":                        "image/ppa", // portable graymap ascii

}

func IdentifyFile(b []byte) string {
	s := string(b)
	for key, val := range magicTable {
		if strings.HasPrefix(s, key) {
			return val
		}
	}
	return ""
}

func IsASCIIPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
