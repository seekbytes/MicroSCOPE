package heuristics

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"microscope/formats/pe"
	"strings"
)

type PEEntry struct {
	Name      string // Nome del programma a cui fa riferimento
	Signature []byte // N byte che compongono la signature da confrontare
	EpOnly    bool   // Entry Point, vero: la signature può essere trovata solo all'inizio, falso: può essere trovata dovunque nel programma
}

var SignaturesRead []PEEntry
var PeIDFileContent string

func ImportPEIDEntry(sections []*pe.Section) {
	// https://github.com/erocarrera/pefile/blob/master/peutils.py
	reader := strings.NewReader(PeIDFileContent)
	scanner := bufio.NewScanner(reader)
	var tmp PEEntry

	// limite: 65536 caratteri in una sola riga
	for scanner.Scan() {
		stringa := scanner.Text()
		if len(stringa) != 0 {
			if stringa[0] == '[' {
				tmp.Name = stringa[1 : len(stringa)-1]
			} else if stringa[0:9] == "signature" {
				// Leggi i byte
				tmp.Signature = readBytes(stringa)
			} else if stringa[0:7] == "ep_only" {
				// Inserimento nuova struttura
				if stringa[10] == 't' {
					tmp.EpOnly = true
				} else {
					tmp.EpOnly = false
				}

				SignaturesRead = append(SignaturesRead, tmp)

				// tmp nuovo PEEntry
				tmp = PEEntry{}
			}
		}

	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}

	Scan(sections)
}

func readBytes(stringRead string) []byte {

	byteRead := make([]byte, len(stringRead)-12)
	// I primi 12 byte non ci interessano (sono la stringa "signature = ")

	// split della stringa che contiene i caratteri esadecimali come byte
	// se la coppia che sto confrontando è uguale a ?? ==> 255 come byte
	// altrimenti decodestring
	// append di byte

	splittedString := strings.Split(stringRead[12:], " ")
	var tmpbyte byte

	for i := 0; i < len(splittedString)-1; i++ {
		if !strings.Contains(splittedString[i], ":") && !strings.Contains(splittedString[i], "V") {
			if splittedString[i][0] == '?' || splittedString[i][0] == 'J' {
				tmpbyte = 255
			} else if len(splittedString[i]) >= 1 {
				if splittedString[i][1] == '?' {
					tmpbyte = 255
				} else {
					decoded, err := hex.DecodeString(splittedString[i])
					if err != nil || len(decoded) != 1 {
						fmt.Println("Impossibile leggere l'hex per il seguente motivo " + err.Error())
					}

					tmpbyte = decoded[0]
				}
			}

			byteRead[i] = tmpbyte
		}
	}

	return byteRead
}

func Scan(sections []*pe.Section) {
	for i := 0; i < len(SignaturesRead); i++ {
		if SignaturesRead[i].EpOnly {
			// dall'entryPoint, ovvero dall'OptionalHeader.AddressOfEntryPoint

		} else {
			// prendi tutti i raw delle sezioni e confronta i byte
			for j := 0; j < len(sections); j++ {
				indexSig := compareMatch(sections[j].Raw, SignaturesRead[i].Signature)
				if indexSig != -1 {
					fmt.Println(SignaturesRead[i].Name)
				}
			}

		}

	}
}

func compareMatch(fileBuffer []byte, signatureBuffer []byte) int {
	index := -1

	if len(signatureBuffer) == 0 {
		return -1
	}

	i := 0
	k := 0

	/*
		Confronto signatureBuffer[k] con filebuffer[i]
		se sono uguali, aumento i, aumento k, ricomincio
		altrimenti aumento solo i, k ritorna a 0

		quando sono a k == len(signatureBuffer), allora ho finito, ho trovato la struttura
		se invece sono i == len(signaturebuffer) allora restituisco -1
	*/

	for {

		if signatureBuffer[k] == '?' {
			k++
			i++
		}

		if k >= len(signatureBuffer) && i <= len(fileBuffer) {
			return index
		}

		if i >= len(fileBuffer) {
			return -1
		}

		if signatureBuffer[k] == fileBuffer[i] {
			i++
			k++
			if index == -1 {
				index = i
			}
		} else {
			index = -1
			i++
			k = 0
		}
	}

}
