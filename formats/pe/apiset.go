package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"microscope/utils"
)

// La sezione APISet è una particolare sezione di un file binario che a partire da Windows 7 viene utilizzata per
// importare una serie di funzionalità all'interno del binario utilizzando delle API "globali" fornite da Windows.
// Dal momento che le Win32 API variano in base alla versione di Windows e l'architettura, Microsoft ha ideato un'astrazione
// più estesa delle API del sistema operativo. Questa sezione fa un uso esteso delle tabelle hash per associare il nome dell'API (apiset)
// a tutte gli import originali di Win32.

func readApiSet() {
	// https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html
	var sectionApiSet *Section

	for i := 0; i < int(fileAnalyzed.COFFHeader.NumberOfSections); i++ {
		if fileAnalyzed.Sections[i].Name == ".apiset\u0000" {
			sectionApiSet = fileAnalyzed.Sections[i]
			break
		}
	}

	if sectionApiSet == nil {
		fmt.Println("Non esiste la sezione apiset.")
		return
	}

	readerApiSet := bytes.NewReader(sectionApiSet.Raw)
	// Controlla versione dell'api set
	var version uint32

	err := binary.Read(readerApiSet, binary.LittleEndian, &version)
	if err != nil {
		fmt.Println("Impossibile leggere la versione dell'ApiSet")
		return
	}

	if version >= 3 {
		var header ApiSetHeader3
		err := binary.Read(readerApiSet, binary.LittleEndian, &header)
		if err != nil {
			fmt.Println("Impossibile leggere l'ApiSetHeader")
			return
		}

		for i := 0; i < int(header.NumberOfApiSets); i++ {

			// Sposta l'offset
			_, err = readerApiSet.Seek(int64(int(header.NamesOffset)+binary.Size(ApiSetNameEntry{})*i), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile spostare il seek " + err.Error())
				return
			}

			var tmp ApiSetNameEntry
			err = binary.Read(readerApiSet, binary.LittleEndian, &tmp)
			if err != nil {
				fmt.Println("Impossibile leggere ApiSetNameEntry")
				return
			}

			name := utils.ReadStringUTF16(sectionApiSet.Raw[tmp.Offset : tmp.Offset+tmp.Size])
			fmt.Println(name)

			for i := 0; i < int(tmp.NumberOfHosts); i++ {
				_, err = readerApiSet.Seek(int64(tmp.HostOffset)+int64(i*(binary.Size(ApiSetValueEntry{}))), io.SeekStart)
				if err != nil {
					fmt.Println("Impossibile effettuare il seek" + err.Error())
					return
				}
				var tmpEntry ApiSetValueEntry
				err = binary.Read(readerApiSet, binary.LittleEndian, &tmpEntry)
				if err != nil {
					fmt.Println("Impossibile leggere la struttura ApiSetValueEntry")
					return
				}

				stringName := utils.ReadStringUTF16(sectionApiSet.Raw[tmpEntry.ValueOffset : tmpEntry.ValueOffset+tmpEntry.ValueLength])
				fmt.Println(stringName)
			}

		}

	}

}
