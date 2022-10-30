package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func readResourceDirectory(virtualAddress uint32) {

	section := getSectionFromVirtualAddress(uint64(virtualAddress))

	if section == nil {
		fmt.Println("Non esiste la sezione \"Risorse\" per questo binario")
		return
	}

	offset := virtualAddress - section.VirtualAddress
	if offset < 0 {
		fmt.Println("L'offset non può essere minore di 0.")
		return
	}

	reader := bytes.NewReader(section.Raw)

	_, err := reader.Seek(int64(offset), io.SeekStart)
	if err != nil {
		fmt.Println("Impossibile ottenere il seek per l'offset")
		return
	}

	resourceDirectory := ResourceDirectory{}
	// Lettura della resourceDirectory
	err = binary.Read(reader, binary.LittleEndian, &resourceDirectory)
	if err != nil {
		fmt.Println("Impossibile leggere resourceDirectory per il seguente motivo " + err.Error())
		return
	}

	// Ricavo il numero di resource dirs
	NumberResDir := resourceDirectory.NumberOfIDEntries + resourceDirectory.NumberOfNamedEntries

	var ImgResDirEntry []*ResourceDirectoryEntry
	ImgResDirEntry = make([]*ResourceDirectoryEntry, int(NumberResDir))

	// Primo livello, identifico i vari tipi di risorse

	for i := 0; i < int(NumberResDir); i++ {
		ImgTmp := ResourceDirectoryEntry{}
		err = binary.Read(reader, binary.LittleEndian, &ImgTmp)

		if err != nil {
			fmt.Println("Errore durante la lettura dell'ImgResDirEntry " + err.Error())
			return
		}

		if ImgTmp.Name&IMAGE_RESOURCE_NAME_IS_STRING != 0 {
			// se il bit più in alto è impostato, allora i rimanenti 31 bit indicano l'offset del nome della entry
			NameOffset := ImgTmp.Name & (IMAGE_RESOURCE_NAME_IS_STRING - 1)
			seekPosition, err := reader.Seek(0, io.SeekCurrent)
			if err != nil {
				fmt.Println("Impossibile ottenere il seek corrente")
				return
			}

			_, err = reader.Seek(int64(NameOffset), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile spostare l'offset per il seguente motivo : " + err.Error())
				return
			}
			var ResourceDir ResourceDirString

			err = binary.Read(reader, binary.LittleEndian, &ResourceDir)
			if err != nil {
				fmt.Println("Impossibile leggere la struttura ResourceDirString per il seguente motivo: " + err.Error())
				return
			}
			var tmpString []byte
			tmpString = append(tmpString, ResourceDir.NameString)
			var single byte
			// Lettura della stringa
			for j := 0; j <= int(ResourceDir.Length)*2; j = j + 1 {
				// Lettura della stringa byte per byte
				err = binary.Read(reader, binary.LittleEndian, &single)
				if err != nil {
					fmt.Println("Impossibile leggere la struttura byte per il seguente motivo " + err.Error())
					return
				}
				if single != 0 {
					tmpString = append(tmpString, single)
				}
			}
			_, err = reader.Seek(seekPosition, io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile riallineare l'offset allo stato iniziale per il seguente errore " + err.Error())
				return
			}
		} else {
			// PrintResource(int(ImgTmp.Name))
		}
		ImgResDirEntrySingle := &ResourceDirectoryEntry{Name: ImgTmp.Name, OffsetToData: ImgTmp.OffsetToData}
		ImgResDirEntry[i] = ImgResDirEntrySingle
	}

	// Per ogni ImgResDirEntry, devo trovare l'entry (tabella che mi specifica tutte le risorse per quell'id) - secondo livello
	// e ovviamente le risorse - terzo livello

	for i := 0; i < int(NumberResDir); i++ {

		if ImgResDirEntry[i].OffsetToData&IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0 {
			offsetImgResEntry := ImgResDirEntry[i].OffsetToData & (IMAGE_RESOURCE_DATA_IS_DIRECTORY - 1)

			// procedo a leggere la struttura ResourceDirEntry per questa categoria
			var ResourceDirectoryTmp ResourceDirectory
			_, err = reader.Seek(int64(offsetImgResEntry), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile riallineare l'offset allo stato iniziale " + err.Error())
				return
			}
			err = binary.Read(reader, binary.LittleEndian, &ResourceDirectoryTmp)
			if err != nil {
				fmt.Println("Impossibile ottenere la struttura ResourceDirectory " + err.Error())
				return
			}
			numberOfEntries := ResourceDirectoryTmp.NumberOfIDEntries + ResourceDirectoryTmp.NumberOfNamedEntries

			for j := 0; j < int(numberOfEntries); j++ {
				// Elenco di tutte le risorse associate all'ID ImgResDirEntry

				var ImgResDirEntryTmp ResourceDirectoryEntry
				err = binary.Read(reader, binary.LittleEndian, &ImgResDirEntryTmp)
				if err != nil {
					fmt.Println("Errore nella lettura di ResourceDirectoryEntry: " + err.Error())
				}
				seekPosition, err := reader.Seek(0, io.SeekCurrent)
				if err != nil {
					fmt.Println("Impossibile ottenere l'offset corrente: " + err.Error())
					return
				}
				var tmpString []byte

				if ImgResDirEntryTmp.Name&IMAGE_RESOURCE_NAME_IS_STRING != 0 {
					NameOffset := ImgResDirEntryTmp.Name & (IMAGE_RESOURCE_NAME_IS_STRING - 1)
					seekPosition, err := reader.Seek(0, io.SeekCurrent)
					_, err = reader.Seek(int64(NameOffset), io.SeekStart)
					if err != nil {
						fmt.Println("Impossibile spostare l'offset per il seguente motivo : " + err.Error())
						return
					}
					var ResourceDir ResourceDirString
					err = binary.Read(reader, binary.LittleEndian, &ResourceDir)
					if err != nil {
						fmt.Println("Impossibile leggere la struttura ResourceDirString per il seguente motivo: " + err.Error())
						return
					}
					tmpString = append(tmpString, ResourceDir.NameString)
					var single byte
					// Lettura della stringa
					for j := 0; j <= int(ResourceDir.Length)*2; j = j + 1 {
						err = binary.Read(reader, binary.LittleEndian, &single)
						if err != nil {
							fmt.Println("Impossibile leggere la struttura byte per il seguente motivo " + err.Error())
							return
						}
						if single != 0 {
							tmpString = append(tmpString, single)
						}
					}
					_, err = reader.Seek(seekPosition, io.SeekStart)
					if err != nil {
						fmt.Println("Impossibile ripristinare l'offset " + err.Error())
						return
					}

				} else {
					// fmt.Println(ImgResDirEntryTmp.Name)
				}

				if ImgResDirEntryTmp.OffsetToData&IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0 {
					// Leggo la entry ResourceDataEntry
					OffsetToDataAligned := ImgResDirEntryTmp.OffsetToData & (IMAGE_RESOURCE_DATA_IS_DIRECTORY - 1)

					_, err = reader.Seek(int64(OffsetToDataAligned), io.SeekStart)
					if err != nil {
						fmt.Println("Impossibile eseguire il seek per il seguente motivo: " + err.Error())
						return
					}
					var resource ResourceDirectory
					err = binary.Read(reader, binary.LittleEndian, &resource)
					if err != nil {
						fmt.Println("Impossibile eseguire il read per il seguente motivo: " + err.Error())
						return
					}
					var resourceEntry ResourceDirectoryEntry
					err = binary.Read(reader, binary.LittleEndian, &resourceEntry)
					if err != nil {
						fmt.Println("Impossibile eseguire il read per il seguente motivo: " + err.Error())
						return
					}
					Offset2 := resourceEntry.OffsetToData
					_, err = reader.Seek(int64(Offset2), io.SeekStart)
					if err != nil {
						fmt.Println("Impossibile effettuare il seek per il seguente motivo: " + err.Error())
						return
					}

					var resourceTmp ResourceDataEntry
					err = binary.Read(reader, binary.LittleEndian, &resourceTmp)
					if err != nil {
						fmt.Println("Impossibile effettuare la lettura di ResourceDataEntry per il seguente motivo: " + err.Error())
						return
					}

					resourceTmpFrom := Resource{Name: string(tmpString), Type: int(ImgResDirEntry[i].Name), Offset: uint64(resourceTmp.Offset), Size: uint64(resourceTmp.Size), Content: nil, TimedateStamp: resource.TimeDateStamp}
					fileAnalyzed.Resource = append(fileAnalyzed.Resource, resourceTmpFrom)
				}
				_, err = reader.Seek(seekPosition, io.SeekStart)
				if err != nil {
					fmt.Println("Impossibile effettuare la seek per il seguente motivo. " + err.Error())
					return
				}
			}
		}
	}

}
