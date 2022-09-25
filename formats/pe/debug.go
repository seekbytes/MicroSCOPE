package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func readDebugSection(virtualAddress uint32) {
	var debugInfo DebugDirectory
	section := getSectionFromVirtualAddress(uint64(virtualAddress))
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
	err = binary.Read(reader, binary.LittleEndian, &debugInfo)
	if err != nil {
		fmt.Println("Errore!")
		return
	}

	debugDirCount := int(debugInfo.SizeOfData) / (binary.Size(DebugDirectory{}))
	offsetNew := offset
	for i := 0; i < debugDirCount; i++ {

		offsetNew = uint32(int(offsetNew) + (binary.Size(DebugDirectory{}))*i)
		var tmpDebugDirectory DebugDirectory
		_, err := reader.Seek(int64(offset), io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile ottenere il seek per l'offset")
			return
		}

		err = binary.Read(reader, binary.LittleEndian, &tmpDebugDirectory)
		if err != nil {
			fmt.Println("Errore durante la lettura di DebugDirectory per la seguente ragione : " + err.Error())
			return
		}

		fileAnalyzed.DebugSections = append(fileAnalyzed.DebugSections, tmpDebugDirectory)
	}

}

func readDebugInformations() {
	for i := 0; i < len(fileAnalyzed.DebugSections); i++ {
		switch fileAnalyzed.DebugSections[i].Type {
		case IMAGE_DEBUG_TYPE_CODEVIEW:
			var debugSignature uint32
			_, err := reader.Seek(int64(fileAnalyzed.DebugSections[i].PointerToRawData), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile fare il seek per il seguente motivo: " + err.Error())
			}

			err = binary.Read(reader, binary.LittleEndian, &debugSignature)
			if err != nil {
				fmt.Println("Impossibile leggere la signature del DEBUG " + err.Error())
			}
			if debugSignature == DEBUG_CV_SIGNATURE_RSDS {
				// Formato file PDB7
				pdb := DebugCodeViewPDB7{CodeViewSignature: DEBUG_CV_SIGNATURE_RSDS}

				// Get the signature (GUID), salto la signature
				_, err := reader.Seek(int64(fileAnalyzed.DebugSections[i].PointerToRawData+4), io.SeekStart)
				if err != nil {
					fmt.Println("Impossibile eseguire il seek per il seguente motivo: " + err.Error())
					return
				}

				err = binary.Read(reader, binary.LittleEndian, &pdb.GUIDSignature)
				if err != nil {
					continue
				}

				err = binary.Read(reader, binary.LittleEndian, &pdb.Age)
				if err != nil {
					continue
				}

				pdbFileNameSize := fileAnalyzed.DebugSections[i].SizeOfData - 24 - 1
				fileName := make([]byte, pdbFileNameSize)
				err = binary.Read(reader, binary.LittleEndian, &fileName)

				pdb.PDBFileName = string(fileName)
			} else if debugSignature == DEBUG_CV_SIGNATURE_NB10 {
				// Formato file PDB 2
				_, err := reader.Seek(int64(fileAnalyzed.DebugSections[i].PointerToRawData+8), io.SeekStart)
				if err != nil {
					fmt.Println("Impossibile spostarsi all'indice per il seguente errore " + err.Error())
				}

				var pdb DebugCodeViewPDB2
				err = binary.Read(reader, binary.LittleEndian, &pdb.CodeViewSignature)
				if err != nil {
					fmt.Println("Impossibile leggere il campo CodeViewSignature per il seguente motivo: " + err.Error())
					return
				}
				err = binary.Read(reader, binary.LittleEndian, &pdb.Age)
				if err != nil {
					fmt.Println("Impossibile leggere il campo Age per il seguente motivo: " + err.Error())
					return
				}
				pdbFileNameSize := fileAnalyzed.DebugSections[i].SizeOfData - 16 - 1
				fileName := make([]byte, pdbFileNameSize)
				err = binary.Read(reader, binary.LittleEndian, &fileName)
				pdb.PDBFileName = string(fileName)
			} else {
				fmt.Println("Impossibile effettuare il parsing della sezione di debug")
			}
		case IMAGE_DEBUG_TYPE_PGO:
			var pgoSignature uint32
			_, err := reader.Seek(int64(fileAnalyzed.DebugSections[i].PointerToRawData), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile spostare il seek del file per il seguente motivo: " + err.Error())
				return
			}
			err = binary.Read(reader, binary.LittleEndian, &pgoSignature)
			if err != nil {
				fmt.Println("Impossibile leggere la struttura pgoSignature")
				return
			}
			pogo := PGO{}
			pogo.Signature = pgoSignature
			k := 0
			for k < int(fileAnalyzed.DebugSections[i].SizeOfData-4) {
				pgoentry := PGOItem{}
				err = binary.Read(reader, binary.LittleEndian, &pgoentry.Rva)
				if err != nil {
					fmt.Println("Impossibile leggere la struttura pgoEntry")
					break
				}
				err = binary.Read(reader, binary.LittleEndian, &pgoentry.Size)
				if err != nil {
					fmt.Println("Impossibile leggere la struttura pgoEntry")
					break
				}
				pgoFileName := make([]byte, 4)
				err = binary.Read(reader, binary.LittleEndian, &pgoFileName)
				if err != nil {
					fmt.Println("Impossibile leggere la struttura pgoEntry")
					break
				}
				pgoentry.Name = string(pgoFileName)
				pogo.Entries = append(pogo.Entries, pgoentry)
				k += 8 + (len(pgoFileName)) + 4
			}

		case IMAGE_DEBUG_TYPE_VC_FEATURE:
			var vcf VCFeature
			_, err := reader.Seek(int64(fileAnalyzed.DebugSections[i].PointerToRawData), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile fare il seek per il seguente motivo: " + err.Error())
				return
			}

			err = binary.Read(reader, binary.LittleEndian, &vcf)
			if err != nil {
				fmt.Println("Impossibile leggere la struttura VCFeature per il seguente motivo: " + err.Error())
				return
			}
		case IMAGE_DEBUG_TYPE_REPRO:
			repro := REPRO{}
			_, err := reader.Seek(int64(fileAnalyzed.DebugSections[i].PointerToRawData), io.SeekStart)
			if err != nil {
				fmt.Println("Impossibile fare il seek per il seguente motivo: " + err.Error())
				return
			}

			err = binary.Read(reader, binary.LittleEndian, &repro.Size)
			if err != nil {
				fmt.Println("Impossibile leggere la size per il seguente motivo: " + err.Error())
				return
			}
			repro.Hash = make([]byte, repro.Size)
			err = binary.Read(reader, binary.LittleEndian, &repro.Hash)
			if err != nil {
				fmt.Println("Impossibile leggere l'hash per il seguente motivo: " + err.Error())
				return
			}

		case IMAGE_DEBUG_TYPE_FPO:
		}

	}
}
