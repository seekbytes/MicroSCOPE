package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func ProdIDtoVSVersion(prodID uint16) string {
	if prodID > 0x010e {
		return ""
	} else if prodID >= 0x00fd && prodID < 0x010e+1 {
		return "Visual Studio 2015 14.00"
	} else if prodID >= 0x00eb && prodID < 0x00fd {
		return "Visual Studio 2013 12.10"
	} else if prodID >= 0x00d9 && prodID < 0x00eb {
		return "Visual Studio 2013 12.00"
	} else if prodID >= 0x00c7 && prodID < 0x00d9 {
		return "Visual Studio 2012 11.00"
	} else if prodID >= 0x00b5 && prodID < 0x00c7 {
		return "Visual Studio 2010 10.10"
	} else if prodID >= 0x0098 && prodID < 0x00b5 {
		return "Visual Studio 2010 10.00"
	} else if prodID >= 0x0083 && prodID < 0x0098 {
		return "Visual Studio 2008 09.00"
	} else if prodID >= 0x006d && prodID < 0x0083 {
		return "Visual Studio 2005 08.00"
	} else if prodID >= 0x005a && prodID < 0x006d {
		return "Visual Studio 2003 07.10"
	} else if prodID == 1 {
		return "Visual Studio"
	} else {
		return "unknown"
	}
}

func readRichHeader() {

	offset := fileAnalyzed.DosHeader.AddressExeOffset
	// Siamo sicuri che i primi N byte di DosHeader non costituiscono il rich header
	_, err := reader.Seek(int64(binary.Size(DosHeaderT{})), io.SeekStart)
	if err != nil {
		fmt.Println("Impossibile spostare il seek per il seguente motivo: " + err.Error())
	}

	// prendiamo i primi m bytes (dove m = offset - dimensione della struttura)
	bufferTmp := make([]byte, int(offset)-binary.Size(DosHeaderT{}))
	err = binary.Read(reader, binary.LittleEndian, &bufferTmp)
	if err != nil {
		fmt.Println("Impossibile effettuare la lettura della struttura buffer per il seguente motivo: " + err.Error())
		return
	}
	position := bytes.Index(bufferTmp, []byte("Rich"))
	if position < 0 {
		fmt.Println("Rich header non trovato")
		return
	}

	var richHeader RichHeader
	richHeader.XORKey = binary.LittleEndian.Uint32(bufferTmp[position+4:])

	CheckXORKey(richHeader.XORKey)

	// Decifriamo 4 byte alla volta
	var decipheredRichHeader []uint32
	estimated := position - 4
	for i := 0; i < estimated; i += 4 {
		tmpBuff := binary.LittleEndian.Uint32(bufferTmp[position-4-i:])
		res := tmpBuff ^ richHeader.XORKey

		if res == 0x536E6144 {
			// Il richHeader è stato decifrato :)
			break
		}

		decipheredRichHeader = append(decipheredRichHeader, res)
	}

	for i, j := 0, len(decipheredRichHeader)-1; i < j; i, j = i+1, j-1 {
		decipheredRichHeader[i], decipheredRichHeader[j] = decipheredRichHeader[j], decipheredRichHeader[i]
	}

	var lenCompIDs int
	if (len(decipheredRichHeader)-3)%2 != 0 {
		lenCompIDs = len(decipheredRichHeader) - 1
	} else {
		lenCompIDs = len(decipheredRichHeader)
	}

	var CompIDs []CompID

	for i := 3; i < lenCompIDs; i += 2 {
		cidTmp := CompID{}
		compid := make([]byte, binary.Size(cidTmp))
		binary.LittleEndian.PutUint32(compid, decipheredRichHeader[i])
		binary.LittleEndian.PutUint32(compid[4:], decipheredRichHeader[i+1])
		buf := bytes.NewReader(compid)
		err := binary.Read(buf, binary.LittleEndian, &cidTmp)
		if err != nil {
			fmt.Println("Errore durante la lettura " + err.Error())
		}
		cidTmp.Raw = binary.LittleEndian.Uint32(compid)
		// fmt.Println(ProdIDtoVSVersion(cidTmp.ProdID))
		CompIDs = append(CompIDs, cidTmp)
	}

	fileAnalyzed.RichHeader = richHeader
}

func CheckXORKey(XORKey uint32) {
	// Presi da https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/
	switch XORKey {
	case 0x886973F3, 0x8869808D, 0x88AA42CF, 0x88AA2A9D, 0x89A99A19, 0x88CECC0B, 0x8897EBCB, 0xAC72CCFA, 0x1AAAA993, 0xD05FECFB, 0x183A2CFD, 0xACCF9994, 0xC757AD0B, 0xA7EEAD02, 0xD1197995, 0x83CDAD4, 0x8917A389, 0x88CEA841, 0x8917DE83, 0x89AA0373, 0x8ACD8739, 0x8D156179, 0x8ACE4D53, 0x8897FE31, 0x91A515F9, 0xD1983193, 0x8D16E113, 0x9AC47EF9, 0x91A80893, 0xAD0350F9, 0xD180F4F9, 0xAD0EF593, 0x9ACA5793:
		fmt.Println("Visual Basic 6.0")
	case 0xD28650E9, 0x38BF1A05, 0x6A2AD175, 0xD246D0E9, 0x371742A2, 0xAB930178, 0x69EAD975, 0x69EB1175, 0xFB2414A1, 0xFB240DA1:
		fmt.Println("NSIS")
	case 0x88737619, 0x89A56EF9:
		fmt.Println("MASM 6.14 build 8444")
	case 0xC47CACAA, 0xFDAFBB1F, 0xD3254748, 0x557B8C97, 0x8DEFA739, 0x723F06DE, 0x16614BC7:
		fmt.Println("WinRar SFX")
	case 0xBEAFE369, 0xC1FC1252, 0xCDA605B9, 0xA9CBC717, 0x8FEDAD28, 0x273B0B7D, 0xECFA7F86:
		fmt.Println("Autoit")
	case 0x43FACBB6:
		fmt.Println("Microsoft Cabinet File")
	case 0x377824C3:
		fmt.Println("NTkernelPacker")
	case 0x8B6DF331:
		fmt.Println("Thinstall")
	case 0x8CABE24D:
		fmt.Println("MoleBox Ultra v4")
	}
}
