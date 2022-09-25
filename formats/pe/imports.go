package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"microscope/utils"
	"strings"
)

func readImports(is64bit bool, virtualAddress uint32) {

	// Ottieni la sezione che corrisponde al virtualAddress importato
	section := getSectionFromVirtualAddress(uint64(virtualAddress))

	if section == nil {
		fmt.Println("Non è stato possibile ritrovare la sezione Import")
		return
	}

	// Calcola la tableOffset
	tableOffset := virtualAddress - section.VirtualAddress

	// Crea un nuovo lettore dati
	readerSection := bytes.NewReader(section.Raw)

	if readerSection == nil {
		fmt.Println("Impossibile creare un nuovo reader per il contenuto della sezione.")
	}

	// Per ogni import DLL
	// Scorri la tableOffset nelle righe
	for i := tableOffset; ; i += uint32(binary.Size(ImportDirectory{})) {

		_, err := readerSection.Seek(int64(i), io.SeekStart)
		if err != nil {
			fmt.Println("Impossibile impostare l'offset per il seguente motivo : " + err.Error())
			return
		}

		importDirectory := ImportDirectory{}

		err = binary.Read(readerSection, binary.LittleEndian, &importDirectory)
		if err != nil {
			fmt.Println("Non è stato possibile leggere l'importDirectory per il seguente motivo " + err.Error())
			return
		}

		if importDirectory.NameRVA == 0 {
			break
		}

		requiredSection := getSectionFromVirtualAddress(uint64(importDirectory.NameRVA))

		if requiredSection == nil {
			fmt.Println("Non è stato possibile trovare la sezione dal relative address del nome della DLL. Binario malformato.")
			return
		}

		dllName := strings.ToLower(utils.ReadString(requiredSection.Raw[importDirectory.NameRVA-requiredSection.VirtualAddress:]))

		// Parsa il raw per trovare la prima stringa

		var padding int
		var bitMaskedFlag uint64

		if is64bit {
			padding = 8
			bitMaskedFlag = 0x8000000000000000
		} else {
			padding = 4
			bitMaskedFlag = 0x80000000
		}

		// prendi una sezione
		section = getSectionFromVirtualAddress(uint64(importDirectory.ImportAddressTableRVA))

		thunk2 := importDirectory.ImportAddressTableRVA
		importThunk := 0

		if importDirectory.ImportLookupTableRVA > section.VirtualAddress {
			importThunk = int(importDirectory.ImportLookupTableRVA - section.VirtualAddress)
		} else {
			importThunk = int(importDirectory.ImportAddressTableRVA - section.VirtualAddress)
		}

		for importThunk+padding < len(section.Raw) {
			// Recupera
			thunk1 := binary.LittleEndian.Uint32(section.Raw[importThunk : importThunk+padding])
			if thunk1 == 0 {
				break
			}
			var funcName string

			// flag che specifica la modalità d'import (prelevata dalla ILT) Import Lookup Table
			// doOrdinal = true: le import sono ordinate per un numero
			// doOrdinal = false: le import sono ordinate per la funcName
			doOrdinal := uint64(thunk1)&bitMaskedFlag > 0
			if doOrdinal {
				// Fai il parsing in ordine di numero
				ord := uint16(thunk1 & 0xffff)

				// Traduci il numero in una funzione con il nome
				funcName = translateOrdinal(dllName, ord)
				thunk2 += uint32(padding)
			} else {
				sectionTmp := getSectionFromVirtualAddress(uint64(thunk1) + 2)
				if sectionTmp != nil {
					v := uint32(thunk1) + 2 - sectionTmp.VirtualAddress
					funcName = utils.ReadString(sectionTmp.Raw[v:])
					thunk2 += uint32(padding)
				}

			}

			importElement := &ImportInfo{DllName: dllName, APICalled: funcName, Offset: tableOffset}

			fileAnalyzed.Imports = append(fileAnalyzed.Imports, importElement)

			// Continua il ciclo aggiungendo il padding
			importThunk += padding

		}
	}
}

func translateOrdinal(dllName string, ord uint16) string {

	switch dllName {
	case "ws2_32.dll":
		return translateOrdinalWS32(ord)
	}
	return ""
}

func translateOrdinalWS32(ord uint16) string {
	switch ord {
	case 1:
		return "imp_accept"
	case 2:
		return "imp_bind"
	case 3:
		return "imp_closesocket"
	case 4:
		return "imp_connect"
	case 5:
		return "imp_getpeername"
	case 6:
		return "imp_getsockname"
	case 7:
		return "imp_getsockopt"
	case 8:
		return "imp_htonl"
	case 9:
		return "imp_htons"
	case 10:
		return "imp_ioctlsocket"
	case 11:
		return "imp_inet_addr"
	case 12:
		return "imp_inet_ntoa"
	case 13:
		return "imp_listen"
	case 14:
		return "imp_ntohl"
	case 15:
		return "imp_ntohs"
	case 16:
		return "imp_recv"
	case 17:
		return "imp_recvfrom"
	case 18:
		return "imp_select"
	case 19:
		return "imp_send"
	case 20:
		return "imp_sendto"
	case 21:
		return "imp_setsockopt"
	case 22:
		return "imp_shutdown"
	case 23:
		return "imp_socket"
	case 24:
		return "imp_GetAddrInfoW"
	case 25:
		return "imp_GetNameInfoW"
	case 26:
		return "imp_WSApSetPostRoutine"
	case 27:
		return "imp_FreeAddrInfoW"
	case 28:
		return "imp_WPUCompleteOverlappedRequest"
	case 29:
		return "imp_WSAAccept"
	case 30:
		return "imp_WSAAddressToStringA"
	case 31:
		return "imp_WSAAddressToStringW"
	case 32:
		return "imp_WSACloseEvent"
	case 33:
		return "imp_WSAConnect"
	case 34:
		return "imp_WSACreateEvent"
	case 35:
		return "imp_WSADuplicateSocketA"
	case 36:
		return "imp_WSADuplicateSocketW"
	case 37:
		return "imp_WSAEnumNameSpaceProvidersA"
	case 38:
		return "imp_WSAEnumNameSpaceProvidersW"
	case 39:
		return "imp_WSAEnumNetworkEvents"
	case 40:
		return "imp_WSAEnumProtocolsA"
	case 41:
		return "imp_WSAEnumProtocolsW"
	case 42:
		return "imp_WSAEventSelect"
	case 43:
		return "imp_WSAGetOverlappedResult"
	case 44:
		return "imp_WSAGetQOSByName"
	case 45:
		return "imp_WSAGetServiceClassInfoA"
	case 46:
		return "imp_WSAGetServiceClassInfoW"
	case 47:
		return "imp_WSAGetServiceClassNameByClassIdA"
	case 48:
		return "imp_WSAGetServiceClassNameByClassIdW"
	case 49:
		return "imp_WSAHtonl"
	case 50:
		return "imp_WSAHtons"
	case 51:
		return "imp_gethostbyaddr"
	case 52:
		return "imp_gethostbyname"
	case 53:
		return "imp_getprotobyname"
	case 54:
		return "imp_getprotobynumber"
	case 55:
		return "imp_getservbyname"
	case 56:
		return "imp_getservbyport"
	case 57:
		return "imp_gethostname"
	case 58:
		return "imp_WSAInstallServiceClassA"
	case 59:
		return "imp_WSAInstallServiceClassW"
	case 60:
		return "imp_WSAIoctl"
	case 61:
		return "imp_WSAJoinLeaf"
	case 62:
		return "imp_WSALookupServiceBeginA"
	case 63:
		return "imp_WSALookupServiceBeginW"
	case 64:
		return "imp_WSALookupServiceEnd"
	case 65:
		return "imp_WSALookupServiceNextA"
	case 66:
		return "imp_WSALookupServiceNextW"
	case 67:
		return "imp_WSANSPIoctl"
	case 68:
		return "imp_WSANtohl"
	case 69:
		return "imp_WSANtohs"
	case 70:
		return "imp_WSAProviderConfigChange"
	case 71:
		return "imp_WSARecv"
	case 72:
		return "imp_WSARecvDisconnect"
	case 73:
		return "imp_WSARecvFrom"
	case 74:
		return "imp_WSARemoveServiceClass"
	case 75:
		return "imp_WSAResetEvent"

	case 76:
		return "imp_WSASend"
	case 77:
		return "imp_WSASendDisconnect"
	case 78:
		return "imp_WSASendTo"
	case 79:
		return "imp_WSASetEvent"
	case 80:
		return "imp_WSASetServiceA"
	case 81:
		return "imp_WSASetServiceW"
	case 82:
		return "imp_WSASocketA"
	case 83:
		return "imp_WSASocketW"
	case 84:
		return "imp_WSAStringToAddressA"
	case 85:
		return "imp_WSAStringToAddressW"
	case 86:
		return "imp_WSAWaitForMultipleEvents"
	case 87:
		return "imp_WSCDeinstallProvider"
	case 88:
		return "imp_WSCEnableNSProvider"
	case 89:
		return "imp_WSCEnumProtocols"
	case 90:
		return "imp_WSCGetProviderPath"
	case 91:
		return "imp_WSCInstallNameSpace"
	case 92:
		return "imp_WSCInstallProvider"
	case 93:
		return "imp_WSCUnInstallNameSpace"
	case 94:
		return "imp_WSCUpdateProvider"
	case 95:
		return "imp_WSCWriteNameSpaceOrder"
	case 96:
		return "imp_WSCWriteProviderOrder"
	case 97:
		return "imp_freeaddrinfo"
	case 98:
		return "imp_getaddrinfo"
	case 99:
		return "imp_getnameinfo"

	case 101:
		return "imp_WSAAsyncSelect"
	case 102:
		return "imp_WSAAsyncGetHostByAddr"
	case 103:
		return "imp_WSAAsyncGetHostByName"
	case 104:
		return "imp_WSAAsyncGetProtoByNumber"
	case 105:
		return "imp_WSAAsyncGetProtoByName"
	case 106:
		return "imp_WSAAsyncGetServByPort"
	case 107:
		return "imp_WSAAsyncGetServByName"
	case 108:
		return "imp_WSACancelAsyncRequest"
	case 109:
		return "imp_WSASetBlockingHook"
	case 110:
		return "imp_WSAUnhookBlockingHook"
	case 111:
		return "imp_WSAGetLastError"
	case 112:
		return "imp_WSASetLastError"
	case 113:
		return "imp_WSACancelBlockingCall"
	case 114:
		return "imp_WSAIsBlocking"
	case 115:
		return "imp_WSAStartup"
	case 116:
		return "imp_WSACleanup"
	case 151:
		return "imp___WSAFDIsSet"
	case 500:
		return "imp_WEP"
	}

	return ""
}
