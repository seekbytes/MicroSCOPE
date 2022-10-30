package pe

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"go.mozilla.org/pkcs7"
	"io"
)

// La sezione "security" contiene una firma chiamata authenticode che è un formato di firma
// utilizzato per verificare l'integrità e l'origine del software.
func readSecuritySection(virtualAddress uint32) {
	section := getSectionFromVirtualAddress(uint64(virtualAddress))

	if section == nil {
		fmt.Println("Non esiste la sezione \"Security\" per questo binario")
		return
	}

	//offset := virtualAddress - section.VirtualAddress
	offset := virtualAddress
	if offset < 0 {
		fmt.Println("L'offset non può essere minore di 0.")
		return
	}

	for {
		_, err := reader.Seek(int64(offset), io.SeekStart)
		var reasonString string
		if err != nil {
			fmt.Println("Impossibile effettuare il seek per il seguente motivo: " + err.Error())
			return
		}

		// Parsa ogni certificato
		var Certificate WinCertificate

		err = binary.Read(reader, binary.LittleEndian, &Certificate)
		if err != nil {
			fmt.Println("Impossibile leggere la struttura WinCertificate per il seguente motivo: " + err.Error())
			return
		}

		if Certificate.Length == 0 {
			fmt.Println("Errore: certificato invalido")
			return
		}

		fmt.Printf("%+v\n", Certificate)

		certificateContent := make([]byte, Certificate.Length-uint32(binary.Size(WinCertificate{})))
		err = binary.Read(reader, binary.LittleEndian, certificateContent)
		if err != nil {
			fmt.Println("Impossibile leggere il contenuto del certificato " + err.Error())
			return
		}

		pkcs, err := pkcs7.Parse(certificateContent)
		if err != nil {
			reasonString = err.Error()
			fmt.Println("Errore: il certificato non è valido: " + reasonString)
			fileAnalyzed.SecuritySection = append(fileAnalyzed.SecuritySection, SecurityHeader{Header: Certificate, Content: pkcs, IsSigned: false, ReasonFail: reasonString})
			return
		}

		for _, cert := range pkcs.Certificates {
			fmt.Printf("%+v\n", cert)
		}

		// Verifica la signature
		certPool, err := x509.SystemCertPool()
		isValid := true
		err = pkcs.VerifyWithChain(certPool)
		if err != nil {
			reasonString = err.Error()
			fmt.Println("Il certificato non è valido: " + err.Error())
			isValid = false
		}

		offset = Certificate.Length + offset
		offset = offset + 8 - 1
		fileAnalyzed.SecuritySection = append(fileAnalyzed.SecuritySection, SecurityHeader{Header: Certificate, Content: pkcs, IsSigned: isValid, ReasonFail: reasonString})
	}

}
