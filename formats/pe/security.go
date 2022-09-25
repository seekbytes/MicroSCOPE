package pe

import (
	"bytes"
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

	offset := virtualAddress - section.VirtualAddress
	if offset < 0 {
		fmt.Println("L'offset non può essere minore di 0.")
		return
	}

	readerRaw := bytes.NewReader(section.Raw)

	for {
		_, err := readerRaw.Seek(int64(offset), io.SeekStart)

		if err != nil {
			fmt.Println("Impossibile effettuare il seek per il seguente motivo: " + err.Error())
			return
		}

		// Parsa ogni certificato
		var Certificate WinCertificate

		err = binary.Read(readerRaw, binary.LittleEndian, &Certificate)
		if err != nil {
			fmt.Println("Impossibile leggere la struttura WinCertificate")
			return
		}

		if Certificate.Length == 0 {
			fmt.Println("Errore: certificato invalido")
			return
		}

		certificateContent := make([]byte, Certificate.Length)
		err = binary.Read(readerRaw, binary.LittleEndian, certificateContent)
		if err != nil {
			fmt.Println("Impossibile leggere il contenuto del certificato " + err.Error())
			return
		}

		pkcs, err := pkcs7.Parse(certificateContent)
		if err != nil {
			fmt.Println("Errore: il certificato non è valido")
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
			fmt.Println("Il certificato non è valido")
			isValid = false
		}

		offset = Certificate.Length + offset
		offset = offset + 8 - 1
		fileAnalyzed.SecuritySection = append(fileAnalyzed.SecuritySection, SecurityHeader{Header: Certificate, Content: pkcs, IsSigned: isValid})
	}

}
