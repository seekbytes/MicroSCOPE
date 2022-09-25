# HOW TO

## Compilare il codice

Attraverso `go build` è possibile compilare il codice e ottenere un binario statico da poter eseguire nella maggior parte delle architetture disponibili sul mercato. Per modificare l'architettura target per il binario che vorremo generare, bisogna impostare le variabili d'ambiente `GOOS` (sistema operativo target) e `GOARCH` (l'architettura di riferimento).

## Utilizzare MicroSCOPE

È possibile avviare l'analisi di un qualsiasi binario utilizzando il comando `microscope` o avviando l'eseguibile tramite `./microscope` (assumendo che il binario sia nella stessa cartella da dove si lancia il comando). Di seguito le flags:

* `-f` **OBBLIGATORIA** specifica il file per l'analisi (di default è vuoto); è possibile specificare path assoluti o relativi, purché siano validi. 
* `-t` : threshold, valore numerico specifico per il valore di threshold. Default è 100.
* `-o`: il formato file di analisi: `html` oppure `txt`
* `-d`: limite che specifica il massimo numero di byte che un binario ha e può essere analizzato da MicroSCOPE. Scarta tutti i binari maggiori del limite. Per default, questo valore è stato impostato a `2^32 - 1` (4 GByte).

Esempio (carica in microscope un binario chiamato sample-ransomware, imposta il threshold a 10 e come output HTML):
```
microscope -f sample-ransomware -t 10 -o html
```

Il risultato sarà all'interno della cartella `results` creato da MicroSCOPE nella stessa cartella da dove viene eseguito. Come nome del file del risultato verrà utilizzato il nome del file analizzato.

## Contribuire a MicroSCOPE

Ognuno può contribuire al progetto MicroSCOPE, a patto di non violare la licenza.

Parti in cui serve un aiuto o un contributo:
* testing di MicroSCOPE con ransomware recenti;
* testing di MicroSCOPE con binari malformati;
* approfondimento e dettagli delle euristiche;

Hai due principali metodi per contribuire: puoi creare un nuova segnalazione se pensi di essere incappato in un [problema](https://github.com/seekbytes/MicroSCOPE/issues), oppure aprire una nuova [Pull Request](https://github.com/seekbytes/MicroSCOPE/pulls).