# Formato PE

Il formato file PE (_Portable Executable_) è un formato file creato per rappresentare i file di tipo binari per piattaforme Windows. È stato scritto inizialmente per la versione 1.0 di MSDOS e non ha subito alcun cambiamento radicale in 30 anni.

Questo documento vuole essere un riassunto riguardo la descrizione del formato file binario PE.

Si compone di diverse parti, tra cui:

* Header DOS: struttura che assume significato solo nel caso in cui l'applicazione venga eseguita tramite MS-DOS. È posizionata per prima. Negli eseguibili moderni, il linker mette uno stub "This program cannot be run in DOS mode" che viene stampata a schermo quando viene eseguito in MS-DOS. All'offset 0x3c, lo stub ha l'offset della signature PE.
* Signature PE: 4 byte signature ("PE\0\0")
* Header COFF: intestazione che indica il tipo di macchina di destinazione, il numero di sezioni, la data e l'ora (quando è stato creato il file), la dimensione del file. (quando il file è stato creato), dimensioni dell'OptionalHeader, caratteristiche del file.
* OptionalHeader: intestazione "opzionale" (anche se è obbligatoria!) che specifica le dimensione delle varie sezioni, l'entry point del binario, la dimensione dell'intestazione, la dimensione del file in memoria virtuale, alignment del file e delle sezioni.
* Sezioni: ottenute dalle Data Directory, una serie di parti indipendenti l'una dalle altre adibite ad uno scopo ben preciso.

## Concetti e tipi di dato

Di seguito si possono trovare una serie di definizioni che introducono l'utente alle strutture del file PE.

### Relative Virtual Address

Il formato PE utilizza in modo pesante alcuni tipi di dato chiamati RVA. Una RVA (Relative Virtual Address) è utilizzato per riferirsi/descrivere una parte di memoria di cui ancora non si conosce l'indirizzo base. In altri termini, è il valore che devi aggiungere all'indirizzo base per avere l'indirizzo di memoria assoluto.

Esempio: supponi di avere un eseguibile mappato da una zona di memoria 0x300 e l'esecuzione parte da RVA 0x20, l'indirizzo assoluto sarà 0x320. Se lo stesso eseguibile fosse stato mappato nella zona di memoria 0x1000, allora l'indirizzo assoluto sarebbe stato 0x1020.

### Tipi di dato

Nome del tipo di dato | Dimensione | numero in bit
-- | -- | --
Word | due byte | 16
DoubleWord | quattro byte | 32
Bytes | un byte | 8

## Sezioni

Le sezioni sono individuate tramite la Data Directory corrispondente che indica l'offset (tramite VirtualAddress) e la dimensione della sezione. Ad ogni sezione è attribuito un significato particolare che può variare in base alla versione del sistema operativo (se Windows 8 oppure Windows 2003) e in base al programma stesso. 

Esistono però delle sezioni che sono universali nel loro formato e contengono preziose informazioni per lo studio comportamentale del binario. Tra queste troviamo:

* Sezione Import: una serie di entry descrivono che funzioni il programma andrà a utilizzare quando viene avviato. Molto importante per prevedere il comportamento del binario. Ad ogni funzione importata è associato un nome (o alternativamente un ordinal) e il nome della libreria da importare. Iterando sulle librerie, il sistema operativo sa quale funzione deve importare.
* Sezione export: una serie di entry descrivono che funzioni il programma o una libreria può mettere a disposizione per il sistema operativo o altri programmi. Possono contenere alcune informazioni, ma non necessarie per MicroSCOPE. Le funzioni esportate sono anche chiamate _symbols_ e possono essere individuate tramite un nome (stringa di caratteri ASCII) oppure un numero (chiamato _ordinal_).
* Resource: questa sezione contiene una vasta gamma di informazioni su eventuali risorse (testo, icone, informazioni di copyright, di versione) che un programma può utilizzare. La sezione è costruita ad albero che può avere fino a 2^31 livelli (anche se Windows preferisce utilizzarne al massimo TRE).

Altre strutture che al momento MicroSCOPE comprende sono:
* APISET: (solo versione 3+) sezione aggiuntiva disponibile da Windows 7 che consente al sistema operativo di astrarre dalle Win32 API un'interfaccia comune e più ampia. I programmi che utilizzano questa sezione non hanno problemi di compatibilità tra architetture diverse e versioni di Win32.
* Security: header che consente di verificare se un binario è firmato oppure no. MicroSCOPE legge eventuali informazioni sulla firma e sul tipo di certificato utilizzato, verificandone la validità. Normalmente i binari sono firmati con dei certificati che rispettano una _trust chain_ (catena di "affidabilità"). 
* Debug: questa sezione contiene una serie di informazioni di debug. Talvolta sono molto importanti perché inglobano informazioni extra sull'attaccante e su come il programma opera.
* Rich Header: questa sezione non è documentata all'interno della specifica ufficiale del formato PE. La sezione contiene alcune informazioni utili riguardo l'ambiente di costruzione (identificatore del prodotto, numero di build, numero di volte in cui è stato utilizzato durante la compilazione). 

## Grafici

* [PE Format graphically visualized](http://www.openrce.org/reference_library/files/reference/PE%20Format.pdf)

### Risorse utilizzate

* http://www.pelib.com/resources/luevel.txt
* Microsoft PE Specification Revision 8.3 (ultimo aggiornamento: 07 Novembre 2018)
* [..TODO..]