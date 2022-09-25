![MicroSCOPE logo](https://github.com/seekbytes/MicroSCOPE/blob/main/utils/MicroSCOPE.jpg?raw=true)

## Scopo del progetto

MicroSCOPE è un software sviluppato tramite il linguaggio di programmazione [Go](https://go.dev) che permette di inidividuare una precisa categoria di software dannoso. Il programma è stato studiato specificamente per una classe di programmi dannosi chiamata _ransomware_ il cui funzionamento consiste nella crittazione dei dati e richiesta di riscatto per poter riaccedere al contenuto.

In particolare, MicroSCOPE è stato sviluppato per poter supportare due tra i formati principalmente utilizzati: il formato PE (_Portable Executable_) per piattaforme Windows ed ELF (_Executable and Linking Format_) per piattaforme Unix-based. Tramite l'applicazione di alcune euristiche, MicroSCOPE è in grado di attribuire un punteggio che corrisponde al livello di pericolosità del file che si vuole analizzare. Tanto più alto è il punteggio, tanto più il software presenterà caratteristiche simili a ransomware già studiati. Le euristiche sono state estrapolate da numerosi casi di studio e verranno migliorate nel corso del tempo.

## Struttura del progetto

* `analysis`: cartella relativa all'analisi statica dei binari (incluso le varie fasi di MicroSCOPE)
* `docs`: cartella contenente la documentazione del progetto MicroSCOPE
* `formats`: cartella relativa ai formati file binari (ELF e PE) incluse costanti, controlli e parsing del binario;
* `heuristics`: le euristiche vere e proprie
* `utils`: utilità generali

## Come funziona

L'analisi effettuata da MicroSCOPE ha tre fasi principali:
* **data mining**: analisi approfondita del file binario in base al tipo di estensione (ad esempio: se file PE o ELF), estrapolando stringhe, funzioni che utilizza e qualsiasi altra informazione potenzialmente utile per prevedere l'esecuzione del programma;
* **applicazione delle euristiche**: in base alle informazioni estrapolate dalla prima fase, si applicano le euristiche che consentono di capire che comportamento avrà il programma una volta eseguito. In questa fase viene calcolato un punteggio (sommatoria dei vari punteggi delle euristiche);
* **determinazione del risultato**: in base al punteggio e sopra un certo valore (chiamato valore di threshold - definito dall'utente), MicroSCOPE assocerà un certo punteggio a un comportamento malevolo;
