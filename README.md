# parlaConANPR




# Descrizione
Script Python **didattico** per interagire con il servizio C001 (Notifica) di ANPR, l'Anagrafe Nazionale della Popolazione Residente, tramite la PDND (Piattaforma Digitale Nazionale Dati).  
Lo script funziona nell'**ambiente di collaudo** e nell'**ambiente di produzione** di PDND e di INAD.  
Per l'**uso in ambiente di produzione** è sufficiente:
- cambiare il valore delle variabili degli endpoint di PDND e ANPR (commentare e decommentare le rispettive righe);
- sostiture 'verify = False' con 'verify = True' nelle chiamate requests delle funzioni estrai_residenza(_*) [un "trova e sostituisci" fa il suo lavoro)  

L'interazione avviene tramite riga di comando. Anche la configurazione, al primo avvio, è interattiva da riga di comando. I dati di configurazione sono cifrati e per avviare lo script occorre una password (vedi sotto).

Un file con soggetti registrati nell'ambiente ANPR di collaudo è disponibile nella documentazione di alcuni e-service ANPR su PDND. Per comodità il file è presente anche nella cartella docs.

# Prerequisiti e configurazione

Per l'esecuzione dello script è necessaria un'installazione di Python con alcuni moduli aggiuntivi (vedi sotto).

Per l'autorizzazione all'uso delle API di ANPR, si rimanda alla documentazione della PDND: https://docs.pagopa.it/interoperabilita-1/). In sintesi:
- aderire alla PDND;
- in ambiente di collaudo, creare l'accordo di fruizione dell'e-service "C001–servizioNotifica-approvazione_automatica, versione 1";
- attendere l'approvazione;
- creare coppia di chiavi come da documentazione;
- in ambiente di collaudo, creare un client e-service e caricarci la chiave pubblica;
- in ambiente di collaudo, creare una finalità per l'e-service "C001–servizioNotifica-approvazione_automatica, versione 1" e associarla al client e-service creato al punto precedente.

Per la generazione delle chiavi è disponibile lo script **[generatore/generatore.py](https://github.com/franthemanIT/parlaConINAD2/blob/main/generatore/generatore.py)** (nel repository di parlaConINAD2) che produce una coppia di chiavi crittografiche RSA in formato compatibile con le richieste PDND.

**Configurazione**:
Al primo avvio lo script richiede alcune informazioni:
- una **password** per accedere allo script e cifrare i dati di configurazione. La password non è recuperabile, quindi occorre custodirla in un posto sicuro e segreto;
- i dati del **client e-service ANPR**. Questi sono recuperabili dal back office PDND: conviene tenere la pagina PDND del client e-service e fare copia e incolla;
- la **chiave privata** associata alla chiave pubblica inserita nel client e-service: occorre salvare il file della chiave privata temporaneamente nella cartella di parlaConANPR e, una volta configurata, spostarlo.

La password deve soddisfare i seguenti criteri di robustezza (modificabile tramite l'espressione regolare RE_PASSWORD):
- ha lunghezza da 8 a 20 caratteri;
- contiene una lettera maiuscola;
- contiene una lettera minuscola;
- contiene un numero;
- contiene un carattere speciale (fra !, #, $, &, ?).

Se si perde la password occorre cancellare i file "ANPR.cfg" e "chiave.priv" e ripetere la configurazione.  
Il file di log di precedenti consultazioni non andranno perduti.

Sarebbe possibile l'installazione a partire da un file di configurazione e da una chiave cifrati proveniente dun'altra installazione (da rinominare come "ANPR.master.cfg" e "chiave.master.priv").  
Se i due file sono copiati nella cartella di lavoro di parlaConANPR, al primo avvio è possibile scegliere l'opzione "Configurazione da file master" (occorre inserire la password dell'installazione originaria).
Tuttavia, installare lo script su più postazioin utilizzando lo stesso client PDND non è una buona idea. Infatti le richieste devono essere numerate in sequenza e codividere la stessa configurazione su più postazioni crea incongruenze nella numerazione.

# Avvertenze e misure di sicurezza

Si tratta di un'**iniziativa didattica**, con lo scopo di:
- rendersi conto dell'interazione con ANPR e del passaggio tramite PDND;
- individuare aspetti di criticità per integrazioni stabili ed eleganti con software "veri" in produzione.

Sono comunque considerati, sempre a scopo didattico, aspetti di sicurezza:
- chiave privata e dati del client e-service sono memorizzati cifrati nella cartella di parlaConANPR;
- conseguentemente, chi ha accesso alla cartella non li vede in chiaro;
- i dati sono cifrati con una chiave ricavata dalla password impostata al primo avvio: per questo la password non è memorizzata in alcun modo (nemmeno come hash);
- di conseguenza chi non conosce la password non può utilizzare efficacemente lo script;
- è presente una gestione minimale di errori e eccezioni;
- sono presenti controlli sul formato dei dati di input per codici fiscalim id anpr e date.

Lo script fa accesso a ANPR che è una banca dati consultabile solo da parte di utenti autorizzati.
**Si rimette alla valutazione di ognuno l'implementazione di ulteriori misure di sicurezza**, specialmente se si intende usare lo script nell'ambiente ANPR di produzione e se la chiave privata è usata anche per altri e-service.  
Sicuramente lo script, configurato, va mantenuto su una postazione protetta.  
Infine, lo script è pensato per l'uso presidiato da riga di comando e non per essere integrato in software più estesi.  

# Documentazione su ANPR

Le specifiche delle API di ANPR sono disponibili direttamente su PDND. Nella cartella docs si trova una copia delle specifiche in formato OPENAPI (potrebbe non essere aggioranto, fare sempre riferimento al catalogo PDND) e la loro descrizione testuale.
Per visualizzarle in modo più comprensibile si può caricare il fiel YAML su https://editor.swagger.io/ (come link o come upload).  
Personalmente non ho trovato le specifiche del tutto esaustive, per esempio sull'indicazione dei campi obbligatori e sui valori accettati per alcuni campi (maiuscolo/minuscolo, lista di valori ammessi).

La circolare del Ministero dell'interno (DAIT) con le linee guida per l'accesso ai dati ANPR da parte degli uffici comunali è la n. 73 del 31 maggio 2023: [https://dait.interno.gov.it/servizi-demografici/circolari/circolare-dait-n73-del-31-maggio-2023](https://dait.interno.gov.it/servizi-demografici/circolari/circolare-dait-n73-del-31-maggio-2023) (il link potrebbe non funzionare, fai copia e incolla oppure cercala manualmente).

ATTENZIONE: come restituito in coda alle interrogazioni, il decreto del Ministero dell'interno 3 marzo 2023 (art.3 comma 3) prevede che la consultazione di ANPR avvenga esclusivamente con identificativo unico nazionale (ID ANPR). Probabilmente, a breve, le interrogazioni traite codice fiscale o dati anagrafici di base non saranno più possibili. Questo renderà probabilmente inutilizzabili gli e-service di ANPR per la maggior parte dei casi d'uso (se ho l'ID ANPR di un soggetto probabilmente conosco anche la sua residenza).

# Prerequisiti Python

Gli script fanno uso di alcuni moduli, fra cui:
- python-jose;
- requests;
- cryptography;
- urllib3;
- pyinputplus;
- pwinput,
che potrebbero non essere parte dell'installazione standard di Python. 
Verificare di averli installati.  

**File requirements.txt in preparazione** (poi: *pip install -r .\requirements.txt*).

# Consigli per l'uso dello script

Se tutto va bene, in ambiente Windows, un doppio click su parlaConANPR.py avvia lo script.

Lo script implementa le 3 modalità di ricerca previste dall'e-service:
1) a partire dal codice fiscale;
2) a partire dall'ID ANPR;
3) a partire dai dati anagrafici di base (nome, cognome, sesso, data e luogo di nascita).

E' sempre richiesto di specificare il motivo / il riferimento al procedimento amministrativo per cui si effettua l'interrogazione e la data di riferimento per la consultazione.  

**3 - Estrazione a partire dai dati anagrafici di base**

Per semplicità lo script funziona ed è stato provato per soggetti nati in Italia e con data di nascita certa.

# Trasformare in eseguibile Windows

Su sistemi Windows è possibile **trasformare lo script in un eseguibile** .exe che mantiene la stessa logica di funzionamento.  

Istruzioni:
- SE MANCA: pip install pyinstaller
- pyinstaller parlaConANPR.py --onefile

Sotto la cartella "dist/" si recupera l'eseguibile Windows.
Utile per usarlo su PC senza Python installato.


