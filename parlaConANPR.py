'''Script per l'interrogazione di ANPR (Indice Nazionale dei Domicili Digitali) tramite API.
Per l'autenticazione si fa riferimento alla PDND (Piattaforma Digitale Nazionale Dati),
secondo il ModI.'''
## Autore: Francesco Del Castillo (2024)
import datetime
import time
import sys
import uuid
import os
import base64
import socket
import json
import csv
import re
import logging  #per log di requests
import random
import hashlib
from jose import jwt
from jose.constants import Algorithms
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
import pwinput
import pyinputplus as pyip

##URL E AUDIENCE

#Ambiente di collaudo
BASE_URL_AUTH = "https://auth.uat.interop.pagopa.it/token.oauth2" 
BASE_URL_ANPR = "https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR-PDND/C001–servizioNotifica/v1"
AUD_INTEROP = "auth.uat.interop.pagopa.it/client-assertion"
AUD_ANPR = 'https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR/C001-servizioNotifica/v1'
target = "https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR-PDND/C001-servizioNotifica/v1/anpr-service-e002"
DURATA_TOKEN = 600 #600 in produzione (in secondi)

# Ambiente di produzione
# BASE_URL_AUTH = "https://auth.interop.pagopa.it/token.oauth2" #Ambiente PDND di produzione
# BASE_URL_ANPR = "https://modipa.anpr.interno.it/govway/rest/in/MinInternoPortaANPR-PDND/C001–servizioNotifica/v1"
# target = "https://modipa.anpr.interno.it/govway/rest/in/MinInternoPortaANPR-PDND/C001–servizioNotifica/v1/anpr-service-e002"
# AUD_INTEROP = "auth.interop.pagopa.it/client-assertion"
# AUD_ANPR = 'https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR/C001-servizioNotifica/v1'
# DURATA_TOKEN = 600 #600 in produzione, 86400 in collaudo (in secondi)

#nome del file di log generale
LOG_FILE_NAME="ANPR.log"

#Regole per il logging delle chiamate requests (si loggano solo le chiamate per estrazioni massive)
#logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("urllib3")
log.setLevel(logging.DEBUG)

## Funzioni e variabili globali che servono per l'interazione con l'utente
def get_ip_address():
    '''Recupera e restituisce l'indirizzo IP dell'utente'''
    return socket.gethostbyname(socket.gethostname())

CALLING_IP = get_ip_address()
CALLING_USER = os.getlogin()
CALLING_HOSTNAME = socket.gethostname()

def timestamp():
    '''Restituisce il timestamp attuale in formato %Y%m%d-%H%M%S-%f'''
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")

def timestamp_breve():
    '''Restituisce il timestamp attuale in formato %Y%m%d-%H%M%S'''
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    
def attendi():
    '''Richiede un'interazione dell'utente per proseguire'''
    input("Premi INVIO/ENTER per proseguire.")

def termina():
    '''Richiede un'interazione dell'utente per terminare il programma
    Utile anche a fine srpt per evitare di perdere quanto scritto a video'''
    input("Premi INVIO/ENTER per terminare.")
    sys.exit()

RE_CF = "^([0-9]{11})|([A-Za-z]{6}[0-9]{2}[A-Za-z]{1}[0-9]{2}[A-Za-z]{1}[0-9]{3}[A-Za-z]{1})$"
RE_IDANPR = "^([a-zA-Z0-9]{9})$"
RE_SESSO = "^([mMfF]{1})$"
RE_MAIL = "^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

def chiedi_cf():
    '''Chiede di inserire un codice fiscale / partita IVA e valida il formato.'''
    ottieni_cf = False
    while ottieni_cf is False:
        x = input("Inserisci il codice fiscale per cui estrarre i dati anagrafici: ")
        if re.match(RE_CF, x):
            ottieni_cf = True
        else:
            print("Codice fiscale non valido.")
    return x

def chiedi_data():
    '''Chiede di inserire una data G/M/A o G-M-A
    e la restituisce AAAA-MM-GG'''
    x = pyip.inputDate(prompt = "Inserisci la data alla quale verificare: ",
        formats=["%d/%m/%y", "%d/%m/%Y", "%d-%m-%y", "%d-%m-%Y"])
    y = x.strftime("%Y-%m-%d")
    return y

def chiedi_data_nascita():
    '''Chiede di inserire una data G/M/A o G-M-A
    e la restituisce AAAA-MM-GG'''
    x = pyip.inputDate(prompt = "Data di nascita: ",
        formats=["%d/%m/%y", "%d/%m/%Y", "%d-%m-%y", "%d-%m-%Y"])
    y = x.strftime("%Y-%m-%d")
    return y
    
def chiedi_idanpr():
    '''Chiede di inserire un ID ANPR IVA e valida il formato.'''
    ottieni_idanpr = False
    while ottieni_idanpr is False:
        x = input("Inserisci l'ID ANPR per cui estrarre i dati anagrafici: ")
        if re.match(RE_IDANPR, x):
            ottieni_idanpr = True
        else:
            print("ID ANPR non valido.")
    return x
    
def chiedi_sesso():
    '''Chiede di inserire un sesso M o F.'''
    ottieni_sesso = False
    while ottieni_sesso is False:
        x = input("Inserisci il sesso (M o F): ")
        if re.match(RE_SESSO, x):
            ottieni_sesso = True
        else:
            print("Sesso non valido.")
    return x.upper()

## Funzioni che servono per la manipolazione di file di input e output
# def crea_cartella(descrizione, data_e_ora=timestamp_breve()):
    # '''Crea una sottocartella nella cartella di esecuzione dello script
    # Se l'argomento data_e_ora è nullo, usa un timestamp breve al suo posto.'''
    # path="./lotti/" + data_e_ora + "-" + descrizione + "/"
    # if not os.path.isdir(path):
        # os.mkdir(path)
    # return path

def salva_dizionario(dizionario, file_out):
    '''Salva un dizionario in un file JSON'''
    with open(file_out, "w+") as file:
        file.write(json.dumps(dizionario, sort_keys=False, indent=4))

## Funzioni che servono per il logging
def log_request(log_file, request_time, verbo, metodo, info):
    '''Aggiunge una riga al file log_file, con gli argomenti divisi da un ;
    Si usa per annotare nel log le request di requests'''
    riga_di_log=[request_time, CALLING_IP, CALLING_USER, CALLING_HOSTNAME, verbo, metodo, info]
    log_file.write(";".join(riga_di_log))
    log_file.write("\n")
    log_file.flush()

def log_response(log_file, response_time, request_time, status_code, info):
    '''Aggiunge una riga al file log_file, con gli argomenti divisi da un ;
    Si usa per annotare nel log le request di requests'''
    riga_di_log=[response_time, CALLING_IP, CALLING_USER, CALLING_HOSTNAME, request_time, str(status_code), info]
    log_file.write(";".join(riga_di_log))
    log_file.write("\n")
    log_file.flush()

# def logga(stringa, file_di_log = None):
    # '''Scrive una stringa nel log di lotto'''
    # file_di_log = file_di_log or LOTTO_LOG
    # with open(file_di_log, "a+") as file:
        # riga_di_log=[timestamp(),stringa]
        # file.write(";".join(riga_di_log))
        # file.write("\n")
        # file.flush()

# def stampa(stringa, file_di_log = None):
    # '''Scrive una stringa a schermo e nel log di lotto'''
    # file_di_log = file_di_log or LOTTO_LOG
    # print(stringa)
    # with open(file_di_log, "a+") as file:
        # riga_di_log=[timestamp(),stringa]
        # file.write(";".join(riga_di_log))
        # file.write("\n")
        # file.flush()

# def clear():
    # '''Cancella la schermo'''
    # os.system("cls" if os.name == "nt" else "clear")

## Funzioni crittografiche
# def cifra_stringa(stringa, chiave):
    # '''Cifra una stringa con la chiave indicata'''
    # fernet = Fernet(chiave)
    # fernet.encrypt(stringa.encode())

# def decifra_stringa(stringa, chiave):
    # '''Decifra una stringa cifrata tramite la chiave indicata'''
    # fernet = Fernet(chiave)
    # fernet.decrypt(stringa).decode()

def cifra_dizionario(diz, chiave, output_file):
    '''Salva un dizionario diz nel file output_file cifrato con la chiave "chiave" '''
    fernet = Fernet(chiave)
    a = json.dumps(diz, indent=4).encode()
    b =fernet.encrypt(a)
    with open(output_file, "wb") as f:
        f.write(b)

def decifra_dizionario(input_file, chiave):
    '''Decifra un dizionario memorizzato in un file JSON'''
    fernet = Fernet(chiave)
    with open(input_file, "rb") as f:
        a = f.read()
        b = fernet.decrypt(a)
        c = b.decode()
        d = json.loads(c)
    return d

def cifra_file(file_da_cifrare, chiave, output_file = ""):
    '''Cifra un file in un altro file'''
    if output_file == "":
        output_file = file_da_cifrare
    with open(file_da_cifrare, "rb") as f:
        originale = f.read()
    fernet = Fernet(chiave)
    cifrato = fernet.encrypt(originale)
    with open(output_file, "wb") as f:
        f.write(cifrato)

def decifra_file(file_da_decifrare, chiave, output_file = ""):
    '''Decifra un file in un altro file'''
    if output_file == "":
        output_file = file_da_decifrare
    with open(file_da_decifrare, "rb") as f:
        cifrato = f.read()
    fernet = Fernet(chiave)
    originale = fernet.decrypt(cifrato)
    with open(output_file, "wb") as f:
        f.write(originale)

def ricifra_file(file_da_ricifrare, chiave1, chiave2, output_file):
    '''Decifra un file cifrato con chiave 1 o la cifra con chiave2'''
    with open(file_da_ricifrare, "rb") as f:
        cifrato = f.read()
        fernet = Fernet(chiave1)
        in_chiaro = fernet.decrypt(cifrato)
        fernet = Fernet(chiave2)
        ricifrato = fernet.encrypt(in_chiaro)
    with open(output_file, "wb") as f:
        f.write(ricifrato)
        
def recupera_chiave(file_cifrato, chiave):
    '''Recupera la chiave privata da un file cifrato con cifraChiave.
    In realtà decifra qualsiasi file cifrato e lo restituisce come risultato.'''
    with open(file_cifrato, "rb") as f:
        fernet = Fernet(chiave)
        a = f.read()
        b = fernet.decrypt(a)
    return b

salt = b"parlaConANPR"
def kdf():
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        )

# def ottieni_chiave(stringa):
    # '''Ottiene la chiave crittografica a partire da una stringa'''
    # x = base64.urlsafe_b64encode(kdf().derive(stringa))
    # return x

def imposta_password():
    '''Chiede all'utente di impostare una password sicura
    e restituisce la chiave crittografica derivata'''
    RE_PASSWORD = "^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!#$%&?].*)(?=.*[\W]).{8,20}$"
    password_1 = ""
    while bool(re.match(RE_PASSWORD, password_1)) is False:
        print("Scegli una password. Fra 8 e 20 caratteri con una maiuscola, "\
              "una minuscola, un numero e un carattere speciale.")
        password_1 = pwinput.pwinput(prompt = "Scegli una password: ")
        password_2 = pwinput.pwinput(prompt= "Ripeti la password: ")
        while password_1 != password_2:
            print("Le password non coincidono. Ripeti.")
            password_1 = pwinput.pwinput(prompt = "Scegli una password: ")
            password_2 = pwinput.pwinput(prompt= "Ripeti la password: ")
        if bool(re.match(RE_PASSWORD, password_1)) is False:
            print("Password debole. Ripeti.")
    parola = password_1.encode()
    x = base64.urlsafe_b64encode(kdf().derive(parola))
    password_1 = ""
    password_2 = ""
    parola = b""
    return x

## Funzioni che servono per interazione con PDND per staccare il token
# def get_private_key(key_path):
    # '''Recupera la chiave privata dal file in cui è memorizzata.'''
    # with open(key_path, "rb") as private_key:
        # encoded_string = private_key.read()
        # return encoded_string


def create_audit_assertion(issued, clientid, audience, kid, alg, typ, key, purposeID):
    jti = uuid.uuid4()
    #issued = datetime.datetime.now(datetime.timezone.utc)
    delta = datetime.timedelta(minutes=43200)
    expire_in = issued + delta
    dnonce = random.randint(1000000000000, 9999999999999)
    headers_rsa = {
        "kid": kid,
        "alg": alg,
        "typ": typ
    }
    audit_payload = {
        "userID": CALLING_USER,
        "userLocation": CALLING_HOSTNAME,
        "LoA": "2",
        "iss" : clientid,
        "aud" : audience,
        "purposeId": purposeID,
        "dnonce" : dnonce,
        "jti":str(jti),
        "iat": issued,
        "nbf" : issued,
        "exp": expire_in
    }
    audit = jwt.encode(audit_payload, key, algorithm=Algorithms.RS256, headers=headers_rsa)
    audit_hash = hashlib.sha256(audit.encode('UTF-8')).hexdigest()
    return (audit, audit_hash)
   
def create_m2m_client_assertion(issued, kid, alg, typ, iss, sub, aud, key, audit_hash, purposeID = ""):
    '''Crea l'asserzione JWT e la firma, per ottenere il token da PDND.'''
    #issued = datetime.datetime.now(datetime.timezone.utc)
    delta = datetime.timedelta(minutes=43200)
    expire_in = issued + delta
    jti = uuid.uuid4()
    headers_rsa = {
        "kid": kid,
        "alg": alg,
        "typ": typ
    }
    payload = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "jti": str(jti),
        "iat": issued,
        "exp": expire_in,
        "purposeId" : purposeID,
        "digest": {
            "alg": "SHA256",
            "value": audit_hash
        }
    }
    client_assertion = jwt.encode(payload, key, algorithm=Algorithms.RS256, headers=headers_rsa)
    return client_assertion

def token_request(client_id, client_assertion, client_assertion_type, grant_type):
    '''Invia l'asserzione firmata a PDND e recupea il token di autenticazione per ANPR.'''
    body = {
        "client_id" : client_id,
        "client_assertion" : client_assertion,
        "client_assertion_type" : client_assertion_type,
        "grant_type" : grant_type
    }
    headers = {"Content-Type" : "application/x-www-form-urlencoded"}
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(log_file, request_time, "POST", "token_request", client_id)
        r = requests.post(BASE_URL_AUTH, headers = headers, timeout=100, data=body)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r

## Funzioni per l'interazione con ANPR (autoesplicative)
def estrai_residenza(token, contatore, cf, data, motivo, client_id, audience, purposeID, issued, kid, alg, typ, key, audit):
    '''Interroga ANPR per estrarre i dati anagrafici a partire dal codice fiscale cf
    ref è il practicalReference cioè il riferimento al procedimento amministrativo
    per il quale si richiede l'estrazione'''
    #url = BASE_URL_ANPR+"/anpr-service-e002"
    url = target
    #prepara il body della richiesta
    bodyDic = {"idOperazioneClient" : contatore,
        "criteriRicerca": {
            "codiceFiscale": cf
        },
        "datiRichiesta": {
            "dataRiferimentoRichiesta": data,
            "motivoRichiesta": motivo,
            "casoUso": "C001"
        }
    }
    body = json.dumps(bodyDic)
    body_digest = hashlib.sha256(body.encode("UTF-8"))
    digest = 'SHA-256=' + base64.b64encode(body_digest.digest()).decode("UTF-8")
    #crea la firma della richiesta
    jti = uuid.uuid4()
    delta = datetime.timedelta(minutes=43200)
    expire_in = issued + delta
    print(expire_in)
    payload = {
      "iss" : client_id,
      "aud" : audience,
      "purposeId": purposeID,
      "sub": client_id,
      "jti": str(jti),
      "iat": issued,
      "nbf": issued,
      "exp": expire_in,
      "signed_headers": [
          {"digest": digest},
          {"content-type": 'application/json'},
          {"content-encoding": "UTF-8"}
      ]
    }    
    headers_rsa = {
        "kid": kid,
        "alg": alg,
        "typ": typ
    }
    signature = jwt.encode(payload, key, algorithm=Algorithms.RS256, headers=headers_rsa)  
    #crea l'header della richiesta   
    headers = {"Accept": "application/json",
        "Content-Type": "application/json",
        "Content-Encoding": "UTF-8",
        "Digest": digest,
        "Authorization":"Bearer " + token,
        "Agid-JWT-TrackingEvidence": audit,
        "Agid-JWT-Signature": signature
    }
    #invia la richiesta
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "GET", "estrai", "richiesti dati per "+cf[:2]+"***"+" idOp "+str(contatore)
            )
        r = requests.post(url, data = body.encode('UTF-8'), headers = headers, verify = False)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r

def estrai_residenza_id(token, contatore, idanpr, data, motivo, client_id, audience, purposeID, issued, kid, alg, typ, key, audit):
    '''Interroga ANPR per estrarre i dati anagrafici a partire dall'identificativo unico nazione (ID ANPR)
    ref è il practicalReference cioè il riferimento al procedimento amministrativo
    per il quale si richiede l'estrazione'''
    #url = BASE_URL_ANPR+"/anpr-service-e002"
    url = target
    #prepara il body della richiesta
    bodyDic = {"idOperazioneClient" : contatore,
        "criteriRicerca": {
            "idANPR": idanpr
        },
        "datiRichiesta": {
            "dataRiferimentoRichiesta": data,
            "motivoRichiesta": motivo,
            "casoUso": "C001"
        }
    }
    body = json.dumps(bodyDic)
    body_digest = hashlib.sha256(body.encode("UTF-8"))
    digest = 'SHA-256=' + base64.b64encode(body_digest.digest()).decode("UTF-8")
    #crea la firma della richiesta
    jti = uuid.uuid4()
    delta = datetime.timedelta(minutes=43200)
    expire_in = issued + delta
    print(expire_in)
    payload = {
      "iss" : client_id,
      "aud" : audience,
      "purposeId": purposeID,
      "sub": client_id,
      "jti": str(jti),
      "iat": issued,
      "nbf": issued,
      "exp": expire_in,
      "signed_headers": [
          {"digest": digest},
          {"content-type": 'application/json'},
          {"content-encoding": "UTF-8"}
      ]
    }    
    headers_rsa = {
        "kid": kid,
        "alg": alg,
        "typ": typ
    }
    signature = jwt.encode(payload, key, algorithm=Algorithms.RS256, headers=headers_rsa)  
    #crea l'header della richiesta   
    headers = {"Accept": "application/json",
        "Content-Type": "application/json",
        "Content-Encoding": "UTF-8",
        "Digest": digest,
        "Authorization":"Bearer " + token,
        "Agid-JWT-TrackingEvidence": audit,
        "Agid-JWT-Signature": signature
    }
    #invia la richiesta
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "GET", "estrai", "richiesti dati per ID ANPR "+idanpr[:3]+"***"+" idOp "+str(contatore)
            )
        r = requests.post(url, data = body.encode('UTF-8'), headers = headers, verify = False)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r
    
def estrai_residenza_dati(token, contatore, nome, cognome, sesso, data_nascita, luogo_nascita, prov_nascita, data, motivo, client_id, audience, purposeID, issued, kid, alg, typ, key, audit):
    '''Interroga ANPR per estrarre i dati di residenza a partire da alcuni dati anagrafici (nome, cognome, sesso, data e luogo di nascita
    ref è il practicalReference cioè il riferimento al procedimento amministrativo
    per il quale si richiede l'estrazione'''
    #url = BASE_URL_ANPR+"/anpr-service-e002"
    url = target
    #prepara il body della richiesta
    bodyDic = {"idOperazioneClient" : contatore,
        "criteriRicerca": {
            "cognome": cognome,
            "nome": nome,
            "sesso": sesso,
            "datiNascita": {
                "dataEvento": data_nascita,
                "luogoNascita": {
                    "comune": {
                        "nomeComune": luogo_nascita,
                        "siglaProvinciaIstat": prov_nascita
                    }
                }
            }
        },
        "datiRichiesta": {
            "dataRiferimentoRichiesta": data,
            "motivoRichiesta": motivo,
            "casoUso": "C001"
        }
    }
    body = json.dumps(bodyDic)
    body_digest = hashlib.sha256(body.encode("UTF-8"))
    digest = 'SHA-256=' + base64.b64encode(body_digest.digest()).decode("UTF-8")
    #crea la firma della richiesta
    jti = uuid.uuid4()
    delta = datetime.timedelta(minutes=43200)
    expire_in = issued + delta
    print(expire_in)
    payload = {
      "iss" : client_id,
      "aud" : audience,
      "purposeId": purposeID,
      "sub": client_id,
      "jti": str(jti),
      "iat": issued,
      "nbf": issued,
      "exp": expire_in,
      "signed_headers": [
          {"digest": digest},
          {"content-type": 'application/json'},
          {"content-encoding": "UTF-8"}
      ]
    }    
    headers_rsa = {
        "kid": kid,
        "alg": alg,
        "typ": typ
    }
    signature = jwt.encode(payload, key, algorithm=Algorithms.RS256, headers=headers_rsa)  
    #crea l'header della richiesta   
    headers = {"Accept": "application/json",
        "Content-Type": "application/json",
        "Content-Encoding": "UTF-8",
        "Digest": digest,
        "Authorization":"Bearer " + token,
        "Agid-JWT-TrackingEvidence": audit,
        "Agid-JWT-Signature": signature
    }
    #invia la richiesta
    with open(LOG_FILE_NAME, "a+") as log_file:
        request_time=timestamp()
        log_request(
            log_file, request_time, "GET", "estrai", "richiesti dati per "+nome[:2]+"*** "+cognome[:2] +"*** idOp "+str(contatore)
            )
        r = requests.post(url, data = body.encode('UTF-8'), headers = headers, verify = False)
        response_time=timestamp()
        info = str(r.status_code)
        log_response(log_file, response_time, request_time, r.status_code, info)
    return r

def ottieni_token(file, chiave):                
    TOKEN_DISPONIBILE = False
    while TOKEN_DISPONIBILE is False:
        if os.path.exists(file) is True:
            print("Verifico se il token PDND è ancora valido.")
            try:
                tokenDict = decifra_dizionario(file, chiave)
                allora = datetime.datetime.strptime(tokenDict["creato"], "%a, %d %b %Y %H:%M:%S %Z")
                adesso = datetime.datetime.utcnow()
                if int((adesso - allora).total_seconds()) < (DURATA_TOKEN-30):
                    token = tokenDict["token"]
                    print("Token valido.")
                    TOKEN_DISPONIBILE = True
                    return (token, tokenDict)
                else:
                    print("Token non valido.")
                    os.remove(file)
            except:
                os.remove(file)
        else:
            print("\nNessun token PDND valido per ANPR è disponibile. Ne ottengo uno.")
            privateKey = recupera_chiave("chiave.priv", chiave)
            issued = datetime.datetime.now(datetime.timezone.utc)
            (audit, audit_hash) = create_audit_assertion(issued, ANPR["Client_id"], ANPR["aud_anpr"], ANPR["kid"], ANPR["alg"], ANPR["typ"], privateKey, ANPR["PurposeID"])
            client_assertion = create_m2m_client_assertion(issued, ANPR["kid"], ANPR["alg"], ANPR["typ"],
                ANPR["iss"], ANPR["sub"], ANPR["aud_interop"], privateKey, audit_hash, ANPR["PurposeID"])
            token_response = token_request(ANPR["iss"], client_assertion,
                ANPR["Client_assertion_type"], ANPR["Grant_type"])
            tokenDict = {}
            if token_response.status_code == 200:
                tokenDict["token"] = token_response.json()["access_token"]
                tokenDict["creato"] = token_response.headers["date"]
                tokenDict["issued"] = str(issued)
                tokenDict["audit"] = audit
                tokenDict["audit_hash"] = audit_hash
                cifra_dizionario(tokenDict, chiave, file)
                print("Ho creato il token (o voucher). Proseguiamo...")
                token = tokenDict["token"]
                TOKEN_DISPONIBILE = True
                return (token, tokenDict)
            else:
                print("Non sono riuscito a creare il token. Di seguito la risposta completa.")
                try:
                    print(token_response.content.decode())
                except:
                    print(token_response.content)
                termina()

#####################################
###INIZIO DELLO SCRIPT INTERATTIVO###
#####################################

#####################################
### INSTALLAZIONE AL PRIMO AVVIO ####
#####################################
print("Benvenuto "+CALLING_USER+".")
if os.path.exists("ANPR.cfg") is False:
    CONFIGURATO = False
    print("Il programma non è configurato.")
    print("Ti chiederò di: ")
    print("- scegliere una password")
    print("- inserire i dati di configurazione del client e-service PDND di ANPR;")
    print("- indicare il nome del file della chiave privata.")
    chiave = imposta_password()
    print("Password impostata. \nAnnotala in un luogo segreto e sicuro: "\
          "NON potrai recuperarla in alcun modo.")
    if (os.path.exists("ANPR.master.cfg") and os.path.exists("chiave.master.priv")) is True:
        print("Scegli: ")
        tipo_configurazione = pyip.inputMenu(["Configurazione manuale", "Configurazione da file master"],\
                                             numbered = True)
        if  tipo_configurazione == "Configurazione manuale":
            pass   
        else:
            print("\nHai bisogno della password master.\n")
            passwM = pwinput.pwinput(prompt = "Inserici la password dei file master: ")
            passwordM = passwM.encode()
            CHIAVEM = base64.urlsafe_b64encode(kdf().derive(passwordM))
            passwM = ""
            passwordM = b""
            PASSWORDM_CORRETTA = False
            while PASSWORDM_CORRETTA is False:
                try:
                    ricifra_file("ANPR.master.cfg", CHIAVEM, chiave, "ANPR.cfg")
                    print("Configurazione di ANPR importata.")
                    PASSWORDM_CORRETTA = True
                except:
                        print("La password NON è corretta.")
                        passwM = pwinput.pwinput()
                        passwordM = passwM.encode()
                        CHIAVEM = base64.urlsafe_b64encode(kdf().derive(passwordM))
                        passwM = ""
                        passwordM = b""
            ricifra_file("chiave.master.priv", CHIAVEM, chiave, "chiave.priv")
            CHIAVEM = ""
            CONFIGURATO = True
    if CONFIGURATO is False:
        print("Configuriamo i dati del client e-service di ANPR. Li trovi nel back-office della PDND.")
        #seguono i parametri che servono per contattare il client e-service ANPR su PDND.
        #I predefiniti si possono modificare o sostituire con "" per inserirli interattivamente.
        ANPR = {
                      "kid" : "",
                      "typ" : "JWT",
                      "iss" : "",
                      "sub" : "",
                      "aud_interop" : AUD_INTEROP,
                      "aud_anpr" : AUD_ANPR,
                      "alg" : "RS256",
                      "PurposeID" : "",
                      "Client_id" : "",
                      "Client_assertion_type" : "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                      "Grant_type" : "client_credentials",
                      "baseURL" : BASE_URL_ANPR
                     }
        lista = []
        for i in ANPR:
            if ANPR[i] == "":
                lista.append(i)
        for i in lista:
            value = input(i+": ")
            ANPR[i] = value
        cifra_dizionario(ANPR, chiave, "ANPR.cfg")
        print("Dati del client e-service configurati.")
        print("Configuriamo la chiave privata.")
        print("Ti conviene copiare il file con la chiave privata nella cartella del programma.")
        nome_file_chiave = input("Nome del file della chiave privata (es.: key.priv): ")
        CHIAVE_TROVATA = False
        while CHIAVE_TROVATA is False:
            if os.path.exists(nome_file_chiave):
                CHIAVE_TROVATA = True
                print("File trovato.")
                cifra_file(nome_file_chiave, chiave, "chiave.priv")
                print("Ho configurato la chiave in un file cifrato. "\
                      "Cancella il file " + nome_file_chiave + " dalla cartella del programma.")
            else:
                nome_file_chiave = input(
                    "File "+ nome_file_chiave + "non trovato. Verifica e "\
                    "inserisci di nuovo il nome del file della chiave privata: "
                    )
        print("La configurazione è terminata. \n"\
              "Ricorda la password per avviare i programmi di interazione con ANPR.")
elif os.path.exists("chiave.priv") is False:
    print("IL programma è configurato a metà. Manca la chiave privata "\
          "da usare per il service e-client ANPR.")
    print("Ti chiederò di inserire la password precedentemente scelta.")
    print("Se non la ricordi, cancella il file \'ANPR.cfg\' "\
          "dalla cartella del programma e avvia di nuovo l'installazione.")
    passw = pwinput.pwinput()
    password = passw.encode()
    chiave = base64.urlsafe_b64encode(kdf().derive(password))
    passw = ""
    password = b""
    PASSWORD_CORRETTA = False
    while PASSWORD_CORRETTA is False:
        with open("ANPR.cfg", "r") as f:
            try:
                ANPR = decifra_dizionario("ANPR.cfg", chiave)
                print("La password è corretta.")
                PASSWORD_CORRETTA = True
            except:
                print("La password NON è corretta.")
                passw = pwinput.pwinput()
                password = passw.encode()
                chiave = base64.urlsafe_b64encode(kdf().derive(password))
                passw = ""
                password = b""
    print("Copia il file con la chiave privata associata "\
          "al client e-service ANPR nella cartella del programma.")
    nome_file_chiave = input("Nome del file della chiave privata (es.: key.priv): ")
    CHIAVE_TROVATA = False
    while CHIAVE_TROVATA is False:
        if os.path.exists(nome_file_chiave):
            CHIAVE_TROVATA = True
            print("File trovato.")
            cifra_file(nome_file_chiave, chiave, "chiave.priv")
            print("Ho configurato la chiave in un file cifrato. "\
                  "Cancella il file " + nome_file_chiave + " dalla cartella del programma.")
        else:
            nome_file_chiave = input(
                "File "+ nome_file_chiave + " non trovato. \n \
                Verifica e inserisci di nuovo il nome del file della chiave privata: "
                )
    print("La configurazione è terminata. \n"\
          "Ricorda la password per avviare i programmi di interazione con ANPR.")
else:
    print("Il programma sembra già configurato.")
    print("Se non ricordi la password cancella dalla cartella del programma "\
          "i file \'ANPR.cfg\' e \'chiave.priv\' e ripeti l'installazione.")

#####################################
### AVVIO INTERAZIONE CON ANPR  #####
#####################################

#Verifica se configurazione presente e chiedi e verifica password.
if "chiave" in locals():
    print("\nSei già loggato. Proseguiamo.")
else:
    passw = pwinput.pwinput()
    password = passw.encode()
    chiave = base64.urlsafe_b64encode(kdf().derive(password))
    passw = ""
    password = b""
    PASSWORD_CORRETTA = False
    while PASSWORD_CORRETTA is False:
        with open("ANPR.cfg", "r") as f:
            try:
                ANPR = decifra_dizionario("ANPR.cfg", chiave)
                print("La password è corretta.")
                PASSWORD_CORRETTA = True
            except:
                print("La password NON è corretta.")
                passw = pwinput.pwinput()
                password = passw.encode()
                chiave = base64.urlsafe_b64encode(kdf().derive(password))
                passw = ""
                password = b""

CONTINUARE = True
while CONTINUARE is True:

    ###Scegli la funzione da usare
    print("\nparlaConANPR consente le seguenti funzioni: \n\n"\
          "1 - estrazione di dati anagrafici a partire dal codice fiscale; \n"\
          "2 - estrazione di dati anagrafici a partire dall'ID ANPR; \n"\
          "3 - estrazione della residenza a partire da dati; \n"\
          "U - esci da parlaConANPR.\n")
    scelta = ""
    while scelta not in ["1", "2", "3", "U", "u"]:
        scelta = input("Cosa vuoi fare? Scegli 1, 2 o 3 (U per uscire): ")
    if scelta in ["U", "u"]:
        print("\nCiao " + CALLING_USER + ", è stato un piacere fare affari con te ;)")
        termina()

    ##verifico presenza di un contatore valido (file ANPR.counter) 
    CONTATORE_DISPONIBILE = False
    print("Verifico la presenza del contatore delle richieste e lo aggiorno")
    while CONTATORE_DISPONIBILE is False:
        if os.path.exists("ANPR.counter") is True:
            print("Contatore trovato")
            try:
                with open("ANPR.counter", "r") as f:
                    Contatore = json.loads(f.read())
                    contatore = Contatore["contatore"]
                    CONTATORE_DISPONIBILE = True
            except:
                print("Qualcosa non va con il file del Contatore. Ne creo uno nuovo partendo da 1. Eventualmente aggiornalo a mano.")
                os.remove("ANPR.counter")
        else:
            print("\nNessun file contatore trovato. Lo creo.")
            Contatore = {}
            Contatore["contatore"] = 1
            salva_dizionario(Contatore, "ANPR.counter")
            print("Contatore creato, con valore 1.")
                
            
#############################
######  ESTRAZIONE DA CF    #
#############################
    if scelta == "1":
        print("\n"+scelta + " - Estrazione a partire dal codice fiscale\n")
        #contatore = "23"
        cf = chiedi_cf()
        data = chiedi_data()
        motivo = input("Inserisci un riferimento al procedimento amministrativo: ")
        print("Elaboro la richiesta con idOperazioneClient = "+str(contatore))
        ##verifico presenza di un token valido (file ANPR.tkn)
        (token, tokenDict) = ottieni_token("ANPR.tkn", chiave)
        privateKey = recupera_chiave("chiave.priv", chiave)
        format = "%Y-%m-%d %H:%M:%S.%f+00:00"
        #issued = datetime.datetime.strptime(tokenDict["issued"], format)
        issued = datetime.datetime.now(datetime.timezone.utc)
        estrazione = estrai_residenza(token, str(contatore), cf, data, motivo, ANPR["Client_id"], ANPR["aud_anpr"], ANPR["PurposeID"], issued, ANPR["kid"], ANPR["alg"], ANPR["typ"], privateKey, tokenDict["audit"])
        Contatore["contatore"] +=1
        salva_dizionario(Contatore, "ANPR.counter")
        if estrazione.status_code == 200:
            try:
                print("\nDati anagrafici di " + cf + " trovati. Id operazione ANPR: "\
                      +estrazione.json()["idOperazioneANPR"])
                a = json.dumps(estrazione.json(), indent = 4)
                print (a)
            except:
                print("\nL\'interazione è andata a buon fine, "\
                      "ma probabilmente il servizio è chiuso.")
            print("\nDi seguito la risposta completa di ANPR:")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
        elif estrazione.status_code == 400:
            print(estrazione.status_code)
            print("\nCaso d'uso invalido: ")
            print(json.dumps(estrazione.json(), indent = 4))
        elif estrazione.status_code == 404:
            print(estrazione.status_code)
            print("\nCaso d'uso non trovato: ")
            print(json.dumps(estrazione.json(), indent = 4))
        elif estrazione.status_code == 500:
            print(estrazione.status_code)
            print:("\nInternal server error: ")
            print(json.dumps(estrazione.json(), indent = 4))
        # elif estrazione.status_code == 404:
            # print(estrazione.json()["status"] +" - " + estrazione.json()["listaErrori"])
            # print("\nSoggetto non trovato. Ragionevolmente, "+cf+" non è registrato su ANPR")
            # print("\nDi seguito il contenuto completo della risposta: ")
            # print(estrazione.json())
        else:
            print("Qualcosa è andato storto, "\
                  "lo status code della risposta è: "+str(estrazione.status_code)+". "\
                  "Consulta le specifiche per maggiori informazioni")
            print("Di seguito il contenuto completo della risposta: ")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
#############################
######  ESTRAZIONE DA ID  ###
#############################
    elif scelta == "2":
        print("\n"+scelta + " - Estrazione a partire dall'ID ANPR\n")
        #contatore = "23"
        idanpr = chiedi_idanpr()
        data = chiedi_data()
        motivo = input("Inserisci un riferimento al procedimento amministrativo: ")
        print("Elaboro la richiesta con idOperazioneClient = "+str(contatore))
        ##verifico presenza di un token valido (file ANPR.tkn)
        (token, tokenDict) = ottieni_token("ANPR.tkn", chiave)
        privateKey = recupera_chiave("chiave.priv", chiave)
        format = "%Y-%m-%d %H:%M:%S.%f+00:00"
        #issued = datetime.datetime.strptime(tokenDict["issued"], format)
        issued = datetime.datetime.now(datetime.timezone.utc)
        estrazione = estrai_residenza_id(token, str(contatore), idanpr, data, motivo, ANPR["Client_id"], ANPR["aud_anpr"], ANPR["PurposeID"], issued, ANPR["kid"], ANPR["alg"], ANPR["typ"], privateKey, tokenDict["audit"])
        Contatore["contatore"] +=1
        salva_dizionario(Contatore, "ANPR.counter")
        if estrazione.status_code == 200:
            try:
                print("\nDati anagrafici di " + idanpr + " trovati. Id operazione ANPR: "\
                      +estrazione.json()["idOperazioneANPR"])
                a = json.dumps(estrazione.json(), indent = 4)
                print (a)
            except:
                print("\nL\'interazione è andata a buon fine, "\
                      "ma probabilmente il servizio è chiuso.")
            print("\nDi seguito la risposta completa di ANPR:")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
        elif estrazione.status_code == 400:
            print(estrazione.status_code)
            print("\nCaso d'uso invalido: ")
            print(json.dumps(estrazione.json(), indent = 4))
        elif estrazione.status_code == 404:
            print(estrazione.status_code)
            print("\nCaso d'uso non trovato: ")
            print(json.dumps(estrazione.json(), indent = 4))
        elif estrazione.status_code == 500:
            print(estrazione.status_code)
            print:("\nInternal server error: ")
            print(json.dumps(estrazione.json(), indent = 4))
        # elif estrazione.status_code == 404:
            # print(estrazione.json()["status"] +" - " + estrazione.json()["listaErrori"])
            # print("\nSoggetto non trovato. Ragionevolmente, "+cf+" non è registrato su ANPR")
            # print("\nDi seguito il contenuto completo della risposta: ")
            # print(estrazione.json())
        else:
            print("Qualcosa è andato storto, "\
                  "lo status code della risposta è: "+str(estrazione.status_code)+". "\
                  "Consulta le specifiche per maggiori informazioni")
            print("Di seguito il contenuto completo della risposta: ")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
                
#############################
######  ESTRAZIONE DA DATI###
#############################
    elif scelta == "3":
        print("\n"+scelta + " - Estrazione a partire da dati\n")
        #contatore = "23"
        nome = input("Nome: ")
        cognome = input("Cognome: ")
        sesso = chiedi_sesso()
        data_nascita = chiedi_data_nascita()
        luogo_nascita = input("Comune di nascita (o stato estero): ")
        prov_nascita = input("Sigla della provincia di nascita: ").upper()
        data = chiedi_data()
        motivo = input("Inserisci un riferimento al procedimento amministrativo: ")
        print("Elaboro la richiesta con idOperazioneClient = "+str(contatore))
        ##verifico presenza di un token valido (file ANPR.tkn)
        (token, tokenDict) = ottieni_token("ANPR.tkn", chiave)
        privateKey = recupera_chiave("chiave.priv", chiave)
        format = "%Y-%m-%d %H:%M:%S.%f+00:00"
        #issued = datetime.datetime.strptime(tokenDict["issued"], format)
        issued = datetime.datetime.now(datetime.timezone.utc)
        estrazione = estrai_residenza_dati(token, str(contatore), nome, cognome, sesso, data_nascita, luogo_nascita, prov_nascita,data, motivo, ANPR["Client_id"], ANPR["aud_anpr"], ANPR["PurposeID"], issued, ANPR["kid"], ANPR["alg"], ANPR["typ"], privateKey, tokenDict["audit"])
        Contatore["contatore"] +=1
        salva_dizionario(Contatore, "ANPR.counter")
        if estrazione.status_code == 200:
            try:
                print("\nDati anagrafici di " + nome + " " + cognome + " trovati. Id operazione ANPR: "\
                      +estrazione.json()["idOperazioneANPR"])
                a = json.dumps(estrazione.json(), indent = 4)
                print (a)
            except:
                print("\nL\'interazione è andata a buon fine, "\
                      "ma probabilmente il servizio è chiuso.")
            print("\nDi seguito la risposta completa di ANPR:")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
        elif estrazione.status_code == 400:
            print(estrazione.status_code)
            print("\nCaso d'uso invalido: ")
            print(json.dumps(estrazione.json(), indent = 4))
        elif estrazione.status_code == 404:
            print(estrazione.status_code)
            print("\nCaso d'uso non trovato: ")
            print(json.dumps(estrazione.json(), indent = 4))
        elif estrazione.status_code == 500:
            print(estrazione.status_code)
            print:("\nInternal server error: ")
            print(json.dumps(estrazione.json(), indent = 4))
        # elif estrazione.status_code == 404:
            # print(estrazione.json()["status"] +" - " + estrazione.json()["listaErrori"])
            # print("\nSoggetto non trovato. Ragionevolmente, "+cf+" non è registrato su ANPR")
            # print("\nDi seguito il contenuto completo della risposta: ")
            # print(estrazione.json())
        else:
            print("Qualcosa è andato storto, "\
                  "lo status code della risposta è: "+str(estrazione.status_code)+". "\
                  "Consulta le specifiche per maggiori informazioni")
            print("Di seguito il contenuto completo della risposta: ")
            try:
                print(estrazione.content.decode())
            except:
                print(estrazione.content)
                
#############################
####  USCITA DAL PROGRAMMA ##
#############################
    else:
        print("Ciao " + CALLING_USER + ", è stato un piacere fare affari con te ;)")
        termina()

# Chiedo se si ha intenzione di continuare
    risposta = input("Vuoi fare altre operazioni su ANPR [S = sì / N = no]? ")
    while risposta not in ["S", "sì", "s", "Sì", "N", "no", "NO", "n"]:
        risposta = input("Non ho capito. Vuoi fare altre operazioni su ANPR "\
                         "[S = sì / N = no]? ")
    if risposta in ["N", "no", "NO", "n"]:
        CONTINUARE = False

# Quando è tutto finito, termina
termina()
