#define _POSIX_SOURCE
#include <linux/futex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#undef __x86_64__ // Visual Studio Code complains here.
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fcntl.h>

// Make GCC happy
#undef EAX
#undef ECX
#undef EDX
#undef EBX
#undef ESP
#undef EBP
#undef ESI
#undef EDI
#undef CS
#undef DS
#undef ES
#undef FS
#undef GS
#undef SS

#include "distorm/distorm.h"
#include "halfix/cpu.h"
#include "halfix/internal/std.h"
#include "halfix/linux/execve.h"
#include "halfix/linux/fs.h"
#include "halfix/linux/mman.h"
#include "halfix/linux/process.h"
#include "halfix/linux/syscall.h"
#include "halfix/linux/util.h"
#include "halfix/mem.h"

char* env[] = { "HOME=/home/", /*"LD_DEBUG=all",*/ "LD_SHOW_AUXV=1", "FOO=bar",
    NULL };

// Information about how to use ptrace (with a fully functional example! It's
// not something you see a lot these days) can be found at
// https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1

// This is essentially a bastardized version of a debugger. It abuses features
// like breakpoints to get things to work.

// In comments lowercase register names (i.e. ebx, esi, esp) refer to the host
// (because they are accessed using lowercase, i.e. regs.edx). Halfix registers
// are referred to in UPPERCASE (i.e. EAX, ESI, EDI)

/*
0:  31 c0                   xor    eax,eax
2:  31 c9                   xor    ecx,ecx
4:  31 d2                   xor    edx,edx
6:  31 ed                   xor    ebp,ebp
8:  31 f6                   xor    esi,esi
a:  31 ff                   xor    edi,edi
c:  89 e3                   mov    ebx,esp
e:  8b 63 04                mov    esp,DWORD PTR [ebx+0x4]
11: 8b 5b 08                mov    ebx,DWORD PTR [ebx+0x8]
14: ff e3                   jmp    ebx
*/
// TODO: eliminate move to EBX and jump directly from there.
char* shellcode = "\x31\xC0\x31\xC9\x31\xD2\x31\xED\x31\xF6\x31\xFF"
                  "\x89\xE3\x8B\x63\x04\x8B\x5B\x08\xFF\xE3";

static inline int safe_ptrace(int op, int pid, void* a, void* b)
{
    int c = ptrace(op, pid, a, b);
    if (c == -1) {
        printf("%d %d\n", op, pid);
        perror("ptrace");
        exit(1);
    }
    return c;
}

static void memset_child(int pid, unsigned int addr, uint32_t* data,
    unsigned int size)
{
    if (size & 3) {
        fprintf(stderr,
            "TODO: memset_child with a size that is not a multiple of four\n");
        exit(1);
    }
    int dwords = size >> 2;
    for (int i = 0; i < dwords; i++) {
        safe_ptrace(PTRACE_POKETEXT, pid, (void*)(addr + i * 4), (void*)data[i]);
    }
}

// Executes a system call on the guest.
static void
run_syscall_guest(int pid, struct user_regs_struct* new,
    struct user_regs_struct* old)
{
    safe_ptrace(PTRACE_GETREGS, pid, NULL, old);

    new->eip = 0x66666000;
    safe_ptrace(PTRACE_SETREGS, pid, NULL, new);

    // Run INT 80h
    int status = 0;
    safe_ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (!(waitpid(pid, &status, 0) && !WIFEXITED(status))) {
        fprintf(stderr, "Something went terribly wrong in run_syscall_guest\n");
        exit(1);
    }

    // Restore our registers after a job well done.
    safe_ptrace(PTRACE_SETREGS, pid, NULL, old);
}

#if 0
static void memget_child(int pid, unsigned int addr, unsigned int size){
    uint32_t* region = malloc(size);
    int dwords = size >> 2;
    for(int i=0;i<dwords;i++){
        region[i] = safe_ptrace(PTRACE_PEEKTEXT, pid, )
    }
}
#endif

static inline void disassembleinsns(cpu_t* cpu, uint32_t eip)
{
    void* area = read_str_copy(cpu->cr3_read, eip, 16);
    char string[1000];
    unsigned int dsize;
    int res;
    _DecodedInst decodedInstructions[1];
#define WVAL(n) decodedInstructions[0].n.p
    res = (int)distorm_decode(eip, // codeOffset
        area, // code
        16, // codeLen
        Decode32Bits, // decoding mode
        decodedInstructions, // result
        1, // max insn
        &dsize);

    if (res != DECRES_INPUTERR) {
        sprintf(string, "Instruction #%d @ %08x: %-24s %s %s", cpu->insn_count, eip,
            WVAL(instructionHex), WVAL(mnemonic), WVAL(operands));
    }
    puts(string);
    free(area);
}

process_t* current_process;

int main(int argc, char** argv)
{
    int start;
    process_t* process = parse_args(argc, argv, &start);
    setup_default_cleanup_hooks();

    process->cpu = cpu_create();
    __set_current_cpu(process->cpu);

    current_process = process;
    init_cpu_state();
#if 0
    FILE *program = halfix_fopen(argv[1], "rb");
    if (!program)
    {
        perror("open program");
        exit(1);
    }
#endif
    char** args = &argv[start];
    process->program_brk = simplified_native_execve(process->cpu, args[0], args, env);

    // Some process initialization
    for (int i = 3; i < MAX_FILE_DESCRIPTORS; i++) {
        process->fds[i].avail = 1;
    }
    INIT_FD(process->fds[0], 0, 0, 0);
    INIT_FD(process->fds[1], 1, 1, 0);
    INIT_FD(process->fds[2], 2, 2, 0);

    // Now we create a new process.
    int pid = fork();

    if (pid == 0) {
        safe_ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        // In here, we must do the following:
        //  - Get ready for the parent to ptrace us
        //  - Turn Halfix memory maps into host ones
        //  - Destroy the Halfix CPU
        //  - Give control over to the emulated process

        // First, we have to do this really ugly kludge that allows us to execute
        // arbitrary system calls in the guest.
        unsigned char* evil = (unsigned char*)0x66666000;
        mmap((void*)evil, 4096, PROT_WRITE | PROT_READ,
            MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
        evil[0] = 0xCD; // INT 80h
        evil[1] = 0x80;
        mprotect(evil, 4096, PROT_READ | PROT_EXEC);
        printf("Allocated in the bytes %02x at %p\n", evil[0], evil);
        // Now let's add a data area so that we can "fix" system calls
        unsigned char* evil2 = (unsigned char*)0x66667000;
        mmap((void*)evil2, 4096 * 2, PROT_WRITE | PROT_READ,
            MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);

        // Memory map in the stack area
        mmap((void*)(MMAP_BASE - STACK_SIZE), STACK_SIZE, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);

        for (int i = 0; i < 1024; i++) {
            void** table = process->cpu->cr3_master[i];
            if (table) {
                for (int j = 0; j < 1024; j++) {
                    size_t host_addr = i << 22 | j << 12;
                    void* ptr = table[j];
                    if (ptr < (void*)0x1000) {
                        continue;
                    }

                    if (host_addr >= (MMAP_BASE - STACK_SIZE) && host_addr < MMAP_BASE) {
                        // This is a stack area; simply copy it
                        memcpy((void*)host_addr, ptr, 4096);
#if 0
                        char xa[1000];
                        sprintf(xa, "dumps/0x%08x-0x%08x [stack %d kb].out", host_addr, host_addr + 0x1000, 4);
                        int x = open(xa, O_CREAT | O_RDWR, 0666);
                        write(x, host_addr, 4096);
                        close(x);
#endif
                    } else {
                        void* p = mmap((void*)host_addr, 4096, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
                        if (p != (void*)host_addr) {
                            perror("mmap failed");
                            exit(1);
                        }
                        memcpy(p, ptr, 4096);

#if 0
                        char xa[1000];
                        sprintf(xa, "dumps/0x%08x-0x%08x [%d kb].out", host_addr, host_addr + 0x1000, 4);
                        int x = open(xa, O_CREAT | O_RDWR, 0666);
                        write(x, p, 4096);
                        close(x);
#endif

                        mprotect(p, 4096, cpu_get_page_prot(process->cpu, host_addr));
                    }
                }
            }
        }

        // Hackish, yes, but this will have to do.
        void (*ret)(uint32_t, uint32_t) = (void (*)(uint32_t, uint32_t))shellcode;

        //brk((void *)process->program_brk);

        unsigned int esp = process->ESP;
        unsigned int eip = process->cpu->eip;

        cpu_destroy(process->cpu);
        destroy_cpu_state();
        free(process);

        raise(SIGTRAP);

        ret(esp, eip);
        exit(1);
    } else {
        // It seems that after each PTRACE SINGLESTEP there needs to be waitpid
        // call.
        printf("Child pid: %d\n", pid);
        struct user_regs_struct regs;
        struct user_fpxregs_struct fpregs;
        memset(fpregs.xmm_space, 0, 32 * 4);
        int status = 0;
        while (1) {
            if (!(waitpid(pid, &status, 0) && !WIFEXITED(status)))
                break;
            safe_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if ((unsigned)regs.eip == process->cpu->eip)
                break;
            safe_ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        }
        safe_ptrace(PTRACE_SETFPXREGS, pid, 0, &fpregs);
        safe_ptrace(PTRACE_GETFPXREGS, pid, 0, &fpregs);
        safe_ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        cpu_t* cpu = process->cpu; // Save typing time
        EBX = cpu->eip; // Because we jump from ebx.

        uint32_t prev_ebx; // For mmap purposes
        uint32_t prev_brk = process->program_brk; // kludgy brk
        while (1) {
            // Here are the steps we must follow:
            //  1. Cycle emulated CPU
            //  2. Check for certain CPU state (i.e. if the instruction was RDTSC, INT
            //     80h, etc.), and change CPU state accordingly
            //  3. Cycle real CPU
            //  4. Get native registers
            //  5. If necessary, patch return values (for example, RDTSC)
            //  6. Compare

            uint32_t prev_eip = cpu->eip;
            uint16_t pword = read_word(cpu->cr3_exec, prev_eip);
            uint32_t prev_eax = EAX; // For system call purposes
            // Step one.

            execute_code(cpu);

#define SETREGS safe_ptrace(PTRACE_SETREGS, pid, NULL, &regs)
            switch (pword) {
            case 0x80CD:
                switch (prev_eax) {
                case 45:
                    if (prev_brk != process->program_brk) {
                        prev_ebx = prev_brk;
                        prev_brk = process->program_brk;
                    } else
                        prev_ebx = 0;
                    break;
                case 192:
                    // mmap.
                    // We need to control the base address.
                    // So set host ebx to the address (EAX)
                    // Hopefully it hasn't been used yet.
                    prev_ebx = regs.ebx;
                    if (regs.ebx == 0 && !DETECT_MMAP_FAIL(EAX)) {
                        regs.ebx = EAX;
                    }
                    SETREGS;
                    break;
                }
                break;
            }

            // Steps three AND four
            uint32_t host_cur_eip = regs.eip;

            do {
                // Note that ptrace treats each rendition of REPZ [insn] as a single
                // one, so repeat the same instruction until we finally get a different
                // eip/
                safe_ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                if (!(waitpid(pid, &status, 0) && !WIFEXITED(status))) // Need this here, apparently
                    break;
                // Get the registers again.
                safe_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                // if(cpu->insn_count > 545370) {printf("DONES host %08x guest %08x\n",
                // regs.eip, host_cur_eip);dump_cpu_state(cpu);}
                // if(cnt++ > 300) exit(1);
            } while (host_cur_eip == (unsigned)regs.eip);

            // Step four
            safe_ptrace(PTRACE_GETFPXREGS, pid, 0, &fpregs);
            // safe_ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            // Step five
            switch (pword) {
            case 0x310F:
                printf("PATCH RDTSC\n");
                EAX = regs.eax;
                EDX = regs.edx;
                break;
            case 0xA20F:
                // CPUID
                // Some CPUID leaves are non deterministic!
                EAX = regs.eax;
                EBX = regs.ebx;
                ECX = regs.ecx;
                EDX = regs.edx;
                break;
            case 0x80CD:
                // printf("DWORD AT : bff7fd8C is %08x\n",
                //       read_dword(cpu->cr3_read, 0xbff7fd8C));

                // The vast majority of system calls need no patching! Just these pesky
                // ones.
                switch (prev_eax) {
                case 5: // open
                {
                    if (SYSCALL_DETECT_FAIL(EAX))
                        break;
                    // First, duplicate the file descriptor.
                    int old_fd = process->fds[EAX].host_fd;
                    // And close it
                    process->fds[EAX].avail = 1;
                    // Move it to the right one
                    process->fds[regs.eax].host_fd = old_fd;
                    process->fds[regs.eax].avail = 0;
                    // Get the right one.
                    printf("Moved file descriptor %d to %d <host: %d>\n", EAX, (int)regs.eax, old_fd);
                    EAX = regs.eax;
                    break;
                }
                case 20:
                case 64:
                    // getpid
                    // getppid
                    regs.eax = EAX;
                    SETREGS;
                    break;
                case 45:
                    // brk
                    regs.eax = EAX; // Set it to OUR break
                    SETREGS;
                    if (prev_ebx != 0) {
                        // WARNING: THIS IS THE MOST AWFUL HACK I HAVE EVER SEEN IN MY LIFE.
                        if (EAX < prev_ebx) {
                            fprintf(stderr, "what the fuck\n");
                            exit(1);
                        }
                        struct user_regs_struct mmap_regs;
                        memset(&mmap_regs, 0, sizeof(struct user_regs_struct));
                        safe_ptrace(PTRACE_GETREGS, pid, NULL, &mmap_regs); // Fill it in
                        // with initial
                        // values (i.e.
                        // cs, ds, et.c)
                        mmap_regs.eax = 192; // MMAP
                        mmap_regs.ebx = prev_ebx; // addr
                        mmap_regs.ecx = EAX - prev_ebx; // length
                        mmap_regs.edx = PROT_READ | PROT_WRITE;
                        mmap_regs.esi = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE;
                        mmap_regs.edi = -1;
                        mmap_regs.ebp = 0;
                        run_syscall_guest(pid, &mmap_regs, &regs);
                    }
                    break;
                case 122:
                    // uname
                    {
                        printf("Uname address %08x\n", EBX);
                        void* data = read_str_copy(cpu->cr3_read, EBX, 292);
                        memset_child(pid, EBX, data, 292);
                        break;
                    }
                    break;
                case 192:
                    regs.ebx = prev_ebx;
                    SETREGS;
                    printf("%08x\n", (uint32_t)regs.eax);
                    printf("%s\n", strerror(-regs.eax));
                    break;
                }
            }

//disassembleinsns(cpu, prev_eip);
// Step six
#define rcompare(a, b)                                                                                          \
    if (a != (unsigned int)b) {                                                                                 \
        fprintf(stderr, "Mismatch between " #a " and " #b " at %08x!!\n" #a " = %08x, " #b " = %08x\n\n\n\n\n", \
            cpu->eip, a, (unsigned int)b);                                                                      \
        dump_cpu_state(cpu);                                                                                    \
        disassembleinsns(cpu, prev_eip);                                                                        \
        goto KILL;                                                                                              \
    }
            rcompare(EAX, regs.eax);
            rcompare(ECX, regs.ecx);
            rcompare(EDX, regs.edx);
            rcompare(EBX, regs.ebx);
            rcompare(ESP, regs.esp);
            rcompare(EBP, regs.ebp);
            rcompare(ESI, regs.esi);
            rcompare(EDI, regs.edi);

            rcompare(cpu->eip, regs.eip);

            for (int i = 0; i < 32; i++) {
                if ((unsigned int)fpregs.xmm_space[i] != cpu->xmm[i >> 2].dwords[i & 3]) {
                    dump_cpu_state(cpu);
                    int xmmn = i >> 2;
                    int xmmb = i & ~3;
                    printf("XMM%d mismatch!!\n", xmmn);
                    disassembleinsns(cpu, prev_eip);
                    printf("HOST : %08x%08x%08x%08x\n", (unsigned int)fpregs.xmm_space[xmmb],
                        (unsigned int)fpregs.xmm_space[xmmb + 1], (unsigned int)fpregs.xmm_space[xmmb + 2],
                        (unsigned int)fpregs.xmm_space[xmmb + 3]);
                    printf("GUEST: %08x%08x%08x%08x\n", (unsigned int)cpu->xmm[xmmn].dwords[0],
                        (unsigned int)cpu->xmm[xmmn].dwords[1], (unsigned int)cpu->xmm[xmmn].dwords[2],
                        (unsigned int)cpu->xmm[xmmn].dwords[3]);
                    exit(1);
                }
            }

            // printf("insn is done\n");
        }
    KILL:
        kill(pid, SIGKILL); // INFANTICIDE (just kidding)
    }
    exit(1);
}

/*
// Some stupid functions
void hlt_handler(cpu_t *cpu)
{
    printf("HLT!\n");
    dump_cpu_state(cpu);
}

void segfault_impl(uint32_t addr, uint32_t why)
{
    printf("Segmentation FAULT!!! at %x, error code %x\n", addr, why);
    exit(1);
}

void interrupt_impl(cpu_t *cpu, int32_t vector)
{
    if (vector != 0x80)
    {
        // ERROR!

        printf("Interrupt implementation todo %x\n", vector);
        dump_cpu_state(cpu);
        exit(1);
    }
    do_system_call(cpu);
}
*/
void interrupt_impl(cpu_t* cpu, int32_t vector)
{
    if (vector != 0x80) {
        printf("Unknown interrupt vector: %02x\n", vector);
        abort();
    }
    halfix_syscall(cpu);
}
void hlt_handler(cpu_t* cpu)
{
    dump_cpu_state(cpu);
    printf("Error: hlt!\n");
    abort();
}
void segfault(cpu_t* cpu, uint32_t addr, int why)
{
    dump_cpu_state(cpu);
    printf("Error: segmentation fault at %08x! (Reason: %d)\n", addr, why);
    abort();
}
void syscall_log(char* output)
{
    printf("[\33[32mSYSCALL\33[0m] %s\n", output);
}