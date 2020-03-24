/* Program illustrating how the ptrace system call can be used to intercept and 
 * inspect system calls made by a process. 
 *
 * Name: Dinh Nguyen and Toan Huynh
 * ECEC353
 * Instructor: Naga Kandasamy
 * Date created: February 20, 2020
 *
 * Compile as follows: gcc -o sandbox sandbox.c -std=c99 -Wall 
 * Execute as follows: ./sandbox ./program-name 
 * The tracee program is in the same directory as your simple_strace program.
 *
 */

/* Includes from the C standard library */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/* POSIX includes */
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux includes */
#include <syscall.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

int 
main (int argc, char **argv)
{
    if (argc != 2) {
        printf ("Usage: %s ./program-name\n", argv[0]);
        exit (EXIT_FAILURE);
    }

    /* Extract program name from command-line argument (without the ./) */
    char *program_name = strrchr (argv[1], '/');
    if (program_name != NULL)
        program_name++;
    else
        program_name = argv[1];

    pid_t pid;
    pid = fork ();
    switch (pid) {
        case -1: /* Error */
            perror ("fork");
            exit (EXIT_FAILURE);

        case 0: /* Child code */
            /* Set child up to be traced */
            ptrace (PTRACE_TRACEME, 0, 0, 0);
            printf ("Executing %s in child code\n", program_name);
            execlp (argv[1], program_name, NULL);
            perror ("execlp");
            exit (EXIT_FAILURE);
    }

    /* Parent code. Wait till the child begins execution and is 
     * stopped by the ptrace signal, that is, synchronize with 
     * PTRACE_TRACEME. When wait() returns, the child will be 
     * paused. */
    waitpid (pid, 0, 0); 

    /* Send a SIGKILL signal to the tracee if the tracer exits.  
     * This option is useful to ensure that tracees can never 
     * escape the tracer's control.
     */
    ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    /* Intercept and examine the system calls made by the tracee */
    while (1) {
        /* Wait for tracee to begin next system call */
        ptrace (PTRACE_SYSCALL, pid, 0, 0);
        waitpid (pid, 0, 0);

        /* Read tracee registers prior to syscall entry */
        struct user_regs_struct regs;
        ptrace (PTRACE_GETREGS, pid, 0, &regs);
        /* Check if syscall is allowed */
        int blocked = 0;
        /*rdx = FLAGS, r10 = MODE, 0 = RONLY, r8,r9 current directory, /tmp has r8 = 0*/
        if(regs.orig_rax == 257 && regs.rdx != 0 && regs.r10 != 0 && regs.r8 != 0){
            blocked = 1;
            /* Set to invalid syscall and modify tracee registers */
            regs.orig_rax = -1;
            ptrace (PTRACE_SETREGS, pid, 0, &regs);
        }
        /* Execute system call and stop tracee on exiting call */
        ptrace (PTRACE_SYSCALL, pid, 0, 0);
        waitpid (pid, 0, 0);
        /* Get result of system call in register rax */
        if (ptrace (PTRACE_GETREGS, pid, 0, &regs) == -1) {
            if (errno == ESRCH)
                exit (regs.rdi);
            perror ("ptrace");
            exit (EXIT_FAILURE);
        } 
        /* Set errno to EPERM (operation not permitted) in rax */
        if (blocked) {
            regs.rax = -EPERM; /* Operation not permitted */
            ptrace(PTRACE_SETREGS, pid, 0, &regs);
        }
    }        
}

