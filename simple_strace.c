/* Program illustrating how the ptrace system call can be used to intercept and 
 * inspect system calls made by a process. 
 *
 * Author: Naga Kandasamy
 * Date created: February 20, 2020
 *
 * Compile as follows: gcc -o simple_strace simple_strace.c -std=99 -Wall 
 * Execute as follows: ./simple_strace ./program-name 
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
        /* Wait for the tracee to begin the next system call */
        ptrace (PTRACE_SYSCALL, pid, 0, 0);
        waitpid (pid, 0, 0);

        /* When wait() returns, the registers for the process that made the 
         * system call are filled with the system call number and its 
         * arguments. However, the kernel has not yet serviced this system 
         * call. We can now gather the system call information. 
         *
         * On the x86-64 architecture, the following registers hold the 
         * relevant information.
         *
         * rax: system call number. For internal kernel purposes, the system call 
         *      number is stored in orig_rax rather than in rax.
         * rdi, rsi, rdx, r10, r8, r9: Upto six arguments passed via registers (note ordering)
         *
         */
        struct user_regs_struct regs;
        ptrace (PTRACE_GETREGS, pid, 0, &regs);                         /* Read tracee registers into regs */
        long syscall = regs.orig_rax;                                   /* System call number */
        fprintf (stderr, "%ld (%ld, %ld, %ld, %ld, %ld, %ld)",\
                syscall,\
                (long) regs.rdi, (long) regs.rsi, (long) regs.rdx,\
                (long) regs.r10, (long) regs.r8, (long) regs.r9);

        /* Run the system call and stop on exiting the call */
        ptrace (PTRACE_SYSCALL, pid, 0, 0);
        waitpid (pid, 0, 0);

        /* Get the result of the system call */
        if (ptrace (PTRACE_GETREGS, pid, 0, &regs) == -1) {
            if (errno == ESRCH) 
                exit (regs.rdi);                                        /* System call was exit() or similar */
            perror ("ptrace");
            exit (EXIT_FAILURE);
        }

        /* Print result of system call */
        printf (" = %ld\n", (long) regs.rax);
    }

    exit (EXIT_SUCCESS);
}

