/* A simple "hello world" program. 
 * 
 * Compile as: gcc -o hello_world hello_world.c -std=c99 -Wall 
 * */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int 
main (int argc, char *argv[])
{
    pid_t process_id = getpid ();
    printf ("Hello from process %d\n", process_id);
    printf ("Hasta la vista, baby\n");
    exit (EXIT_SUCCESS);
}
