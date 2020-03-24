/* A simple program that reads from and writes to files. 
 * 
 * Compile as: gcc -o guest_program guest_program.c -std=c99 -Wall 
 * */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_BUFFER_LENGTH 256

int 
main(int argc, char *argv[])
{
    pid_t pid = getpid();
    int fd, count;
    char buf[MAX_BUFFER_LENGTH];
    
    /* Open existing file for reading and write contents to stderr */
    char *file_name_1 = "host_message.txt";
    fd = open(file_name_1, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    count = read(fd, buf, sizeof(buf));
    buf[count] = '\0';
    write(2, buf, count);
    close(fd);

    /* Open new file in current directory for read/write */
    char *file_name_2 = "guest_message.txt";
    fd = open(file_name_2, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    strcpy(buf, "Hello from process");
    sprintf(buf, "%s %d\n", buf, pid);
    write(fd, buf, strlen(buf));
    close(fd);
    
    /* Open new file in /tmp directory for read/write */
    char *file_name_3 = "/tmp/guest_message.txt";
    fd = open(file_name_3, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    strcpy(buf, "Hello from process");
    sprintf(buf, "%s %d\n", buf, pid);
    write(fd, buf, strlen (buf));
    close(fd);
    /* Unlink the file from the /tmp directory */
    unlink(file_name_3);

    exit(EXIT_SUCCESS);
}
