//compile method:
//gcc MyShell.c -lpthread -lrt -o MyShell


#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stddef.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <netinet/in.h> 
#include <sys/ipc.h>
#include <unistd.h>

#define BACKLOG                     (0) //Now only one active connection is allowed
#define RCV_BUF_LEN                 (256)
#define PROMPT                       "MyShell> "
#define PROMPT_LOGIN           "Login> "
#define PROMPT_PASSWARD   "Passward> "
#define CORRECT_LOGIN         "root"
#define CORRECT_PASSWARD "rootadmin"

#define MY_SHELL_MAX_ARGS     (50)
#define MY_SHELL_MAX_COMMANDS         64

#define MYSHELL_SESSION_SHM        "MYSHELL_SESSION_SHM"

typedef unsigned int   u32; 
typedef signed int     i32;
typedef int MyShellCbFunction(int argc, char** argv);

typedef struct SMyShellSession
{
    FILE *sock_file;
} SMyShellSession;

typedef struct SMyShellCommand
{
    const char       *name;
    const char       *description;
    MyShellCbFunction *callback;
} SMyShellCommand;

enum
{
    OK = 0
};
enum
{
    ERR_FDOPEN = 1,
    ERR_SOCKET,
    ERR_SOCKOPT,
    ERR_BIND,
    ERR_LISTEN,
    ERR_CONNECT,
    ERR_RECV
};

unsigned short telnet_port_stream;
SMyShellSession   *myShellSessPtr;

static SMyShellCommand  MyShellCommand[MY_SHELL_MAX_COMMANDS];
static int              MyShellCommandCount = 0;
void MyShellPrint(const char *fmt, ...);

static void MyShellInitialize(void)
{
    memset(MyShellCommand, 0, sizeof(MyShellCommand));

    MyShellCommandCount = 0;
}

static SMyShellSession *MyShellGetSession(void)
{
    if (myShellSessPtr->sock_file != 0)
    {
        return myShellSessPtr;
    }
    printf("Session get failed\r\n");
    return NULL;
}

static void MyShellSaveSession(FILE *file)
{
    myShellSessPtr->sock_file = file;
    printf("Saved current session\r\n");
    return;
}

static void MyShellFreeSession(void)
{
    myShellSessPtr->sock_file = 0;
    return;
}

static int MyShellDetectCommand(int argc, char **argv)
{
    int  result = 0;
    int  i      = 0;

    if (argc < 1)
    {
        return -1;
    }

    printf("Command : argc = %d\r\n",argc);

    for (i = 0; i < argc; i++)
    {
        if (argv[i] != 0)
        {
            printf("argv[%d] = %s\r\n",i,argv[i]);
        }
    }

    for (i = 0; i < MyShellCommandCount; i++)
    {
        if (strcmp(MyShellCommand[i].name, argv[0]) == 0)
        {
            break;
        }
    }

    if (i >= MyShellCommandCount)
    {
        MyShellPrint("'%s' is not a valid command\r\n",  argv[0]);
        return -1;
    }

    printf("Call user callback\r\n");
    result = MyShellCommand[i].callback(argc, &argv[0]);
    printf("Command completed: result = %d\r\n",result);
    return result;
}

static int MyShellHelp(int argc, char **argv)
{
    SMyShellCommand *ptr;
    int              i = 0;

    (void)argc;
    (void)argv;

    MyShellPrint("%-24s %s\r\n", "Command", "Description");
    MyShellPrint("------------------------------------\r\n");

    for (i = 0; i < MyShellCommandCount; i++)
    {
        ptr = &MyShellCommand[i];
        MyShellPrint("%-24s %s\r\n", ptr->name, ptr->description);
    }

    return 0;
}

static int MyShellQuit(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    return -2;
}

static int MyShellExample(int argc, char **argv)
{
    int c = 0;

    if (argc == 1)
    {
        MyShellPrint("\r\n");
        MyShellPrint("NAME\r\n");
        MyShellPrint("    MyShell Example Command\r\n");
        MyShellPrint("\r\n");
        MyShellPrint("USAGE\r\n");
        MyShellPrint("    %s [option]...\r\n ", argv[0]);
        MyShellPrint("\r\n");
        MyShellPrint("    -c    Prints to the shell.\r\n");
        MyShellPrint("    -s    Prints to the shell.\r\n");
        MyShellPrint("\r\n");
        return -1;
    }
    //必须要初始化这2个值,否则下次进来case不符合
    optind = 1;
    opterr = 0;
    while ((c = getopt(argc, argv, "cs")) != -1)
    {
        switch (c)
        {
            case 'c':
                MyShellPrint("Hello, you enter c\r\n");
                break;

            case 's':
                MyShellPrint("Hello, you enter s\r\n");
                break;

            default:
                break;
        }
    }

    return 0;
}

void MyShellPrint(const char *fmt, ...)
{
    SMyShellSession *session = NULL;
    va_list          args;

    session = MyShellGetSession();

    if (session == NULL)
    {
        return;
    }

    va_start(args, fmt);
    vfprintf(session->sock_file, fmt, args);
    va_end(args);

    fflush(session->sock_file);
}

int MyShellAddCommand(const char *name, const char *description, MyShellCbFunction *callback)
{
    SMyShellCommand *ptr;

    if (name == NULL || description == NULL || callback == NULL)
    {
        return -1;
    }

    if (MyShellCommandCount >= MY_SHELL_MAX_COMMANDS)
    {
        return -2;
    }

    ptr = &MyShellCommand[MyShellCommandCount++];

    ptr->name        = name;
    ptr->description = description;
    ptr->callback    = callback;

    return 0;
}

static int MyShellSendData(int  s, char *buf, int  *len)
{
    int  total     = 0;
    int  bytesleft = *len;
    int  n         = 0;

    while (total < *len)
    {
        n = send(s, buf + total, bytesleft, 0);

        if (n == -1)
        {
            break;
        }

        total     += n;
        bytesleft -= n;
    }

    *len = total;
    return (n == -1) ? (-1) : (0);
}

static void MyShellPrompt(int   fd, char *p)
{
    int len = strlen(p);

    printf("Print prompt\r\n");

    if (-1 == MyShellSendData(fd, p, &len))
    {
        printf("Error while sending prompt\r\n");
    }

    return;
}

static int MyShellGetCmd(int   fd, char *cmd, int   size)
{
    int   count = 0, total = 0;
    int   ready = 0;
    char *err;

    printf("Get command\r\n");

    do
    {
        count = recv(fd, &cmd[total], size - total, 0);
        if (0 == count)
        {
            return 0;
        }

        if (-1 == count)
        {
            printf("%s - recv: %s\r\n",__FUNCTION__, ((err = strerror(errno)) ? (err) : ("")));
            return -1;
        }

        total += count;
        if (total >= size)
        {
            return -1;
        }

        if ('\r' == cmd[total - 1] || '\n' == cmd[total - 1] || '\0' == cmd[total - 1])
        {
            ready = 1;
        }
    }
    while (!ready);

    return total;
}

static i32 MyShellParseCmd(char *buf, u32   buf_size)
{
    int   argc = 0;
    char *argv[MY_SHELL_MAX_ARGS];
    char *sep  = " \t\n\r";// 4种分隔符，满足一种就会被拆分:空格,\t,\n,\r
    char               *lasts;

    argc = 0;
    argv[argc] = strtok_r(buf, sep, &lasts);

    while (argv[argc])
    {
        if (argc < (MY_SHELL_MAX_ARGS - 1))
        {
            argv[++argc] = strtok_r(NULL, sep, &lasts);
        }
        else
        {
            MyShellPrint("Too many arguments given for a command: max=%d\r\n", MY_SHELL_MAX_ARGS - 1);
            break;
        }
    }

    argv[argc] = 0;

    return MyShellDetectCommand(argc, argv);
}

static i32 MyShellCheckLogin(char *buf, u32   buf_size)
{
    if(strncmp(buf, CORRECT_LOGIN, strlen(CORRECT_LOGIN)) == 0)
    {
        return 0;
    }
    else
    {
        printf("input login=%s\r\n", buf);
        return -1;
    }
}

static i32 MyShellCheckPassword(char *buf, u32   buf_size)
{
    if(strncmp(buf, CORRECT_PASSWARD, strlen(CORRECT_PASSWARD)) == 0)
    {
        return 0;
    }
    else
    {
        printf("input password=%s%d\r\n", buf);
        return -1;
    }
}
static void* MyTelnetProcess(void *arg)
{
    int                 sockfd, new_fd;                  // listen on sockfd, new connection on new_fd
    struct sockaddr_in  srv_addr;         // my address information
    struct sockaddr_in  client_addr;      // connector's address information
    socklen_t           sin_size;
    char               *err;
    int                 yes = 1;
    int                 rcv_len;
    char                rcv_buf[RCV_BUF_LEN];
    int                 ret;
    FILE               *sock_file;

    arg = arg;
    printf("%s:IN\r\n", __FUNCTION__);
    bzero(&srv_addr, sizeof(srv_addr));

    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_port        = htons(telnet_port_stream);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("%s - socket: %s\r\n",__FUNCTION__, ((err = strerror(errno)) ? (err) : ("")));
        return (void *)(-ERR_SOCKET);
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        printf("%s - sockopt: %s\r\n",__FUNCTION__, ((err = strerror(errno)) ? (err) : ("")));
        close(sockfd);
        return (void *)(-ERR_SOCKOPT);
    }

    if (bind(sockfd, (struct sockaddr *)&srv_addr, sizeof srv_addr) == -1)
    {
        printf("%s - bind: %s\r\n",__FUNCTION__, ((err = strerror(errno)) ? (err) : ("")));
        close(sockfd);
        return (void *)(-ERR_BIND);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        printf("%s - listen: %s\r\n",__FUNCTION__, ((err = strerror(errno)) ? (err) : ("")));
        close(sockfd);
        return (void *)(-ERR_LISTEN);
    }

    while (1)
    {
        sin_size = sizeof client_addr;

        if ((new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size)) == -1)
        {
            printf("%s - accept: %s\r\n",__FUNCTION__, ((err = strerror(errno)) ? (err) : ("")));
            close(sockfd);
            continue;
        }

        sock_file = fdopen(new_fd, "w");

        if (!sock_file)
        {
            printf("%s - fdopen: %s\r\n",__FUNCTION__, ((err = strerror(errno)) ? (err) : ("")));
            shutdown(new_fd, 0);
            close(new_fd);
            continue;
        }

        MyShellSaveSession(sock_file);

        //check login
        for (;;)
        {
            MyShellPrompt(new_fd, PROMPT_LOGIN);
            rcv_len = MyShellGetCmd(new_fd, rcv_buf, RCV_BUF_LEN - 1);
            if (0 == rcv_len)
            {
                break;
            }
            if (-1 == rcv_len)
            {
                continue;
            }
            rcv_buf[rcv_len] = '\0';
            ret = MyShellCheckLogin(rcv_buf, sizeof(rcv_buf));
            if (0 == ret)
            {
                fprintf(sock_file, "Login Success\r\n");
                fflush(sock_file);
                fflush(stderr);
                fflush(stdout);

	         //check password
	        for (;;)
	        {
	            MyShellPrompt(new_fd, PROMPT_PASSWARD);
	            rcv_len = MyShellGetCmd(new_fd, rcv_buf, RCV_BUF_LEN - 1);
	            if (0 == rcv_len)
	            {
	                break;
	            }
	            if (-1 == rcv_len)
	            {
	                continue;
	            }
	            rcv_buf[rcv_len] = '\0';
	            ret = MyShellCheckPassword(rcv_buf, sizeof(rcv_buf));
	            if (0 == ret)
	            {
	                fprintf(sock_file, "Password Success\r\n");
	                fflush(sock_file);
	                fflush(stderr);
	                fflush(stdout);

		        //真正获取命令
		        for (;;)
		        {
		            MyShellPrompt(new_fd, PROMPT);
		            rcv_len = MyShellGetCmd(new_fd, rcv_buf, RCV_BUF_LEN - 1);
		            if (0 == rcv_len)
		            {
		                break;
		            }
		            if (-1 == rcv_len)
		            {
		                continue;
		            }
		            rcv_buf[rcv_len] = '\0';
		            ret = MyShellParseCmd(rcv_buf, sizeof(rcv_buf));

		            fflush(sock_file);
		            fflush(stderr);
		            fflush(stdout);
		            if (-2 == ret)
		            {
		                fprintf(sock_file, "Terminating session. Bye ...\r\n");
		                break;
		            }
		        }
	                break;
	            }
		     else
		     {
	                continue;
		     }
	        }
		 break;
            }
            else
            {
                continue;
            }
        }

        MyShellFreeSession();

        fclose(sock_file);
        shutdown(new_fd, 0);
        close(new_fd);
    }
    printf("%s:OUT\r\n", __FUNCTION__);
}

static void *CreateAndMapSharedMemory(const char *const name, const size_t size)
{
    void *shmptr = NULL;
    int   shmdes = -1;
    char  shmName[128];

    snprintf(shmName,sizeof(shmName),"%s-%d",name,getuid());
    if ((shmdes = shm_open(shmName, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG)) == -1)
    {
        printf("opening shared memory '%s' failed, errno %d\r\n",shmName,errno);
        goto error_out;
    }

    if (ftruncate(shmdes, size) == -1)
    {
        printf("resizing shared memory '%s' to %zu failed, errno %d\r\n",shmName, size, errno);
        shm_unlink(shmName);
        goto error_out;
    }

    if ((shmptr = mmap(NULL,size,PROT_WRITE | PROT_READ, MAP_SHARED,shmdes,0)) == (void *)(-1))
    {
        printf("mapping shared memory '%s' failed, errno %d\r\n",shmName,errno);
        shm_unlink(shmName);
        goto error_out;
    }

    (void)close(shmdes);
    return shmptr;

error_out:
    if (shmdes >= 0)
    {
        (void)close(shmdes);
    }
    return NULL;
}

int main(void)
{
    pthread_t threadSrv_t;
    u32             port;

    printf("main enter\r\n");

    myShellSessPtr = (SMyShellSession *)CreateAndMapSharedMemory(MYSHELL_SESSION_SHM, sizeof(SMyShellSession));
    if(NULL == myShellSessPtr)
    {
        printf("Unable to open and map shared mem object\r\n");
        return;
    }
    memset(myShellSessPtr, 0, sizeof(SMyShellSession));

    telnet_port_stream = 15007;// 1024~65535
    pthread_create(&threadSrv_t, NULL, MyTelnetProcess, NULL);

    MyShellInitialize();
    MyShellAddCommand("?",    "Print description of commands", MyShellHelp);
    MyShellAddCommand("help", "Print description of commands", MyShellHelp);
    MyShellAddCommand("quit", "Quit shell session", MyShellQuit);
    MyShellAddCommand("example", "Show a example", MyShellExample);

    while(1)
    {
        sleep(5);
    }
    return;
}

