#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include<fcntl.h>
#include<seccomp.h>

#define PORT1 3690
#define PORT2 4450
#define PORT3 5560
#define PORT4 7891

#define BACKLOG 10
#define s_len 4

static uid_t euid, ruid;
void
do_setuid (void)
{
  int status;
#ifdef _POSIX_SAVED_IDS
  status = seteuid (euid);
#else
  status = setreuid (ruid, euid);
#endif
  if (status < 0) {
    fprintf (stderr, "Couldn't set uid.\n");
    exit (status);
    }
}

void
undo_setuid (void)
{
  int status;
#ifdef _POSIX_SAVED_IDS
  status = seteuid (ruid);
#else
  status = setreuid (euid, ruid);
#endif
  if (status < 0) {
    fprintf (stderr, "Couldn't set uid.\n");
    exit (status);
    }
}

int main()
{
	scmp_filter_ctx ctx;
	ctx=seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(read),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(close),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(fstat),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit_group),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(write),1,SCMP_A0(SCMP_CMP_EQ,STDOUT_FILENO));
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(sendto),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(recvfrom),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(socket),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(open),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(getuid),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(geteuid),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(setresuid),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(setreuid),0);
	seccomp_load(ctx);
	ruid = getuid ();
	euid = geteuid ();
	undo_setuid ();
	int clientSocket, portNum, nBytes;
	char buff[20];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT3);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	addr_size = sizeof serverAddr;
	char filename[30];
	char rbuf[6];
	int rcvd;
	int i;
	while(1){
		sendto(clientSocket,"Ack",4,0,(struct sockaddr *)&serverAddr,addr_size);
		rcvd=recvfrom(clientSocket,rbuf,4,MSG_DONTWAIT,NULL,NULL);
		if(rcvd>0)
			break;
	}
	char s[1000];
	int flagx;
	int f;
	while(1)
	{
		flagx=0;
		nBytes = recvfrom(clientSocket,filename,30,0,NULL, NULL);
		printf("%s\n",filename);
		f=open(filename,O_RDONLY);
		if (f<0)
		{
			do_setuid();
			f=open(filename,O_RDONLY);
			flagx=1;
		}
		ssize_t nrd;
		memset(s,0,strlen(s));
		nrd=read(f,s,1000);
		close(f);
		if(flagx=1)
			undo_setuid();
		nBytes = strlen(s) + 1;
    		printf("The number of bytes: %d and the string: %s\n",nBytes,s);
		sendto(clientSocket,s,nBytes,0,(struct sockaddr *)&serverAddr,addr_size);
	}
	return 0;
}
