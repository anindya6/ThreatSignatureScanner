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
int search(char *s, char *a)
{
	int i,j;
	int ls=strlen(s);
	printf("Search contents: %s\nSearch virus: %s\n",s,a);
	j=0;
	for(i=0;i<ls;i++)
	{
		if (a[j]=='\n')
			return 1;
		else if(s[i]==a[j])
		{
			if(j==3)
				return 1;
			j++;
		}
		else if(s[i]=='\n'||s[i]!=a[j])
			j=0;
	}
	printf("I print this if nothing was found\n");
	return 0;
}
int linebyline(char *s)
{
	FILE* fp;
	char buffer[10];
	fp = fopen("threatdata.txt", "r");
	int v;
	while(fgets(buffer, 10, fp)) 
	{
		v=search(s,buffer);
		if(v==1)
			return 1;
	}
	fclose(fp);
	return 0;
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
	seccomp_load(ctx);
	int clientSocket, portNum, nBytes;
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT2);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  
	addr_size = sizeof serverAddr;
	char buff[20];
	int rcvd;
	char rbuf[6];
	int i;
	while(1){
		sendto(clientSocket,"Ack",4,0,(struct sockaddr *)&serverAddr,addr_size);
		rcvd=recvfrom(clientSocket,rbuf,4,MSG_DONTWAIT,NULL,NULL);
		if(rcvd>0)
			break;
	}	
	while(1)
	{
		char filecontent[1000];
		nBytes = recvfrom(clientSocket,filecontent,1000,0,NULL, NULL);
		int v=linebyline(filecontent);
		char stat[12];
		if(v==1)
			strcpy(stat,"Infected");
		else
			strcpy(stat,"Clean");
		nBytes = strlen(stat) + 1;
   		printf("What Im sending : %s\n",stat);
		sendto(clientSocket,stat,nBytes,0,(struct sockaddr *)&serverAddr,addr_size);
	}
	return 0;
}
