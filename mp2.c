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

int main(int argc, char **argv)
{
	
	scmp_filter_ctx ctx;
	ctx=seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(fstat),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit_group),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(write),1,SCMP_A0(SCMP_CMP_EQ,STDOUT_FILENO));
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(sendto),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(recvfrom),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(socket),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(bind),0);
	seccomp_load(ctx);
	//udpSocket1 for threat update service, udpSocket2 for threat scanner, udpSocket3 for file read service
	int nBytes;
	int udpSocket1;
	struct sockaddr_in serverAddr1;
	struct sockaddr_storage serverStorage1;
	socklen_t addr_size1;
	udpSocket1 = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr1.sin_family = AF_INET;
	serverAddr1.sin_port = htons(PORT1);
	serverAddr1.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr1.sin_zero, '\0', sizeof serverAddr1.sin_zero);  
	int udpSocket2;
	struct sockaddr_in serverAddr2;
	struct sockaddr_storage serverStorage2;
	socklen_t addr_size2;
	udpSocket2 = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr2.sin_family = AF_INET;
	serverAddr2.sin_port = htons(PORT2);
	serverAddr2.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr2.sin_zero, '\0', sizeof serverAddr2.sin_zero);  
	int udpSocket3;
	struct sockaddr_in serverAddr3;
	struct sockaddr_storage serverStorage3;
	socklen_t addr_size3;
	udpSocket3 = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr3.sin_family = AF_INET;
	serverAddr3.sin_port = htons(PORT3);
	serverAddr3.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr3.sin_zero, '\0', sizeof serverAddr3.sin_zero);  
	int fdb,ff;
	char buf[5];
	printf("Waiting for connection from Threat Update Service\n");
	bind(udpSocket1, (struct sockaddr *) &serverAddr1, sizeof(serverAddr1));
	addr_size1 = sizeof serverStorage1;
	nBytes = recvfrom(udpSocket1,buf,4,0,(struct sockaddr *)&serverStorage1, &addr_size1);
	sendto(udpSocket1,"Ack",4,0,(struct sockaddr *)&serverStorage1,addr_size1);
	printf("Threat Update Service Acknowledged! Waiting for Scanner\n");
	bind(udpSocket2, (struct sockaddr *) &serverAddr2, sizeof(serverAddr2));
	addr_size2 = sizeof serverStorage2;
	nBytes = recvfrom(udpSocket2,buf,4,0,(struct sockaddr *)&serverStorage2, &addr_size2);
	sendto(udpSocket2,"Ack",4,0,(struct sockaddr *)&serverStorage2,addr_size2);
	printf("Threat Scanner Acknowledged! Waiting for File Read Service\n");
	bind(udpSocket3, (struct sockaddr *) &serverAddr3, sizeof(serverAddr3));
	addr_size3 = sizeof serverStorage3;
	nBytes = recvfrom(udpSocket3,buf,4,0,(struct sockaddr *)&serverStorage3, &addr_size3);
	sendto(udpSocket3,"Ack",4,0,(struct sockaddr *)&serverStorage3,addr_size3);
	printf("File Read Service Acknowledged! Starting Program.\n");
	sendto(udpSocket1,buf,4,0,(struct sockaddr *)&serverStorage1,addr_size1);
	printf("Threat Update Service Started!\n");
	nBytes = recvfrom(udpSocket1,buf,5,0,(struct sockaddr *)&serverStorage1, &addr_size1);
	printf("Threat Update Complete!\n");
	int len;
	char buffer[1024];
	char status[100];
	int i;
	for (i=1;i<argc;i++)
	{
		printf("Sending file: %s\n",argv[i]);
		len=strlen(argv[i])+1;
		sendto(udpSocket3,argv[i],len,0,(struct sockaddr *)&serverStorage3,addr_size3);
		nBytes = recvfrom(udpSocket3,buffer,1024,0,(struct sockaddr *)&serverStorage3, &addr_size3);
		len=strlen(buffer)+1;
		sendto(udpSocket2,buffer,len,0,(struct sockaddr *)&serverStorage2,addr_size2);
		nBytes = recvfrom(udpSocket2,status,10,0,(struct sockaddr *)&serverStorage2, &addr_size2);
		printf("%s - %s\n",argv[i],status);
	}
}
