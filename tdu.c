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
#define PORTX "3490"

#define BACKLOG 10
#define s_len 4
#define MAXDATASIZE 100
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
int main(int argc, char **argv)
{
	
	scmp_filter_ctx ctx;
	ctx=seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(read),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(close),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(fstat),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(exit_group),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(write),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(sendto),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(recvfrom),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(socket),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(open),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(connect),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(getpid),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(mmap),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(access),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(mprotect),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(munmap),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(stat),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(poll),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(sendmmsg),0);
	seccomp_rule_add(ctx,SCMP_ACT_ALLOW,SCMP_SYS(ioctl),0);
	seccomp_load(ctx);
	int f=open("threatdata.txt",O_WRONLY|O_APPEND);
	int clientSocket1, portNum1, nBytes;
	char buff[20];
	struct sockaddr_in serverAddr1;
	socklen_t addr_size1;
	clientSocket1 = socket(PF_INET, SOCK_DGRAM, 0);
	serverAddr1.sin_family = AF_INET;
	serverAddr1.sin_port = htons(PORT1);
	serverAddr1.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr1.sin_zero, '\0', sizeof serverAddr1.sin_zero);
	addr_size1 = sizeof serverAddr1;
	char filename[30];
	char rbuf[6];
	int rcvd;
	int i;
	while(1){
		sendto(clientSocket1,"Ack",4,0,(struct sockaddr *)&serverAddr1,addr_size1);
		rcvd=recvfrom(clientSocket1,rbuf,4,MSG_DONTWAIT,NULL,NULL);
		if(rcvd>0)
			break;
	}
	nBytes = recvfrom(clientSocket1,buff,20,0,NULL,NULL);//start service
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	int file_size;
	FILE *received_file;
	int remain_data = 0;
	ssize_t len;

	if (argc != 2) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORTX, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo);
	
	if (send(sockfd, "getsize1", 13, 0) == -1)
        perror("send");

	if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) 
	{
		perror("recv");
		exit(1);
	}
	printf("received threat signature :'%s'\n",buf);
	int leng=strlen(buf);
	buf[leng++]='\n';
	write(f,buf,leng);
	close(f);
	sendto(clientSocket1,"Done",5,0,(struct sockaddr *)&serverAddr1,addr_size1);
	close(clientSocket1);
	close(sockfd);
	return 0;
}
