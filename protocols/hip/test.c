#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(void) {

	struct sockaddr_in src_addr, dest_addr;
	int socketfd;
	unsigned int addrlen = sizeof(src_addr);
	char str[20];
	char str2[20];
	
	strcpy(str, "pref ");
	socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	src_addr.sin_family = AF_INET;
	src_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	src_addr.sin_port = htons(0);
	bind(socketfd, (struct sockaddr *) &src_addr, sizeof(src_addr));
	
	dest_addr.sin_family = AF_INET;
	inet_aton("127.0.0.1", &dest_addr.sin_addr);
	dest_addr.sin_port = htons(7776);
	
	while (1) {
		strcpy(str, "pref ");
		scanf("%s", str2);
		strcat(str, str2);
		if (strcmp(str, "exit") == 0)
			break;
		sendto(socketfd, str, strlen(str) + 1, 0, (struct sockaddr *) &dest_addr, addrlen);
		printf("%d =%s=\n", (int) strlen(str), str);
	}
	
	close(socketfd);
	return 0;
}
	
