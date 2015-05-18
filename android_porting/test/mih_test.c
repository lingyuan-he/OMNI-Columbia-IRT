/* Unified Heterogeneous Networking Middleware
 * Android - MIH Interface Query Test
 * Lingyuan He - 05/2015
 */

#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(void) {

	struct sockaddr_in dest_addr;
	int socketfd;
	int size;
	unsigned int dest_addrlen = sizeof(dest_addr);
	char str[20];
	char in[20];

	socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketfd < 0) {
		perror("Failed to create a socket");
		return 0;
	}
	dest_addr.sin_family = AF_INET;
	if (inet_aton("127.0.0.1", &dest_addr.sin_addr) == 0) {
		perror("Failed to convert address");
		return 0;	
	}
	dest_addr.sin_port = htons(18752);
	
	while (1) {
		printf("Query interface: ");
		strcpy(str, "e ");
		scanf("%s", in);
		strcat(str, in);
		printf("=%s=\n", str);
		if (strcmp(in, "exit") == 0)
			break;
		if (sendto(socketfd, str, strlen(str) + 1, 0, (struct sockaddr *) &dest_addr, dest_addrlen) < 0) {
			perror("Failed to send to mih_usr");
			return 0;
		}
		//printf("=interface %s", );
		memset(in,'\0', 20);
		if (recvfrom(socketfd, in, 20, 0, (struct sockaddr*) &dest_addr, &dest_addrlen) < 0) {
			perror("Failed to receive from mih_usr");
			return 0;
		}
		printf("%s\n", in);
	}
	
	close(socketfd);
	return 0;
}
	
