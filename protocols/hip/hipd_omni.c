/* 
 * Source for omni component in hipd 
 * Lingyuan He - 03/2015
 */

#include "hipd/hipd_omni.h"

/* cleanup when receive signal */
void hipd_omni_cleanup(int signo) {

	HIP_INFO("hipd omni: receiving signal %d, terminating\n", signo);
	
	close(hipd_omni_socket);
}

/* update current interface name */
void hipd_omni_update_ifname(void) {

	char *ifname;

	ifname = hipd_omni_get_ifname();
	strcpy(hipd_omni_ifname, ifname);
	HIP_INFO("hipd omni: current interface is %s\n", ifname);
	free(ifname);
}

/* main function of the thread */
void hipd_omni_main(void) {
	struct sockaddr_in serv_addr, cli_addr;
	fd_set rfds, tmp_rfds;
	int status;
	unsigned int addrlen = sizeof(cli_addr);
	char buf[256];
	char result[256];
	struct timeval timeout, timeout_tmp;
		
	HIP_INFO("hipd omni: process init\n");
	
	/* SIGTERM handler */
	if (signal(SIGTERM, hipd_omni_cleanup) == SIG_ERR) {
		HIP_INFO("hipd omni: failed to setup handler for SIGERM\n");
		return;
	}
	
	/* current interface */
	hipd_omni_update_ifname();
	
	/* bind socket at the listening port */
	hipd_omni_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (hipd_omni_socket < 0) {
		HIP_INFO("hipd omni: failed to init socket, %s\n", strerror(errno));
		return;
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(HIPD_OMNI_PORT);
	if (bind(hipd_omni_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		HIP_INFO("hipd omni: failed to bind socket, %s\n", strerror(errno));
		return;
	}
	
	/* fd_set for select() call */
	FD_ZERO(&rfds);
	FD_SET(hipd_omni_socket, &rfds);
	
	/* timeout */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0; 
	
	/* main loop */
	while (1) {
		/* fresh fd_set and timeout */
		tmp_rfds = rfds;
		timeout_tmp = timeout;
		
		/* select on socket */
		if (select(hipd_omni_socket + 1, &tmp_rfds, NULL, NULL, &timeout_tmp) < 0) {
			if (errno == EINTR)
				continue;
			HIP_INFO("hipd omni: failed to select: %s\n", strerror(errno));
			break;
		}
		
		/* we have new input */
		if (FD_ISSET(hipd_omni_socket, &tmp_rfds)) {

			/* receive message */
			if ((status = recvfrom(hipd_omni_socket, buf, 256, 0, (struct sockaddr *) &cli_addr, &addrlen)) < 0) {
				HIP_INFO("hipd omni: failed to recvfrom: %s\n", strerror(errno));
				break;
			}

			buf[4] = '\0';	/* divide the message into two parts */
			
			/* interface preference change */
			if (strcmp(buf, "pref") == 0) {
				/* update current interface */
				hipd_omni_update_ifname();
				HIP_INFO("hipd omni: received preference %s\n", buf + 5);
				/* no need to switch */
				if (strcmp(buf + 5, hipd_omni_ifname) == 0) {
					HIP_INFO("hipd omni: already on %s\n", buf + 5);
					strcpy(result, "0");
				}
				else {
						/* switch interface */
						status = hipd_omni_switch(buf + 5);
						sprintf(result, "%d", status);
				}
			} else {
				HIP_INFO("hipd omni: received unsupported command %s\n", buf);
				strcpy(result, "-1");
			}
			/* feedback */
			if (sendto(hipd_omni_socket, result, strlen(result), 0, (struct sockaddr *) &cli_addr, addrlen) < 0) {
				HIP_INFO("hipd omni: failed to send back result, %s", strerror(errno));
				break;
			}
		}
	}
	
	close(hipd_omni_socket);
	//pthread_cleanup_pop(0);
	return;
}

/* switch to another interface */
int hipd_omni_switch(const char *ifname) {
	char cmd[80];
	char *ip;
	int status = 0;

	/* interface not exist */
	if (hipd_omni_check_ifname(ifname) == 0) {
		HIP_INFO("hipd omni: failed to set new default dev %s, device not found\n", ifname);
		return -1;
	}
	
	/* replace default device */
	sprintf(cmd, "sudo ip route replace default dev %s", ifname);
	status = system(cmd);
	/* failed */
	if (status < 0) {
		HIP_INFO("hipd omni: failed to set new default dev %s, %s\n", ifname, strerror(errno));
		return -1;
	}
	
	/* update default ip */
	ip = hipd_omni_get_gateway();
	
	/* we do it again with proper ip */
	sprintf(cmd, "sudo ip route replace default via %s dev %s", ip, ifname);
	status = system(cmd);
	/* failed */
	if (status < 0) {
		HIP_INFO("hipd omni: failed to set new default gateway %s, %s\n", ip, strerror(errno));
		free(ip);
		return 0;
	}
	
	/* new default device */
	HIP_INFO("hipd omni: new default dev %s with gateway %s\n", ifname, ip);
	strcpy(hipd_omni_ifname, ifname); /* update current device */
	free(ip);
	return 0;
}

/* check if an interface exists */
int hipd_omni_check_ifname(const char *ifname) {
	
	FILE *fp;
	char str[10];

	/* use netstat to grab interface names */
	fp = popen("netstat -i | awk 'NR>=3 { print $1 }'", "r");
	if (fp == NULL) {
		HIP_INFO("hipd omni: cannot execute netstat to check interface name, %s\n", strerror(errno));
		return 0;
	}
	
	/* read all lines and compare */
	while (fscanf(fp, "%s", str) > 0) {
		if (strcmp(str, ifname) == 0) {
			pclose(fp);
			HIP_INFO("hipd omni: found interface %s\n", ifname);
			return 1; /* found */
		}
	}
	
	pclose(fp);
	HIP_INFO("hipd omni: does not found interface %s\n", ifname);
	return 0; /* not found */
}

/* get current gateway/router address */
char* hipd_omni_get_gateway(void) {
	
	char *str = (char *)malloc(sizeof(char) * 50);
	FILE *fp;

	/* one-hop ping on one of google's server */
	fp = popen("ping -c 2 -t 1 74.125.224.48 | awk 'NR==2 { print $2}'", "r");
	if (fscanf(fp, "%s", str) <= 0) {
		/* no result */
		fclose(fp);
		strcpy(str, "0.0.0.0");
		return str; 
	}
	
	/* not ip addr */
	if (!hipd_omni_is_ip_addr(str)) {
		fclose(fp);
		strcpy(str, "0.0.0.0");
		return str; 
	}

	/* return string needs to be deallocated */
	fclose(fp);	
	return str;
}

/* check if a string is ip address */
int hipd_omni_is_ip_addr(const char *addr) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, addr, &(sa.sin_addr));
    return result != 0;
}

/* get current interface name */
char *hipd_omni_get_ifname(void) {

	/* execute one command to get gateway and ifname */
	FILE *fp = popen("route -ne | awk \'NR>2 { print $1, $8 }\'", "r");
	char str[20];
	char *ifname = (char *)malloc(sizeof(char) * 8);
	int found = 0;

	/* read all entries */
	while (fscanf(fp, "%s %s", str, ifname) > 0) {
		/* when ip part is not all 0 */
		if (strcmp(str, "0.0.0.0") == 0) {
			found = 1;
			break;
		}
	}
	
	/* not connected */
	if (found == 0)
		strcpy(ifname, "none");

	fclose(fp);

	/* return string needs to be deallocated */
	return ifname;
}

