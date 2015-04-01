/* 
 * Source for omni component in hipd 
 * Lingyuan He - 03/2015
 */

#include "hipd/hipd_omni.h"

/* cleanup when thread exits */
void hipd_omni_cleanup(void *arg) {

	HIP_DEBUG("hipd omni thread cleanup\n");

	if (arg == NULL) {
		close(hipd_omni_socket);
		return;
	}
	/* deallocate mutex and close socket */
	//pthread_mutex_destroy(&hipd_omni_mutex);
	close(hipd_omni_socket);
	
	//pthread_cleanup_pop(0);
}

/* update current interface name */
void hipd_omni_update_ifname(void) {

	char *ifname;

	ifname = hipd_omni_get_ifname();
	strcpy(hipd_omni_ifname, ifname);
	free(ifname);
}

/* main function of the thread */
void *hipd_omni_main(void *arg) {
	struct sockaddr_in serv_addr, cli_addr;
	fd_set rfds;
	int status;
	unsigned int addrlen = sizeof(cli_addr);
	char buf[256];
	char result[256];
	if (arg != NULL)
		return NULL;
	HIP_DEBUG("hipd omni thread init\n");
	
	/* mutex init */
	//pthread_mutex_init(&hipd_omni_mutex);
	
	pthread_cleanup_push(hipd_omni_cleanup, NULL);
	
	/* current interface */
	hipd_omni_update_ifname();
	
	/* bind socket at the listening port */
	hipd_omni_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (hipd_omni_socket < 0) {
		HIP_DEBUG("hipd omni thread failed to init socket\n");
		return NULL;
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(HIPD_OMNI_PORT);
	if (bind(hipd_omni_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		HIP_DEBUG("hipd omni thread failed to bind socket\n");
		return NULL;
	}
	
	/* fd_set for select() call */
	FD_ZERO(&rfds);
	FD_SET(hipd_omni_socket, &rfds);
	
		/* main loop */
	while (1) {
		if (select(hipd_omni_socket + 1, &rfds, 0, 0, 0) < 0) {
			HIP_DEBUG("hipd omni thread failed to select\n");
			break;
		}
		
		/* cancel point */
		pthread_testcancel();
		
		/* we have new input */
		if (FD_ISSET(hipd_omni_socket, &rfds)) {
			buf[4] = '\0';	/* divide the message into two parts */
			/* interface preference change */
			if (strcmp(buf, "pref") == 0) {
				HIP_DEBUG("hipd omni thread received preference\n");
				if (strcmp(buf + 5, hipd_omni_ifname) == 0) {
					HIP_DEBUG("hipd omni: already on %s\n", buf + 5);
					strcpy(result, "0");
				}
				else {
						/* switch interface */
						status = hipd_omni_switch(buf + 5);
						sprintf(result, "%d", status);
				}
			} else {
				HIP_DEBUG("hipd omni thread received unsupported command %s\n", buf);
				strcpy(result, "-1");
			}
			/* feedback */
			if (sendto(hipd_omni_socket, result, strlen(result), 0, (struct sockaddr *) &cli_addr, addrlen) < 0) {
				HIP_DEBUG("hipd omni: failed to send back result");
			}
		}
	}
	
	pthread_cleanup_pop(0);
	return NULL;
}

/* switch to another interface */
int hipd_omni_switch(const char *ifname) {
	char cmd[100];
	/* current gateway */
	char *current_gw = hipd_omni_get_gateway(hipd_omni_ifname);
	/* new gateway */
	char *new_gw = hipd_omni_get_gateway(ifname);
	int status = 0;
	
	/* not found */
	if (strcmp(new_gw, "0.0.0.0") == 0)
		return -1;
	
	/* drop previous gateway */
	sprintf(cmd, "sudo route delete default gw %s %s", current_gw, hipd_omni_ifname);
	status = system(cmd);
	if (status < 0)
		return -1;
	
	/* use new gateway */
	sprintf(cmd, "sudo route delete default gw %s %s", new_gw, ifname);
	status = system(cmd);
	if (status < 0)
		return -1;
	
	/* free resources */
	free(current_gw);
	free(new_gw);
	
	return 0;
}

/* get gateway/router address by interface name */
char* hipd_omni_get_gateway(const char* ifname) {
	
	char cmd[50];
	char *str = (char *)malloc(sizeof(char) * 16);
	FILE *fp;
	//int status = 0;

	/* get command */
	sprintf(cmd, "arp -n -i %s | awk \'NR==2  { print $1}\'", ifname);

	/* execute route command, extract the correct row and then column, open output as file */
	fp = popen(cmd, "r");
	strcpy(str, "0.0.0.0"); /* 0.0.0.0 for all error or not found condition */
	/* scan from result */
	if (fscanf(fp, "%s", str) <= 0)
		return str;

	fclose(fp);

	/* return string needs to be deallocated */
	return str;
}

/* get current interface name */
char *hipd_omni_get_ifname(void) {

	/* execute one command to get gateway and ifname */
	FILE *fp = popen("route -ne | awk \'NR>2 { print $2, $8 }\'", "r");
	char str[20];
	char *ifname = (char *)malloc(sizeof(char) * 8);
	int found = 0;

	/* read all entries */
	while (fscanf(fp, "%s %s", str, ifname) > 0) {
		printf("-%s-%s-\n", str, ifname);
		/* when ip part is not all 0 */
		if (strcmp(str, "0.0.0.0") != 0) {
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

