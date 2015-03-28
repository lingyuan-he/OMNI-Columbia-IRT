/* 
 * Source for omni component in hipd 
 * Lingyuan He - 03/2015
 */

#include "hipd/hipd_omni.h"

/* cleanup when thread exits */
void hipd_omni_cleanup(void *arg) {

	HIP_DEBUG("hipd omni thread cleanup\n");

	/* deallocate mutex and close socket */
	pthread_mutex_destroy(&hipd_omni_mutex);
	close(hipd_omni_socket);
}


/* main function of the thread */
void *hipd_omni_main(void *arg) {
	struct sockaddr_in serv_addr, cli_addr;
	fd_set rfds;
	int len;
	unsigned int addrlen = sizeof(cli_addr);
	char buf[256];
	char result[256];

	//revert 4 lines
	sockaddr_list *l;
	sockaddr_list *l_new = NULL;
	int preferred_iface_index;
	__u32 ip;
	
	HIP_DEBUG("hipd omni thread init\n");
	
	/* mutex init */
	pthread_mutex_init(&hipd_omni_mutex);
	
	/* current interface */
	
	/* socket and address*/
	hipd_omni_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		HIP_DEBUG("hipd omni thread failed to init socket\n");
		return NULL;
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(HIPD_OMNI_PORT);
	if (bind(hipd_omni_socket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
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
		if (FD_ISSET(ipd_omni_socket, &rfds)) {
			if ((len = recvfrom(sockfd, buf, 255, 0, (struct sockaddr *) &cli_addr, &addrlen)) < 6 || buf[4] != ' ') {
				sprintf(result, "Ignore bad message.");
			}
			else {
				buf[4] = '\0';	/* divide the message into two parts */
				/* interface preference change */
				if (strcmp(buf, "pref") == 0) {
					HIP_DEBUG("hipd omni thread received preference\n");
					if (strcmp(buf + 5, hipd_omni_ifname) == 0) {
						HIP_DEBUG("hipd omni: already on %s\n", buf + 5);
						//pthread_mutex_lock(&pref_mutex); 
						//prefer_changed = 1;
						//pthread_mutex_unlock(&pref_mutex);
					}
					else {
						char cmd[1000] = {0};
						int r;
						
						char *gateway; /* Lingyuan - 03/2015 */
						
						//sprintf(cmd, "sudo ip route change default dev %s", buf + 5);
						//sprintf(result, "Interface changed to %s", buf + 5);
						//r = system(cmd);
					
						if (hip_current_ifname[0] != 0) {
						
							//sprintf(cmd, "sudo ip -%d route del table %s %s",
							//	IP_VERSION, hip_preferred_ifname, DEST_ADDR);
							sprintf(cmd, "sudo ip -%d route flush table %s",
								IP_VERSION, hip_preferred_ifname);
							//log_(NORM, "change routing table: %s\n", cmd);
							//r = system(cmd);
						}
	
					}
				} else {
					HIP_DEBUG("hipd omni thread received unsupported command %s\n", buf);
				}
			}
		}
	}


	pthread_cleanup_pop(0);
	return NULL;
}

void hipd_omni_switch
	
void hipd_omni_handoff(sockaddr_list *l)
{
	pthread_mutex_lock(&pref_mutex);
	if (prefer_changed)     //this second prefer_changed is used to avoid multithread conflict
	{
		prefer_changed = 0;

		sockaddr_list *l2;
		for (l2 = my_addr_head; l2; l2=l2->next)
		{
		        l2->preferred=FALSE;
		}

		struct sockaddr *oldaddr;
		struct sockaddr *newaddr;
		hip_assoc *hip_a;
		int i;
		//char cmd[256];

		newaddr=SA(&l->addr);   //l is selected by the 

		//added, change the routing table here
		//sprintf(cmd, "sudo ip route add table %s 128.59.20.0/24 dev %s src %s",
		//      cmd, hip_preferred_ifname, hip_preferred_ifname, logaddr(newaddr))
		//log_(NORM, "route change: %s", cmd);
		//i = system(cmd);

		for (i = 0; i < max_hip_assoc; i++)
		{
		        hip_a = &hip_assoc_table[i];
		        oldaddr = HIPA_SRC(hip_a);
		        if (oldaddr->sa_family == AF_INET) {
		                ((struct sockaddr_in*)newaddr)->sin_port =
					((struct sockaddr_in*)oldaddr)->sin_port;
		        }

			readdress_association(hip_a, newaddr, l->if_index);
		}

		l->preferred = TRUE;
	}
	pthread_mutex_unlock(&pref_mutex);
}




/* get gateway/router address by interface name */
char* hipd_omni_get_gateway(const char* ifname) {
	
	char cmd[50];
	char *str = (char *)malloc(sizeof(char) * 16);
	FILE *fp;

	/* get command */
	sprintf(cmd, "arp -n -i %s | awk \'NR==2  { print $1}\'", ifname);

	/* execute route command, extract the correct row and then column, open output as file */
	fp = popen(cmd, "r");
	strcpy(str, "0.0.0.0"); /* 0.0.0.0 for all error or not found condition */
	fscanf(fp, "%s", str); /* scan from result */

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
		strcpy(ifname, "");

	fclose(fp);

	/* return string needs to be deallocated */
	return ifname;
}

