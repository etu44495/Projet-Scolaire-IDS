#include "populate2.h"
#include <syslog.h>
#include <stdlib.h>

#define MAXLINE 100
#define NB_RULES 5

struct options
{
	char *msg;
	char *content;

} typedef Options;

struct ids_rule
{
	int action;
	int protocol;
	char *name_protocol;
	char source_ip[IP_ADDR_LEN_STR];
	int source_port;
	char destination_ip[IP_ADDR_LEN_STR];
	int destination_port;
	Options options;
	
} typedef Rule;

Rule rules_ds[NB_RULES];

void rules_matcher(Rule rules_ds[NB_RULES], ETHER_Frame *frame)
{
	char *check_payload;
	for(int i=0; i<NB_RULES; i++)
	{
		check_payload = "x";
		switch(frame->data.protocol)
		{
			
			case 6:
				if (rules_ds[i].options.content != NULL)
				{
					check_payload = strstr((char*)frame->data.data_tcp.data, rules_ds[i].options.content);
				}

				if (strcmp(rules_ds[i].source_ip, "any") == 0)
				{
						strcpy(rules_ds[i].source_ip, frame->data.source_ip);
				}

				if (rules_ds[i].source_port == -1 )
				{
					if ((strcmp(rules_ds[i].name_protocol, "http") == 0) & (frame->data.data_tcp.destination_port != 80))
					{
						rules_ds[i].source_port = 80;
					}
					else if ((strcmp(rules_ds[i].name_protocol, "ftp") == 0) & (frame->data.data_tcp.destination_port != 21))	
					{
						rules_ds[i].source_port = 21;
					}
					else
					{
						rules_ds[i].source_port = frame->data.data_tcp.source_port;
					}
				}

				if (strcmp(rules_ds[i].destination_ip, "any") == 0)
				{
					strcpy(rules_ds[i].destination_ip, frame->data.destination_ip);
				}

				if (rules_ds[i].destination_port == -1)
				{
					if ((strcmp(rules_ds[i].name_protocol, "http") == 0) & (frame->data.data_tcp.source_port != 80))
					{
						rules_ds[i].destination_port = 80;
					}
					else if ((strcmp(rules_ds[i].name_protocol, "ftp") == 0) & (frame->data.data_tcp.source_port != 21))
					{
						rules_ds[i].destination_port = 21;
					}
					else
					{
						rules_ds[i].destination_port = frame->data.data_tcp.destination_port;
					}
				}	

				if((rules_ds[i].protocol == frame->data.protocol) && (strcmp(rules_ds[i].source_ip, frame->data.source_ip) == 0) && 
			   	(rules_ds[i].source_port == frame->data.data_tcp.source_port) && (strcmp(rules_ds[i].destination_ip, frame->data.destination_ip) == 0) &&
			   	(rules_ds[i].destination_port == frame->data.data_tcp.destination_port) && (check_payload != NULL))
				{
					openlog("ids",LOG_CONS | LOG_PERROR | LOG_PID, LOG_USER);
					syslog(rules_ds[i].action, rules_ds[i].options.msg);
					closelog();
				}
				break;

			case 17:
				if (rules_ds[i].options.content != NULL)
				{
					check_payload = strstr((char*)frame->data.data_udp.data, rules_ds[i].options.content);
				}
				if (strcmp(rules_ds[i].source_ip, "any") == 0)
				{
						strcpy(rules_ds[i].source_ip, frame->data.source_ip);
				}
				if (rules_ds[i].source_port == -1)
				{
					rules_ds[i].source_port = frame->data.data_udp.source_port;
				}
				if (strcmp(rules_ds[i].destination_ip, "any") == 0)
				{
					strcpy(rules_ds[i].destination_ip, frame->data.destination_ip);
				}
				if (rules_ds[i].destination_port == -1)
				{
					rules_ds[i].destination_port = frame->data.data_udp.destination_port;
				}

				if((rules_ds[i].protocol == frame->data.protocol) && (strcmp(rules_ds[i].source_ip, frame->data.source_ip) == 0) && 
			   	(rules_ds[i].source_port == frame->data.data_udp.source_port) && (strcmp(rules_ds[i].destination_ip, frame->data.destination_ip) == 0) &&
			   	(rules_ds[i].destination_port == frame->data.data_udp.destination_port) && (check_payload != NULL))
				{
					openlog("ids",LOG_CONS | LOG_PERROR | LOG_PID, LOG_USER);
					syslog(rules_ds[i].action, rules_ds[i].options.msg);
					closelog();
				}
		}
	}
}


void read_rules(FILE * file, Rule rules_ds[NB_RULES])
{
	char line[MAXLINE];
	char *token;
	char *check_content;

	for(int i=0; i<NB_RULES; i++)
	{

		fgets(line,MAXLINE,file);
		check_content = (strstr(line,"content"));
		token = strtok( line, " ");

		//-----------------------------

		if(strcmp(token,"alert") == 0)
		{
			rules_ds[i].action = 1;
		}
		token = strtok(NULL, " ");

		//-----------------------------
	
		if((strcmp(token, "tcp") == 0) | (strcmp(token, "http") == 0) | (strcmp(token, "ftp") == 0))
		{
			rules_ds[i].protocol = 6;
		}
		else if(strcmp(token, "udp") == 0)
		{
			rules_ds[i].protocol = 17;
		}

		rules_ds[i].name_protocol = (char*)malloc(sizeof(char)*(strlen(token)+1));
		strcpy(rules_ds[i].name_protocol, token);
			
		token = strtok(NULL, " ");
		

		//----------------------------------
	

		strcpy(rules_ds[i].source_ip, token);
		token = strtok(NULL, " ");

		//__________________________________
	
		if(strcmp(token,"any")!=0)
		{
			rules_ds[i].source_port = atoi(token);
		}
		else 
		{
			rules_ds[i].source_port = -1;
		}
		token = strtok(NULL, " ");

		//____________________________________________

	
		token = strtok(NULL, " ");		
	
		//____________________________________________


		strcpy(rules_ds[i].destination_ip, token);
		token = strtok(NULL, " ");

		//______________________________________________
		
		if(strcmp(token,"any")!=0)
		{
			rules_ds[i].destination_port = atoi(token);
		}
		else 
		{
			rules_ds[i].destination_port = -1;
		}
		token = strtok(NULL, "\"");

		//_______________________________________________


		token = strtok(NULL, "\"");
		rules_ds[i].options.msg = (char*)malloc(sizeof(char)*(strlen(token)+1));
		strcpy(rules_ds[i].options.msg, token);
		token = strtok(NULL, "\"");

		//_________________________________________________

		if (check_content != NULL)
		{
			token = strtok(NULL, "\"");
			rules_ds[i].options.content = (char*)malloc(sizeof(char)*(strlen(token)+1));
			strcpy(rules_ds[i].options.content, token);
		}
	}
}

	
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	ETHER_Frame frame;

	FILE *file = fopen((char*)args,"r");
	if(file == NULL)
	{
		fprintf(stderr,"error when opening file\n");
		exit(EXIT_FAILURE);
	}

	read_rules(file, &rules_ds[NB_RULES]);
	populate_packet_ds(header, packet, &frame);

	if (frame.data.protocol == 6)
	{
		print_payload(frame.data.data_tcp.data_length, frame.data.data_tcp.data);
		printf("src :%d - dst : %d\n",frame.data.data_tcp.source_port, frame.data.data_tcp.destination_port);
	}
	else if (frame.data.protocol == 17)
	{
		print_payload(frame.data.data_udp.data_length, frame.data.data_udp.data);
	}

	rules_matcher(&rules_ds[NB_RULES], &frame);

	for(int i=0; i<NB_RULES; i++)
	{
		free(rules_ds[i].name_protocol);
		free(rules_ds[i].options.msg);
		free(rules_ds[i].options.content);
	}
	fclose(file);
}

int main(int argc, char *argv[]) 
{
        char *device = "eth0";
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
	bpf_u_int32 netmask;
	bpf_u_int32 net;
	struct bpf_program compiled_filter;
	int total_packet_count = 10;

	if(pcap_lookupnet(device, &net, &netmask, error_buffer) != 0)
	{
		fprintf(stderr,"%s\n",error_buffer);
		return -1;
	}

        handle = pcap_create(device,error_buffer);
	if(handle==NULL)
	{
		fprintf(stderr,"%s\n",error_buffer);
		return -1;
	}

	if(pcap_set_timeout(handle, 10) != 0)
	{
		fprintf(stderr,"error to set timeout\n");
		return -1;
	}
	
	int val = pcap_activate(handle);
	if(val > 0)
	{
		fprintf(stderr, "warning : %s\n", pcap_geterr(handle));
		return 1;
	}
	else if(val < 0)
	{
		fprintf(stderr,"error : %s\n", pcap_geterr(handle));
		return -1;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) 
	{
		fprintf(stderr, "link-layer header is not supported\n");
		return -1;
	}

	if (pcap_compile(handle, &compiled_filter, "tcp", 0, netmask) != 0)
	{
		fprintf(stderr, "%s\n", pcap_geterr(handle));
		return -1;
	}
	
	if(pcap_setfilter(handle, &compiled_filter) != 0)
	{
		fprintf(stderr, "%s\n", pcap_geterr(handle));
		return -1;
	}


        pcap_loop(handle, total_packet_count, my_packet_handler, (u_char*)argv[1]);
	
	pcap_freecode(&compiled_filter);
	pcap_close(handle);

        return 0;
}
