#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

uint16_t my_ntohs(uint16_t n){
	return ((n & 0xFF00)>>8)|((n & 0x00FF)<<8);
}

void print_len(const u_char* s, int len){
	for(int i=0; i<len; i++)
	    printf("%d ", s[i]);
}

void packet_analysis(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
  	int ether_len = 14, ip_len, tcp_len, total_len, data_len;
 	char type_TCP;
  	uint16_t* test;

	printf("\ndest mac : ");
	print_len(packet,6);
	printf("\nsource mac : ");
	print_len(packet+6,6);
  	uint16_t type_IP = my_ntohs((uint16_t)(packet[12]));
	if(type_IP == 0x800){
	    printf("\nsource ip : ");
	    print_len(packet+ether_len+12,4);
	    printf("\ndest ip : ");
	    print_len(packet+ether_len+16,4);
	    ip_len = (packet[ether_len]&15)*4;
	    printf("\nIP header length = %d ",ip_len);
	    type_TCP = packet[ether_len+9];
	    test = (uint16_t*)(packet+2+ether_len);
	    total_len = my_ntohs(*test);
	    if(type_TCP == 6){
	   	uint16_t src_port, dest_port;
	   	test = (uint16_t*)(packet+ether_len+ip_len);
	     	src_port = my_ntohs(*test);
	      	test = (uint16_t*)(packet+ether_len+ip_len+2);
	     	dest_port = my_ntohs(*test);
	      	printf("\nsource port : %d\ndest port : %d", src_port, dest_port);
	     	tcp_len = (packet[ether_len+ip_len+12]&0xF0)/16*4;
	     	printf("\ntcp header length = %d\n",tcp_len);
	      	data_len = total_len-ip_len-tcp_len;
	      	if(data_len>0){
	      		printf("data : ");
	      		if(data_len<32){
	      			for(int i=0; i<data_len; i++)
	   					printf("%x ", packet[ether_len+ip_len+tcp_len+i]);
	      		}
	      		else{
	      			for(int i=0; i<32; i++)
	    				printf("%x ", packet[ether_len+ip_len+tcp_len+i]);
	      		}
	      	}

	     } 
	}
	printf("\n");
}
int main(int argc, char* argv[]) {
 	if (argc != 2) {
    	usage();
    	return -1;
  	}
  	char* dev = argv[1];
  	char errbuf[PCAP_ERRBUF_SIZE];

  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
   	 	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    	return -1;
  	}

   	pcap_loop(handle, 0, packet_analysis, NULL);
  	pcap_close(handle);
  	return 0;
}
