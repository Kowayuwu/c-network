#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "network_package_struct.h"
#include "pcap_util.h"

int main(){
    FILE *file;
    char *file_path = "synflood.pcap";

    file = fopen(file_path, "r");
    if(file == NULL){
        fprintf(stderr, "Failed to open file: %s", file_path);
        exit(1);
    }
    
    pcap_file_header_t pcap_f_hdr;
    fread(&pcap_f_hdr, sizeof(pcap_f_hdr),1,file);
    printf("pcap file magic number: %x\n", pcap_f_hdr.magic_number);

    pcap_packet_header_t pcap_p_hdr;
    fread(&pcap_p_hdr, sizeof(pcap_p_hdr),1,file);


    bool pcap_header_need_swap_byte = false;
    bool pcap_packet_time_in_nanosec = false;
    bool pcap_packet_time_in_microsec = false;
    // check if the endianess of pcap headers is the same between the host that reads and the one that wrote the file
    // and also get the unit of the second time stamp in the pcap packet header
    switch (pcap_f_hdr.magic_number){
        case 0xa1b2c3d4:
            pcap_packet_time_in_microsec = true;
            break;
        
        case 0xd4c3b2a1:
            pcap_packet_time_in_microsec = true;
            pcap_header_need_swap_byte = true;
            break;

        case 0xa1b23c4d:
            pcap_packet_time_in_nanosec = true;
            break;
        
        case 0x4d3cb2a1:
            pcap_packet_time_in_microsec = true;
            pcap_header_need_swap_byte = true;
            break;
        
        default:
            break;
        }
    
    if(pcap_header_need_swap_byte){
        printf("swapping pcap headers byte orders");
        // swap byte
    }

    printf("Processing pcap with major version %d, minor version %d\n", pcap_f_hdr.major_version, pcap_f_hdr.minor_version);
    printf("packet captured data length: %d bytes\n", pcap_p_hdr.captured_data_length);
    bool is_data_truncated = (pcap_p_hdr.captured_data_length != pcap_p_hdr.untruncated_data_length);
    printf("is data truncated?: %s", is_data_truncated ? "true": "false");

    fclose(file);
    return 0;
}