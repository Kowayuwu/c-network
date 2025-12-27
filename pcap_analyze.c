#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "network_package_struct.h"
#include "pcap_util.h"

int main()
{
    FILE *file;
    char *file_path = "synflood.pcap";

    file = fopen(file_path, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file: %s", file_path);
        exit(1);
    }

    pcap_file_header_t pcap_f_hdr;
    fread(&pcap_f_hdr, sizeof(pcap_f_hdr), 1, file);
    printf("pcap file magic number: %x\n", pcap_f_hdr.magic_number);

    bool pcap_header_need_swap_byte = false;
    bool pcap_packet_time_in_nanosec = false;
    bool pcap_packet_time_in_microsec = false;
    // check if the endianess of pcap headers is the same between the host that reads and the one that wrote the file
    // and also get the unit of the second time stamp in the pcap packet header
    switch (pcap_f_hdr.magic_number)
    {
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

    if (pcap_header_need_swap_byte)
    {
        // swap bytes of the fields in the file header, packet header's will be swapped when we go through each packet
        pcap_file_header_swap_endian(&pcap_f_hdr);
    }

    printf("Link layer type number: %d (0 indicates loopback interface, aka localhost)\n", pcap_f_hdr.link_layer_type_and_optionals);
    printf("Processing pcap with major version %d, minor version %d\n", pcap_f_hdr.major_version, pcap_f_hdr.minor_version);
    printf("Are we swapping pcap headers byte orders: %s\n", pcap_header_need_swap_byte ? "Yes" : "No");
    printf("pcap packet time_in_detail is in unit: %s\n", pcap_packet_time_in_microsec ? "Micro-second" : "Nano-second");

    int packet_count = 0;
    const int PCAP_PACKET_HEADER_SIZE = 16;
    // start reading packets
    while (true)
    {
        pcap_packet_header_t pcap_p_hdr;
        size_t read_amount = fread(&pcap_p_hdr, PCAP_PACKET_HEADER_SIZE, 1, file);

        if (read_amount != 1)
        {
            if (feof(file))
                break;
            fprintf(stderr, "Error reading packet header\n");
            fclose(file);
            return 1;
        }

        packet_count += 1;

        if (pcap_header_need_swap_byte)
        {
            pcap_packet_header_swap_endian(&pcap_p_hdr);
        }

        // printf("packet captured data length: %d bytes\n", pcap_p_hdr.captured_data_length);
        // bool is_data_truncated = (pcap_p_hdr.captured_data_length != pcap_p_hdr.untruncated_data_length);
        // printf("is data truncated?: %s", is_data_truncated ? "true" : "false");
        // break;

        if (pcap_p_hdr.captured_data_length != pcap_p_hdr.untruncated_data_length)
        {
            printf("Found data truncated, stop reading packets\n"); // didn't happen in this file, decide not to handle it in this project
            break;
        }
        // printf("%d\n", pcap_p_hdr.captured_data_length);
        fseek(file, (long)pcap_p_hdr.captured_data_length, SEEK_CUR);
    }
    printf("%d amount of packets read", packet_count);

    fclose(file);
    return 0;
}