#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// for importing ntoh functions, I know I wrote my own byte swapping function but hey using this is cool as well
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "network_package_struct.h"
#include "pcap_util.h"

/*
Structure of the pcap file:

pcap file header
 [
    pcap packet header (tells us how long the packet is)
    link layer header (tells us the ip version, for this project we use the loopback interface https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html)
    IP header (BIG ENDIAN!)
    TCP header (BIG ENDIAN!)
    payload
 ]

*/

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
    /* check if the endianess of pcap headers is the same between this host and the one that wrote the file,
    additionly, get the unit of the detailed time stamp in the pcap packet header */
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
        // swap bytes of the fields in the pcap file header, swapping pcap packet headers will be done when we go through each packet
        pcap_file_header_swap_endian(&pcap_f_hdr);
    }

    printf("Link layer type number: %d (0 indicates loopback interface, aka localhost)\n", pcap_f_hdr.link_layer_type_and_optionals);
    printf("Processing pcap with major version %d, minor version %d\n", pcap_f_hdr.major_version, pcap_f_hdr.minor_version);
    printf("Are we swapping pcap headers byte orders: %s\n", pcap_header_need_swap_byte ? "Yes" : "No");
    printf("pcap packet time_in_detail is in unit: %s\n", pcap_packet_time_in_microsec ? "Micro-second" : "Nano-second");

    int packet_count = 0;
    int SYN_initiated_count = 0;
    int ACK_count = 0;

    // size of headers
    const int PCAP_PACKET_HEADER_SIZE = 16;
    const int LOOPBACK_INTERFACE_LINK_LAYER_HEADER_SIZE = 4;
    const int IPV4_HEADER_MIN_SIZE = 20;
    const int TCP_HEADER_MIN_SIZE = 20;

    // read packets till end of file
    while (true)
    {
        pcap_packet_header_t pcap_p_hdr;
        size_t read_amount = fread(&pcap_p_hdr, PCAP_PACKET_HEADER_SIZE, 1, file);

        // break if we reached end of file
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
            printf("Found data truncated, stop reading packets\n"); // data truncate didn't happen in this file, decide not to handle it in this project
            break;
        }
        uint32_t remaining_packet_data_length = pcap_p_hdr.captured_data_length;

        // read link layer header and determine protocal type (should all be ipv4 for this project)
        loopback_interface_link_layer_header_t link_layer_header;
        fread(&link_layer_header, LOOPBACK_INTERFACE_LINK_LAYER_HEADER_SIZE, 1, file);
        remaining_packet_data_length -= LOOPBACK_INTERFACE_LINK_LAYER_HEADER_SIZE;

        enum InternetLayerProtocal internet_protocal_type;
        internet_protocal_type = (enum InternetLayerProtocal)link_layer_header.protocal_type;
        switch (internet_protocal_type)
        {
        case IPV4:
        case IPV6_24:
        case IPV6_28:
        case IPV6_30:
        case OSI:
        case IPX:
            // valid!
            break;
        default:
            internet_protocal_type = INTERNET_PROTOCAL_ERROR;
            break;
        }

        if (internet_protocal_type == INTERNET_PROTOCAL_ERROR)
        {
            fprintf(stderr, "Error reading internet protocal type at packet number %d\n", packet_count);
            fclose(file);
            return 1;
        }

        // read internet protocal header, should all be ipv4 in this project so not handling others :D
        ipv4_header_min_t ipv4_header;
        switch (internet_protocal_type)
        {
        case IPV4:
            fread(&ipv4_header, IPV4_HEADER_MIN_SIZE, 1, file);
            remaining_packet_data_length -= IPV4_HEADER_MIN_SIZE;
            break;

        default:
            fprintf(stderr, "protocal is not IPV4, should not happen at this current project state\n");
            fclose(file);
            return 1;
            break;
        }

        // see if ipv4 options exists, if so then we need to read more, NOTE that in ipv4 the IHL unit is in 32 bits, NOT 1 byte
        uint8_t ihl_in_bytes = (ipv4_header.version_and_IHL & 0x0f) << 2;
        uint8_t ipv4_options_length = ihl_in_bytes - IPV4_HEADER_MIN_SIZE;

        if (ipv4_options_length > 0)
        {
            // don't care about IP options for now
            fseek(file, (long)ipv4_options_length, SEEK_CUR);
            remaining_packet_data_length -= ipv4_options_length;
        }

        // determine tranport layer protocal type, assuming we have ipv4 packet
        enum TransportLayerProtocal transport_protocal_type;
        transport_protocal_type = (enum TransportLayerProtocal)ipv4_header.protocal;
        switch (transport_protocal_type)
        {
        case ICMP:
        case IGMP:
        case TCP:
        case UDP:
        case ENCAP:
        case OSPF:
        case SCTP:
            // valid!
            break;

        default:
            transport_protocal_type = TRANSPORT_PROTOCAL_ERROR;
            break;
        }
        if (transport_protocal_type == TRANSPORT_PROTOCAL_ERROR)
        {
            fprintf(stderr, "Error reading transport protocal type at packet number %d\n", packet_count);
            fclose(file);
            return 1;
        }

        // read transport protocal header, assuming we have TCP
        tcp_header_min_t tcp_header;
        fread(&tcp_header, TCP_HEADER_MIN_SIZE, 1, file);
        remaining_packet_data_length -= TCP_HEADER_MIN_SIZE;

        // see if TCP header options exists, if so then we need to read more, NOTE that the original unit is 32 bits
        uint8_t data_offset_in_bytes = (tcp_header.data_offset_reserved & 0xf0) >> 2; // shift right 4 then left 2
        uint8_t tcp_options_length = data_offset_in_bytes - TCP_HEADER_MIN_SIZE;

        if (tcp_options_length > 0)
        {
            // don't care about TCP options for now
            fseek(file, (long)tcp_options_length, SEEK_CUR);
            remaining_packet_data_length -= tcp_options_length;
        }

        // byte swap tcp_header fields (if > 1 byte) because TCP uses BIG Endian
        uint16_t dst_port = ntohs(tcp_header.destination_port);
        uint16_t src_port = ntohs(tcp_header.source_port);

        bool SYN_flagged = (tcp_header.flags & 0x0002) != 0;
        bool ACK_flagged = (tcp_header.flags & 0x0010) != 0;

        // count packets that initiated a SYN to us
        if (SYN_flagged && dst_port == 80)
        {
            SYN_initiated_count += 1;
        }
        // count packets that we ACKed, the machine should not be able to ACK every SYN (It was a SYN flood attack)
        if (ACK_flagged && src_port == 80)
        {
            ACK_count += 1;
        }

        fseek(file, (long)remaining_packet_data_length, SEEK_CUR);
    }
    printf("%d amount of packets read\n", packet_count);
    printf("Initiated SYN count: %d, ACK count: %d\n", SYN_initiated_count, ACK_count);

    fclose(file);
    return 0;
}