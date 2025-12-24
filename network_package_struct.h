#pragma once
#include <stdint.h>

// length is 24 octets
typedef struct pcap_file_header{
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t reserved_1;
    uint32_t reserved_2;
    uint32_t snapshot_length;
    uint32_t link_layer_type_and_optionals;

} pcap_file_header_t;

// length is 16 octects
typedef struct pcap_packet_header{
    uint32_t time_in_second;
    uint32_t time_in_detail; // microseconds | nanoseconds, we can find out by the file header's magic number
    uint32_t captured_data_length;
    uint32_t untruncated_data_length;

} pcap_packet_header_t;

//TODO: struct that stores field name of the above structs?

//TODO: need TCP & IP structs as well