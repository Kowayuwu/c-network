#pragma once
#include <stdint.h>

enum InternetLayerProtocal
{
    IPV4 = 2,
    IPV6_24 = 24,
    IPV6_28 = 28,
    IPV6_30 = 30,
    OSI = 7,
    IPX = 23,
    INTERNET_PROTOCAL_ERROR = 0
};

enum TransportLayerProtocal
{
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    ENCAP = 41,
    OSPF = 89,
    SCTP = 132,
    TRANSPORT_PROTOCAL_ERROR = 0
};

// length is 24 octets
typedef struct pcap_file_header
{
    uint32_t magic_number;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t reserved_1;
    uint32_t reserved_2;
    uint32_t snapshot_length;
    uint32_t link_layer_type_and_optionals;

} pcap_file_header_t;

// length is 16 octects
typedef struct pcap_packet_header
{
    uint32_t time_in_second;
    uint32_t time_in_detail; // microseconds | nanoseconds, we can find out by the file header's magic number
    uint32_t captured_data_length;
    uint32_t untruncated_data_length;

} pcap_packet_header_t;

// TODO: struct that stores field name of the above structs? EDIT: prob not, made swap endian function in util instead

// length is 4 octects
typedef struct loopback_interface_link_layer_header
{
    uint32_t protocal_type;
} loopback_interface_link_layer_header_t;

// length is 20 octects
typedef struct ipv4_header_min
{
    uint8_t version_and_IHL; // highest 4 bit is Version, rest is IHL
    uint8_t DSCP_and_ECN;    // highest 6 bit is DSCP, rest is ECN
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset; // highest 3 bit is flags, rest is fragment offset
    uint8_t time_to_live;
    uint8_t protocal;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
    // not including options (exists if IHL > 5) due to its dynamic size
} ipv4_header_min_t;

// length is 20 octects
typedef struct tcp_header_min
{
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t data_offset_reserved; // highest 4 bit is data_offset, Nonce Sum Flag was at the lowest bit during 2003-2017
    uint8_t flags;                // forth highest bit is ACK, seventh is SYN
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer; // only used if URG flag is set
    // not including options (exists if data_offset > 5) due to its dynamic size
} tcp_header_min_t;
