#pragma once
#include <stdint.h>
#include "network_package_struct.h"

void reverse_byte_uint32(uint32_t *num);
void reverse_byte_uint16(uint16_t *num);

void pcap_file_header_swap_endian(pcap_file_header_t *h);
void pcap_packet_header_swap_endian(pcap_packet_header_t *h);