#include "pcap_util.h"

void reverse_byte_uint32(uint32_t *num)
{
    uint32_t num_copy = *num;
    uint32_t new_num = 0;
    int mask = 0xFF;

    for (int i = 0; i < sizeof(uint32_t); i++)
    {
        uint8_t byte_num = mask & num_copy;
        num_copy >>= 8;
        new_num <<= 8;
        new_num |= byte_num;
    }

    *num = new_num;
}

void reverse_byte_uint16(uint16_t *num)
{
    uint16_t num_copy = *num;
    uint16_t new_num = 0;
    int mask = 0xFF;

    for (int i = 0; i < sizeof(uint16_t); i++)
    {
        uint8_t byte_num = mask & num_copy;
        num_copy >>= 8;
        new_num <<= 8;
        new_num |= byte_num;
    }

    *num = new_num;
}

void pcap_file_header_swap_endian(pcap_file_header_t *h)
{
    reverse_byte_uint32(&(h->magic_number));
    reverse_byte_uint16(&(h->major_version));
    reverse_byte_uint16(&(h->minor_version));
    reverse_byte_uint32(&(h->reserved_1));
    reverse_byte_uint32(&(h->reserved_2));
    reverse_byte_uint32(&(h->snapshot_length));
    reverse_byte_uint32(&(h->link_layer_type_and_optionals));
}

void pcap_packet_header_swap_endian(pcap_packet_header_t *h)
{
    reverse_byte_uint32(&(h->time_in_second));
    reverse_byte_uint32(&(h->time_in_detail));
    reverse_byte_uint32(&(h->captured_data_length));
    reverse_byte_uint32(&(h->untruncated_data_length));
}