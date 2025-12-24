#include "pcap_util.h";

void reverse_byte_uint32(uint32_t *num){
    uint32_t num_copy = *num;
    uint32_t new_num = 0;
    int mask = 0xFF;

    for(int i=0; i<sizeof(*num); i++){
        uint8_t byte_num = mask&num_copy;
        num_copy >>= 8;
        new_num <<= 8;
        new_num |= byte_num;
    }

    *num = new_num;
}

void reverse_byte_uint16(uint16_t *num){
    uint16_t num_copy = *num;
    uint16_t new_num = 0;
    int mask = 0xFF;

    for(int i=0; i<sizeof(*num); i++){
        uint8_t byte_num = mask&num_copy;
        num_copy >>= 8;
        new_num <<= 8;
        new_num |= byte_num;
    }

    *num = new_num;

}