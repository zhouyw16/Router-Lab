#include <stdint.h>
#include <stdlib.h>

uint16_t calculateIPChecksum(uint8_t *packet) {
    uint32_t checkSum = 0;
    int IHL = (int) (packet[0] & 0xf) * 4;
    for (int i = 0; i < IHL; i += 2) {
        checkSum += packet[i];
    }
    checkSum = checkSum << 8;
    for (int i = 1; i < IHL; i += 2) {
        checkSum += packet[i];
    }
    checkSum -= (uint32_t)((packet[10] << 8) + packet[11]);
    while (checkSum >> 16) {
        checkSum = (checkSum >> 16) + (checkSum & 0xffff);
    }
    uint16_t checkCal = ~((uint16_t)(checkSum & 0xffff));
    return checkCal;
}

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
    uint16_t checkCal = calculateIPChecksum(packet);
    uint16_t checkGet = (uint16_t)((packet[10] << 8) + packet[11]);
    return checkCal == checkGet;
}
