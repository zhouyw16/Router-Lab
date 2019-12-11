#include <stdint.h>
#include <stdlib.h>

uint16_t calculateIPChecksum(uint8_t *packet, size_t len) {
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

bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint16_t checkCal = calculateIPChecksum(packet, len);
  uint16_t checkGet = (uint16_t)((packet[10] << 8) + packet[11]);
  return checkCal == checkGet;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  if (!validateIPChecksum(packet, len))
    return false;
  packet[8] -= 1;
  uint16_t checkCal = calculateIPChecksum(packet, len);
  packet[10] = (uint8_t) (checkCal >> 8);
  packet[11] = (uint8_t) (checkCal & 0xff);
  return true;
}
