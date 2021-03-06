#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

/**
 *在头文件 rip.h 中定义了如下的结构体：
 *#define RIP_MAX_ENTRY 25
 *typedef struct {
 *  // all fields are big endian
 *  // we don't store 'family', as it is always 2(response) and 0(request)
 *  // we don't store 'tag', as it is always 0
 *uint32_t addr;
 *uint32_t mask;
 *uint32_t nexthop;
 *uint32_t metric;
 *} RipEntry;

 *typedef struct {
 *uint32_t numEntries;
 * // all fields below are big endian
 * uint8_t command; // 1 for request, 2 for response, otherwsie invalid
 * // we don't store 'version', as it is always 2
 * // we don't store 'zero', as it is always 0
 *RipEntry entries[RIP_MAX_ENTRY];
 *} RipPacket;

 *你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包 
 *由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。 
 *需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
 */

uint32_t joinByte(const uint8_t* begin) {
    uint32_t res = 0;
    for (int i = 0; i < 4; i++) {
        res += (begin[i] << (i * 8));
    }
    return res;
}

void splitByte(uint8_t* begin, uint32_t variable) {
    for (int i = 0; i < 4; i++) {
        begin[i] = (uint8_t) (variable >> (i * 8));
    }
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    uint32_t totalLen = (packet[2] << 8) + packet[3];
    if (totalLen > len) {
        return false;
    }
    uint32_t IHL = (uint32_t) ((packet[0] & 0xf) * 4);

    const uint8_t *rip = packet + IHL + 8;
    uint8_t command = rip[0];
    uint8_t version = rip[1];
    uint16_t zero = (rip[2] << 8) + rip[3];
    uint32_t numEntries = (len - IHL - 8 - 4) / 20;
    if (!(command == 1 || command == 2)) {
        return false;
    }
    if (!(version == 2)) {
        return false;
    }
    if (!(zero == 0)) {
        return false;
    }
    output -> command = command;
    output -> numEntries = numEntries;

    for (int i = 0; i < numEntries; i++ ) {
        const uint8_t *entry = rip + 4 + 20 * i;
        uint16_t family = (entry[0] << 8) + entry[1];
        uint16_t tag = (entry[2] << 8) + entry[3];
        uint32_t addr = joinByte(entry + 4);
        uint32_t mask = joinByte(entry + 8);
        uint32_t nexthop = joinByte(entry + 12);
        uint32_t metric = joinByte(entry + 16);
        if (!(command == 1 && family == 0 || command == 2 && family == 2)) {
            return false;
        }
        if (!(tag == 0)) {
            return false;
        }
        if (!(ntohl(metric) >= 1 && ntohl(metric) <= 16)) {
            return false;
        }
        if ((mask)&((mask)+1)) {  //judge ~x+1 is 2^n or not
            return false;
        }
        output -> entries[i].addr = addr;
        output -> entries[i].mask = mask;
        output -> entries[i].nexthop = nexthop;
        output -> entries[i].metric = metric;
    }
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
    uint32_t len = 4 + 20 * rip -> numEntries;
    buffer[0] = rip -> command;
    buffer[1] = 2;
    buffer[2] = 0;
    buffer[3] = 0;
    for (int i = 0; i < rip -> numEntries; i ++) {
        uint8_t* entry = buffer + 4 + 20 * i;
    for (int i = 0; i < 20; i++) {
        entry[i] = 0;
    }
    entry[1] = rip -> command == 1 ? 0 : 2;
        splitByte(entry + 4, rip -> entries[i].addr);
        splitByte(entry + 8, rip -> entries[i].mask);
        splitByte(entry + 12, rip -> entries[i].nexthop);
        splitByte(entry + 16, rip -> entries[i].metric);
    }
    return len;
}
