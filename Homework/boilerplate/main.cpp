#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list>

extern uint16_t calculateIPChecksum(uint8_t *packet);
extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern uint32_t joinByte(const uint8_t* begin);
extern void splitByte(uint8_t* begin, uint32_t variable);
extern std::list<RoutingTableEntry>::iterator tableQuery(RoutingTableEntry *entry);

void buildRipPacket(RipPacket *rip, uint32_t if_index, int rip_page, int rip_num); // from table to rip
uint32_t buildIPPacket(const RipPacket* rip, uint8_t *output, uint32_t src_addr, uint32_t dst_addr); // from rip to ip
bool updateRoutingTable(const RipPacket* rip, uint32_t src_addr, uint32_t if_index); // from rip to table
bool updateRoutingEntry(const RipEntry *ripEntry, RoutingTableEntry *tableEntry, uint32_t src_addr, uint32_t if_index); // from rip entry to table entry
void showRoutingTable();

extern std::list<RoutingTableEntry> routingTable;
uint8_t packet[8192];
uint8_t output[8192];
// 0: 192.168.4.2
// 1: 192.168.5.2
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0204a8c0, 0x0205a8c0, 0x0102000a, 0x0103000a};

int main(int argc, char *argv[]) {
    // 0a.
    int res = HAL_Init(1, addrs);
    if (res < 0) {
        return res;
    }

    // 0b. Add direct routes
    // For example:
    // 192.168.3.0/24 if 0
    // 192.168.4.0/24 if 1
    // 10.0.2.0/24    if 2
    // 10.0.3.0/24    if 3
    for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        RoutingTableEntry entry = {
            .addr = addrs[i] & 0x00FFFFFF,  // big endian
            .len = 24,                      // small endian
            .if_index = i,                  // small endian
            .nexthop = 0,                   // big endian, means direct
            .metric = 1 << 24             // big endian
        };
        update(true, entry);
    }

    // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
    in_addr_t multi_addr = 0x090000e0;
    macaddr_t multi_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09};
    uint64_t last_time = 0;
    while (1) {
        uint64_t time = HAL_GetTicks();
        if (time > last_time + 30 * 1000) { 
            // send complete routing table to every interface
            // ref. RFC2453 3.8
            for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
                int rip_num = (routingTable.size() - 1) / RIP_MAX_ENTRY + 1;
                for (int j = 0; j < rip_num; j++) {
                    RipPacket resp;
                    buildRipPacket(&resp, (uint32_t)i, j, rip_num);
                    uint32_t ip_len;
                    ip_len = buildIPPacket(&resp, output, addrs[i], multi_addr);
                    HAL_SendIPPacket(i, output, ip_len, multi_mac);     
                }                         
            }
            showRoutingTable();
            printf("30s Timer\n");
            last_time = time;
        }

        int mask = (1 << N_IFACE_ON_BOARD) - 1;
        macaddr_t src_mac;
        macaddr_t dst_mac;
        int if_index;
        res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);
        if (res == HAL_ERR_EOF) {
            break;
        } else if (res < 0) {
            return res;
        } else if (res == 0) {
            // Timeout
            continue;
        } else if (res > sizeof(packet)) {
            // packet is truncated, ignore it
            continue;
        }

        // 1. validate
        if (!validateIPChecksum(packet, res)) {
            printf("Invalid IP Checksum\n");
            continue;
        }

        // extract src_addr and dst_addr from packet
        // big endian
        in_addr_t src_addr, dst_addr;
        src_addr = joinByte(packet + 12);
        dst_addr = joinByte(packet + 16);

        // 2. check whether dst is me
        bool dst_is_me = false;
        for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
            if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
                dst_is_me = true;
                break;
            }
        }

        // TODO2: Handle rip multicast address(224.0.0.9)?
        if (dst_addr == multi_addr) {
            dst_is_me = true;
            dst_addr = addrs[if_index];
        }

        if (dst_is_me) {
            // 3a.1
            RipPacket rip;
            // check and validate
            if (disassemble(packet, res, &rip)) {
                if (rip.command == 1) {
                    // 3a.3 request, ref. RFC2453 3.9.1
                    // only need to respond to whole table requests in the lab
                    int rip_num = (routingTable.size() - 1) / RIP_MAX_ENTRY + 1;
                    for (int j = 0; j < rip_num; j++) {
                        RipPacket resp;
                        buildRipPacket(&resp, (uint32_t)if_index, j, rip_num);
                        // when response, dst_addr as src and src_addr as dst
                        uint32_t ip_len;
                        ip_len = buildIPPacket(&resp, output, dst_addr, src_addr);
                        // send it back
                        HAL_SendIPPacket(if_index, output, ip_len, src_mac);
                    }
                } else {
                    // 3a.2 response, ref. RFC2453 3.9.2
                    // update routing table
                    // new metric = ?
                    // update metric, if_index, nexthop
                    // what is missing from RoutingTableEntry?
                    // triggered updates? ref. RFC2453 3.10.1
                    if (updateRoutingTable(&rip, src_addr, (uint32_t)if_index)) {
                        for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
                            if (i != if_index) {
                                int rip_num = (routingTable.size() - 1) / RIP_MAX_ENTRY + 1;
                                for (int j = 0; j < rip_num; j++) {
                                    RipPacket resp;
                                    buildRipPacket(&resp, (uint32_t)i, j, rip_num);
                                    uint32_t ip_len;
                                    ip_len = buildIPPacket(&resp, output, addrs[i], multi_addr);
                                    HAL_SendIPPacket(i, output, ip_len, multi_mac);     
                                }                           
                            }
                        }
                        showRoutingTable();
                    }
                }
            }
        } else {
            // 3b.1 dst is not me
            // forward
            // beware of endianness
            uint32_t nexthop, dest_if;
            if (query(dst_addr, &nexthop, &dest_if)) {
                // found
                macaddr_t dest_mac;
                // direct routing
                if (nexthop == 0) {
                    nexthop = dst_addr;
                }
                if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
                    // found
                    memcpy(output, packet, res);
                    if (output[8] > 0) {
                        // if ttl > 0, then update ttl and checksum
                        forward(output, res);
                        HAL_SendIPPacket(dest_if, output, res, dest_mac);   
                    } else {
                        // TODO: you might want to check ttl=0 case
                        // if ttl == 0, then responce ICMP Time Exceeded
                    }
                } else {
                    // not found
                    // you can drop it
                    printf("ARP not found for %x\n", nexthop);
                }
            } else {
                // not found
                // optionally you can send ICMP Host Unreachable
                printf("IP not found for %x\n", src_addr);
            }
        }
    }
    return 0;
}

void buildRipPacket(RipPacket *rip, uint32_t if_index, int rip_page, int rip_num) {
    std::list<RoutingTableEntry>::iterator begin = std::advance(routingTable.begin(), rip_page * RIP_MAX_ENTRY);
    std::list<RoutingTableEntry>::iterator end = rip_page + 1 < rip_num ? 
        std::advance(routingTable.begin(), (rip_page + 1) * RIP_MAX_ENTRY) : routingTable.end();
    for (std::list<RoutingTableEntry>::iterator it = begin; it != end; it++) {
        if (it -> nexthop == 0 || it -> if_index != if_index) {
            RipEntry *entry = (rip -> entries) + i;
            entry -> addr = it -> addr;
            entry -> mask = (1 << it -> len) -1;
            entry -> nexthop = it -> nexthop;
            entry -> metric = it -> metric;  
            i++;  
        }
    rip -> numEntries = (uint32_t) i;
    rip -> command = 0x02;
}

uint32_t buildIPPacket(const RipPacket* rip, uint8_t *output, uint32_t src_addr, uint32_t dst_addr) {
    // assemble
    // RIP
    uint32_t rip_len = assemble(rip, output + 28);
    uint32_t udp_len = rip_len + 8;
    uint32_t ip_len = udp_len + 20;
    // IP
    output[0] = 0x45;
    output[1] = 0x00;
    output[2] = (uint8_t) (ip_len >> 8);
    output[3] = (uint8_t) (ip_len);
    output[4] = 0x00;
    output[5] = 0x00;
    output[6] = 0x00;
    output[7] = 0x00;
    output[8] = 0x01;
    output[9] = 0x11;
    output[10] = 0x00;
    output[11] = 0x00;
    splitByte(output + 12, src_addr);
    splitByte(output + 16, dst_addr);
    // UDP
    // port = 520
    output[20] = 0x02;
    output[21] = 0x08;
    output[22] = 0x02;
    output[23] = 0x08;
    output[24] = (uint8_t) (udp_len >> 8);
    output[25] = (uint8_t) (udp_len);
    output[26] = 0x00;
    output[27] = 0x00;
    // checksum calculation for ip and udp
    // if you don't want to calculate udp checksum, set it to zero
    uint16_t ip_checksum = calculateIPChecksum(output);
    uint16_t udp_checksum = 0x0000;
    output[10] = (uint8_t) (ip_checksum >> 8);
    output[11] = (uint8_t) (ip_checksum);
    output[26] = (uint8_t) (udp_checksum >> 8);
    output[27] = (uint8_t) (udp_checksum);

    return ip_len;
}

bool updateRoutingTable(const RipPacket* rip, uint32_t src_addr, uint32_t if_index) {
    bool has_updated = false;
    for (int i = 0; i < rip -> numEntries; i++) {
        RoutingTableEntry entry;
        if (updateRoutingEntry(rip -> entries + i, &entry, src_addr, if_index)) {
            update(true, entry);
            has_updated = true;
        }
    }
    return has_updated;
}

bool updateRoutingEntry(const RipEntry *ripEntry, RoutingTableEntry *tableEntry, uint32_t src_addr, uint32_t if_index) {
    tableEntry -> addr = ripEntry -> addr;
    tableEntry -> len = (uint32_t) (ripEntry -> mask == 0 ? 0 : 32 - __builtin_clz(ripEntry -> mask));
    std::list<RoutingTableEntry>::iterator it = tableQuery(tableEntry);
    if (it != routingTable.end() && it -> metric <= ripEntry -> metric + (1 << 24 )) {
        return false;
    }
    tableEntry -> if_index = if_index;
    tableEntry -> nexthop = src_addr;
    tableEntry -> metric = ripEntry -> metric + (1 << 24);
    return true;
}

void showRoutingTable() {
    printf("Routing Table : \n");
    int i = 0;
    for (std::list<RoutingTableEntry>::iterator it = routingTable.begin(); it != routingTable.end() && i < 10; it++) {
            printf("entry %d:  ", i);
            printf("addr: %08x  len: %08x  if_index: %08x  nexthop: %08x  metric: %08x\n", it->addr, it->len, it->if_index, it->nexthop, it->metric);
            i++;  
    }
    if (i >= 10) {
        printf("entry num: %d\n", i);
    }
}
