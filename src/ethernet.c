#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // TO-DO

    //先判读大小，如果没有以太网帧头大小都没有就丢弃
    if(buf->len < sizeof(ether_hdr_t))return;
    //获取头部结构体
    ether_hdr_t* p =(ether_hdr_t*)buf->data;
    //获取上层协议号
    uint16_t a = swap16(p->protocol16);
    //手动翻转
    //移除包头
    buf_remove_header(buf,sizeof(ether_hdr_t));
    //传入下一层
    net_in(buf,a,p->src);
    return; 
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // TO-DO
    //如果数据段长度小于最小传输单元
    if(buf->len < ETHERNET_MIN_TRANSPORT_UNIT)
    {
        buf_add_padding(buf,ETHERNET_MIN_TRANSPORT_UNIT - buf->len);
    }
    //添加包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    memcpy(hdr->dst,mac,NET_MAC_LEN);
    uint8_t amac[NET_MAC_LEN] = NET_IF_MAC;
    memcpy(hdr->src,amac,NET_MAC_LEN);
    hdr->protocol16 = swap16(protocol);
    driver_send(buf);
    return;
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
