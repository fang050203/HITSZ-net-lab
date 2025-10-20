#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    //先获取指针
    udp_hdr_t* p= (udp_hdr_t*)buf->data;
    //需要保存源端口
    uint16_t src_p = swap16(p->src_port16);
    if(buf->len <sizeof(udp_hdr_t) || buf->len < swap16(p->total_len16))return;

    uint16_t check = p->checksum16;
    //重新计算校验和
    p->checksum16 =0;

    if(check != transport_checksum(NET_PROTOCOL_UDP,buf,src_ip,net_if_ip))return;
    //恢复原值
    p->checksum16 = check;

    udp_handler_t* f = NULL;
    //当找不到对应的函数
    uint16_t src_d = swap16(p->dst_port16);

    if((f = map_get(&udp_table,&src_d)) == NULL)
    {
        buf_add_header(buf,sizeof(ip_hdr_t));
        //端口不可用差错报文
        icmp_unreachable(buf,src_ip,ICMP_CODE_PORT_UNREACH);
    }else{
        //移除udp报头
        buf_remove_header(buf,sizeof(udp_hdr_t));
        (*f)((uint8_t*)buf->data, buf->len, src_ip, src_p);
    }

}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    // TO-DO
    //添加udp数据报头
    buf_add_header(buf,sizeof(udp_hdr_t));

    //填充首部
    udp_hdr_t* p =(udp_hdr_t*)buf->data;

    p->src_port16 = swap16(src_port);
    p->dst_port16 = swap16(dst_port);
    //先暂时填为0
    p->checksum16 = 0;
    p->total_len16 = swap16(buf->len);

    
    p->checksum16 = transport_checksum(NET_PROTOCOL_UDP,buf,net_if_ip,dst_ip);

    //发出数据包
    ip_out(buf,dst_ip,NET_PROTOCOL_UDP);

}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init() {
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler) {
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port) {
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}