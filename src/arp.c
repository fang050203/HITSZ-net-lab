#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>


struct wait{
    uint8_t* ip;
    buf_t* buf;
};

struct wait wait_queue[100];
//索引
int index_q =0;
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
//用来缓存等待ARP请求的包
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}



//注意：ARP是一个独立的三层协议，所以不用经过IP的封装


//arp_in函数：接受以太网发来的ARP数据包，处理ARP请求或响应(arp_res)
//arp_out:上层要发送IP包，但是不知道IP地址，可能调用req


/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    //初始化缓冲区
    buf_init(&txbuf,0);

    //添加arp报文头
    buf_add_header(&txbuf,sizeof(arp_pkt_t));
    //填写ARP报头信息
    arp_pkt_t* p = (arp_pkt_t*)txbuf.data;
    //拷贝初始arp信息
    p->hw_type16 = arp_init_pkt.hw_type16;
    p->pro_type16 = arp_init_pkt.pro_type16; 
    p->hw_len = arp_init_pkt.hw_len;
    p->pro_len = arp_init_pkt.pro_len;
    //写入请求信息,同时注意要翻转
    p->opcode16 = swap16(ARP_REQUEST);
    memcpy(p->sender_mac,arp_init_pkt.sender_mac,NET_MAC_LEN);
    memcpy(p->sender_ip,arp_init_pkt.sender_ip,NET_IP_LEN);
    //传入目标mac地址

    //将目标mac地址的值写入
    //设置为广播mac地址
    memcpy(p->target_mac,ether_broadcast_mac,NET_MAC_LEN);
    //这里似乎暂时不用翻转
    memcpy(p->target_ip,target_ip,NET_IP_LEN);
    //调用函数发出
    ethernet_out(&txbuf,ether_broadcast_mac,NET_PROTOCOL_ARP);
    return;
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    //初始化缓冲区
    buf_init(&txbuf,0);

    //添加arp报文头
    buf_add_header(&txbuf,sizeof(arp_pkt_t));
    //填写ARP报头信息
    arp_pkt_t* p = (arp_pkt_t*)txbuf.data;
    //拷贝初始arp信息
    p->hw_type16 = arp_init_pkt.hw_type16;
    p->pro_type16 = arp_init_pkt.pro_type16; 
    p->hw_len = arp_init_pkt.hw_len;
    p->pro_len = arp_init_pkt.pro_len;
    //写入请求信息,同时注意要翻转
    p->opcode16 = swap16(ARP_REPLY);
    memcpy(p->sender_mac,arp_init_pkt.sender_mac,NET_MAC_LEN);
    memcpy(p->sender_ip,arp_init_pkt.sender_ip,NET_IP_LEN);
    //传入目标mac地址

    //将目标mac地址的值写入
    //设置为广播mac地址
    memcpy(p->target_mac,target_mac,NET_MAC_LEN);
    //这里似乎暂时不用翻转
    memcpy(p->target_ip,target_ip,NET_IP_LEN);
    //调用函数发出
    ethernet_out(&txbuf,target_mac,NET_PROTOCOL_ARP);
    return;
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    //如果数据长度小于头部，直接丢弃
    if(buf->len < sizeof(arp_pkt_t))return;
    //判断头部各字段是否符合要求
    arp_pkt_t* p = (arp_pkt_t*)buf->data;

    if (p->hw_type16 != swap16(ARP_HW_ETHER) ||
        p->pro_type16 != swap16(NET_PROTOCOL_IP) ||
        p->hw_len != NET_MAC_LEN ||
        p->pro_len != NET_IP_LEN ||
        (p->opcode16 != swap16(ARP_REQUEST) &&
        p->opcode16 != swap16(ARP_REPLY))
    ) return;

    //更新映射表信息
    map_set(&arp_table,p->sender_ip,p->sender_mac);
    //查看buf缓存情况
    buf_t* b =NULL;
    if((b = (buf_t*)map_get(&arp_buf,p->sender_ip)) == NULL)
    {
        uint8_t temp[4] = NET_IF_IP;
        //如果是ARP请求报文并且是发给本机的
        //注意大小端转换！！！！很重要
        if((p->opcode16 == swap16(ARP_REQUEST)) && (memcmp(p->target_ip,temp,NET_IP_LEN) == 0))
        {
            //发送ARP请求
            arp_resp(p->sender_ip,p->sender_mac);
        }
    }
    else{
        //向以太网发送等待的这个数据包
        ethernet_out(b,map_get(&arp_table,p->sender_ip),NET_PROTOCOL_IP);
        map_delete(&arp_buf,p->sender_ip);
        //再写入一个
        for(int i=0;i<index_q;i++)
        {
            if(memcmp(p->sender_ip,wait_queue[i].ip,NET_IP_LEN) ==0)
            {
                map_set(&arp_buf,p->sender_ip,wait_queue[i].buf);
                wait_queue[i].ip = NULL;
                wait_queue[i].buf = NULL;
                break;
            }
        }
    }
    return;
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    //检测是否能找到
    //存储返回mac地址
    uint8_t* p =NULL;
    if((p = (uint8_t*)map_get(&arp_table,(void*)ip) )== NULL){
        //如果没有找到，先判断有没有已经存在的包
        buf_t* b = (buf_t*)map_get(&arp_buf,(void*)ip);
        //如果没有说明并没有正在等待ARP请求返回
        if( b == NULL)
        {
            //存入表中
            map_set(&arp_buf,ip,buf);
            //发出arp_req请求
            arp_req(ip);
        }else if(memcmp(b,buf,sizeof(buf_t)) != 0)
        {
            //写入等待队列
            wait_queue[index_q].ip = ip;
            wait_queue[index_q].buf = buf;
            index_q++;
        }
    }else{
        //如果找到，直接发送
        ethernet_out(buf,p,NET_PROTOCOL_IP);
    }
    return;
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}