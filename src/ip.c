#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO

    //数据包不完整丢弃
    if(buf->len < sizeof(ip_hdr_t))return;
    //获取ip首部指针
    ip_hdr_t* p =(ip_hdr_t*)buf->data;
    //先存储一下首部的长度
    uint8_t hdr_len = p->hdr_len <<2;
    //注意要进行字节大小端转换
    if(p->version != IP_VERSION_4 || swap16(p->total_len16)  > buf->len)return;


    //先保存首部校验和
    uint16_t check = p->hdr_checksum16;
    //再置为0
    p->hdr_checksum16 = 0;
    //如果不一致就返回
    //计算首部长度
    if(check != checksum16((uint16_t*)p,hdr_len))return;
    else p->hdr_checksum16 = check;

    //如果不是发给本机的也丢弃
    uint8_t ip[NET_IP_LEN] =NET_IF_IP;
    if(memcmp(p->dst_ip,ip,NET_IP_LEN) != 0)return;

    //如果大于总长度字段，说明存在填充字段
    if(buf->len > swap16(p->total_len16))
    {
        buf_remove_padding(buf,buf->len - swap16(p->total_len16));
    }
    //临时存储
    ip_hdr_t ip_t;
    memcpy(&ip_t,p,hdr_len);

    //去掉ip头，向上传递
    buf_remove_header(buf,hdr_len);

    //发出差错报文
    if(net_in(buf,p->protocol,p->src_ip) < 0)
    {
        //再加上ip头
        buf_add_header(buf,hdr_len);
        memcpy(buf->data,&ip_t,hdr_len);
        ip_hdr_t* p =(ip_hdr_t*)buf->data;
        icmp_unreachable(buf,p->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
    }
    return;

}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    //增加头部信息
    buf_add_header(buf,sizeof(ip_hdr_t));
    ip_hdr_t* p = (ip_hdr_t*)buf->data;
    p->hdr_len = sizeof(ip_hdr_t)  >> 2;
    //IPV4
    p->version = 4;
    p->tos = 0;
    p->total_len16 = swap16(buf->len);
    p->id16 = swap16((uint16_t)id);
    //这里offset可能需要左移三位？
    p->flags_fragment16 = swap16((mf << 13) | offset);
    p->ttl = 64;
    p->protocol = protocol;
    //先暂时设为0
    p->hdr_checksum16 = 0;
    memcpy(p->src_ip,net_if_ip,NET_IP_LEN);
    memcpy(p->dst_ip,ip,NET_IP_LEN);

    //填入首部
    p->hdr_checksum16 = checksum16((uint16_t*)p,sizeof(ip_hdr_t));

    //发出请求
    arp_out(buf,ip);
    return;
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    //记录一下大小用于后续判断
    //八字节偏移单位
    //注意变量大小取值范围！！！！很重要
    static int send_id =0;
    uint16_t ip_size =  (ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
    if(buf->len > ip_size)
    {
        //此时需要分片发送
        uint8_t* p =  (uint8_t*)buf->data;
        //索引变量
        uint8_t* p_t = p;
        //用来统计已经发送了多少字节
        uint16_t sum =0;

        buf_t* ip_buf = (buf_t*)malloc(sizeof(buf_t));
        for( ; sum + ip_size < buf->len; p_t+=ip_size,sum+=ip_size)
        {   
            buf_init(ip_buf,ip_size);
            memcpy(ip_buf->data,p_t,ip_size);
            ip_fragment_out(ip_buf,ip,protocol,send_id,sum / 8,1);
        }
        //处理剩余多出去的分片
        buf_init(ip_buf,buf->len - sum);
        memcpy(ip_buf->data,p_t,buf->len - sum);
        ip_fragment_out(ip_buf,ip,protocol,send_id,sum/8,0);
        
    }else{
        //直接发送
        ip_fragment_out(buf,ip,protocol,send_id,0,0);
    }
    send_id ++;
    /*static int send_id = 0;
    int Max_load_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    
    // 检查数据报长度
    if(buf->len <= Max_load_len) {
        ip_fragment_out(buf, ip, protocol, send_id, 0, 0);
    }
    else {
        // 分片处理
        uint16_t offset = 0;
        buf_t *ip_buf = (buf_t*)malloc(sizeof(buf_t));
        while (buf->len > 0) {
            size_t part_size = (buf->len > Max_load_len) ? Max_load_len : buf->len;
            buf_init(ip_buf, part_size);
            memcpy(ip_buf->data, buf->data, part_size);
            ip_fragment_out(ip_buf, ip, protocol, send_id, offset / IP_HDR_OFFSET_PER_BYTE, (buf->len > Max_load_len) ? 1 : 0);
            
            // 更新相关变量
            offset += part_size;
            buf->data += part_size;
            buf->len -= part_size;
        }
    }
    send_id++;*/
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}