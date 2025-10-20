#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
    //先初始化包
    buf_init(&txbuf,req_buf->len);
    //把数据部分拷贝过去
    memcpy(txbuf.data,req_buf->data,req_buf->len);
    icmp_hdr_t* p = (icmp_hdr_t*)(txbuf.data); 
    p->type = ICMP_TYPE_ECHO_REPLY;
    p->code = 0;
    //先设为0
    p->checksum16 =0;
    p->id16 =((icmp_hdr_t*)(req_buf->data))->id16;
    p->seq16 =((icmp_hdr_t*)(req_buf->data))->seq16;

    //计算校验和然后填入
    p->checksum16 = checksum16((uint16_t*)(txbuf.data),txbuf.len);

    //发送出去
    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
    //若包长长度小于ICMP首部长度则丢弃
    if(buf->len < sizeof(icmp_hdr_t))return;

    icmp_hdr_t* p = (icmp_hdr_t*)(buf->data);
    //查询是否是ping请求：
    if(p->type == ICMP_TYPE_ECHO_REQUEST)
    {
        icmp_resp(buf,src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    buf_init(&txbuf,sizeof(ip_hdr_t) + 8);

    //拷贝原始ip数据包中需要的数据
    memcpy(txbuf.data + sizeof(icmp_hdr_t),recv_buf->data,sizeof(ip_hdr_t) + 8);

    //添加icmp首部
    buf_add_header(&txbuf,sizeof(icmp_hdr_t));

    icmp_hdr_t* p =(icmp_hdr_t*)txbuf.data;

    p->type = ICMP_TYPE_UNREACH;
    p->code = code;
    //先设为0
    p->checksum16 =0;
    p->id16 =0;
    p->seq16 =0;

    //计算校验和然后填入
    p->checksum16 = checksum16((uint16_t*)(txbuf.data),txbuf.len);

    ip_out(&txbuf,src_ip,NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}