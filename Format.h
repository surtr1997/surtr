#ifndef DATAFORMAT_H
#define DATAFORMAT_H
#include <QString>

typedef unsigned char u_char;   //1
typedef unsigned short u_short; //2
typedef unsigned int u_int;     //4
typedef unsigned long u_long;   //4

typedef struct device_info {
    QString name;
    QString description;
} DEVICE_INFO;

// Ethernet protocol format
// MAC帧
/*
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/

typedef struct ether_header {
    u_char ethernet_des_host[6];    //目的地址
    u_char ethernet_src_host[6];    //源地址
    u_short type;                 //类型
} ETHER_HEADER;

// Ipv4 header
/*
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           |R|D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/

typedef struct ip_header {
    u_char version_length;  //版本
    u_char TOS;             //服务质量
    u_short total_length;   //数据包总长度
    u_short identification; //
    u_short offset;         //偏移量&标志为
    u_char ttl;             //生存时间
    u_char protocol;        //上层协议字段
    u_short checksum;       //校验和
    u_int src_addr;         //源ip地址
    u_int des_addr;         //目的ip地址
} IP_HEADER;

// Tcp header
/*
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/
typedef struct tcp_header{    // 20 byte
    u_short src_port;         // source port [2 byte]
    u_short des_port;         // destination [2 byte]
    u_int sequence;           // sequence number [4 byte]
    u_int ack;                // Confirm serial number [4 byte]
    u_char header_length;     // header length [4 bit]
    u_char flags;             // flags [6 bit]
    u_short window_size;      // size of window [2 byte]
    u_short checksum;         // checksum [2 byte]
    u_short urgent;           // urgent pointer [2 byte]
}TCP_HEADER;

// Udp header
/*
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
typedef struct udp_header{ // 8 byte
    u_short src_port;      // source port [2 byte]
    u_short des_port;      // destination port [2 byte]
    u_short data_length;   // data length [2 byte]
    u_short checksum;      // checksum [2 byte]
}UDP_HEADER;

// Icmp header
/*
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct icmp_header{         // at least 8 byte
    u_char type;                    // type [1 byte]
    u_char code;                    // code [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_short identification;         // identification [2 byte]
    u_short sequence;               // sequence [2 byte]
}ICMP_HEADER;

//Arp
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct arp_header{   // 28 byte
    u_short hardware_type;   // hardware type [2 byte]
    u_short protocol_type;   // protocol [2 byte]
    u_char mac_length;       // MAC address length [1 byte]
    u_char ip_length;        // IP address length [1 byte]
    u_short op_code;         // operation code [2 byte]

    u_char src_eth_addr[6];  // source ether address [6 byte]
    u_char src_ip_addr[4];   // source ip address [4 byte]
    u_char des_eth_addr[6];  // destination ether address [6 byte]
    u_char des_ip_addr[4];   // destination ip address [4 byte]
}ARP_HEADER;

// dns
/*
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
*/
typedef struct dns_header{  // 12 byte
    u_short identification; // Identification [2 byte]
    u_short flags;          // Flags [total 2 byte]
    u_short question;       // Question Number [2 byte]
    u_short answer;         // Answer RRs [2 byte]
    u_short authority;      // Authority RRs [2 byte]
    u_short additional;     // Additional RRs [2 byte]
}DNS_HEADER;

// dns question
typedef struct dns_question{
    // char* name;          // Non-fixed
    u_short query_type;     // 2 byte
    u_short query_class;    // 2 byte
}DNS_QUESTION;

// dns answer
typedef struct dns_answer{
    // char* name          // Non-fixed
    u_short answer_type;   // 2 byte
    u_short answer_class;  // 2 byte
    u_int TTL;             // 4 byte
    u_short dataLength;    // 2 byte
    //char* name           // Non-fixed
}DNS_ANSWER;

#endif // DATAFORMAT_H
