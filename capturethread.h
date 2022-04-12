#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread>
#include <QDebug>
#include "pcap.h"
#include "datapackage.h"

class capturethread:public QThread
{
    Q_OBJECT
public:
    capturethread();
    bool setPointer(pcap_t *device_pointer);//传入设备描述符
    void setIsDoneFlag();       //设置开关
    void resetIsDoneFlag();     //设置开关
    void run() override;
    QString byteToString(u_char *str, int size);

    int ethernetPackageHandle(const u_char* pkt_content, QString &info);    //MAC帧处理
    int ipPackageHandle(const u_char* pkt_content, int &ipPackage);         //IP帧处理
    int tcpPackageHandle(const u_char* pkt_content, QString &info, int ipPackage);  //TCP包处理
    int udpPackageHandle(const u_char* pkt_content, QString &info);         //UDP包处理
    QString dnsPackageHandle(const u_char* pkt_content);                    //DNS解析
    QString arpPackageHandle(const u_char* pkt_content);                    //ARP解析
    QString icmpPackageHandle(const u_char* pkt_content);                   //ICMP解析

signals:
    void send(datapackage data);

private:
    pcap_t* device_pointer;     //设备描述符
    struct pcap_pkthdr* header; //数据包头
    const u_char* pkt_data;     //数据包内容
    time_t local_time_sec;      //时间戳
    struct tm local_time;       //时间戳结构体
    char timeString[16];        //时间字符串格式
    bool isDone;                //线程开关
};

#endif // CAPTURETHREAD_H
