#include <string>
#include <iostream>
#include "winsock2.h"
#include "nictraffic.h"
#include "ui_nictraffic.h"

using namespace std;

NICtraffic::NICtraffic(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::NICtraffic)
{
    ui->setupUi(this);

//    deviceName = "";
//    deviceDescription = "";

//    pcap_t *fp;
//    char errbuf[PCAP_ERRBUF_SIZE];
//    struct timeval st_ts;
//    u_int netmask;
//    struct bpf_program fcode;

//    pcap_if_t *alldevs;
//    pcap_if_t *d;
//    int inum;
//    int i=0;
//    pcap_t *adhandle;
//    char packet_filter[] = "ip and udp";

//    /* 打开输出适配器 */
//    if ( (fp= pcap_open(deviceName, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf) ) == NULL)
//    {
//        fprintf(stderr,"\nUnable to open adapter %s.\n", errbuf);
//        return;
//    }

//    /* 不用关心掩码，在这个过滤器中，它不会被使用 */
//    netmask=0xffffff;

//    //设置过滤器
//    if (pcap_setfilter(fp, &fcode)<0)
//    {
//        fprintf(stderr,"\nError setting the filter.\n");
//        pcap_close(fp);
//        /* 释放设备列表 */
//        return;
//    }

//    /* 将接口设置为统计模式 */
//    if (pcap_setmode(fp, MODE_STAT)<0)
//    {
//        fprintf(stderr,"\nError setting the mode.\n");
//        pcap_close(fp);
//        /* 释放设备列表 */
//        return;
//    }

//    printf("TCP traffic summary:\n");

    /* 开始主循环 */
    //pcap_loop(fp, 0, dispatcher_handler, (PUCHAR)&st_ts);

    //pcap_close(fp);
//    this->resize(400, 80);
//    ui->label->setMaximumSize(300, 50);
//    ui->label->setMaximumSize(300, 50);
//    ui->QChartView1->setMaximumSize(200, 100);
//    ui->QChartView1->setMinimumSize(200, 100);
//    //ui->QChartView1->resize(200,25);

//    QLineSeries* line1 = new QLineSeries();
//    for(double x=0;x<10;x+=1)
//    {
//        line1->append(x,sin(x));
//    }
//    QChart* c = new QChart();
//    c->addSeries(line1);
//    ui->QChartView1->setChart(c);
}

NICtraffic::~NICtraffic()
{
    delete ui;
}

void NICtraffic::handleMessage(DEVICE_INFO devInfo){
    deviceDescription = devInfo.description;
    deviceName = devInfo.name;
    ui->label->setText(deviceDescription);
}

void NICtraffic::dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct timeval *old_ts = (struct timeval *)state;
    u_int delay;
    LARGE_INTEGER Bps,Pps;
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 以毫秒计算上一次采样的延迟时间 */
    /* 这个值通过采样到的时间戳获得 */
    delay=(header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
    /* 获取每秒的比特数b/s */
    Bps.QuadPart=(((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
    /*                                            ^      ^
                                                  |      |
                                                  |      |
                                                  |      |
                              将字节转换成比特 --   |
                                                         |
                                       延时是以毫秒表示的 --
    */

    /* 得到每秒的数据包数量 */
    Pps.QuadPart=(((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));

    /* 将时间戳转化为可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* 打印时间戳*/
    printf("%s ", timestr);

    /* 打印采样结果 */
    printf("BPS=%I64u ", Bps.QuadPart);
    printf("PPS=%I64u\n", Pps.QuadPart);

    //存储当前的时间戳
    old_ts->tv_sec=header->ts.tv_sec;
    old_ts->tv_usec=header->ts.tv_usec;
}
