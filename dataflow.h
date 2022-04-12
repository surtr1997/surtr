#ifndef DATAFLOW_H
#define DATAFLOW_H

#include <QWidget>
#include <QVector>
#include <iphlpapi.h>
#include <QValueAxis>
#include <QTimer>
#include <QDateTimeAxis>
#include <QtCharts/QSplineSeries>
#include <QtCharts/QChartView>
#include "pcap.h"
#include "winsock2.h"
#include "nictraffic.h"
#include "Format.h"
#include "QDateTime"

QT_CHARTS_USE_NAMESPACE

namespace Ui {
class dataflow;
}

class dataflow : public QWidget
{
    Q_OBJECT

public:
    explicit dataflow(QWidget *parent = nullptr);
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct timeval st_ts;
    u_int netmask;
    struct bpf_program fcode;
    QVector<DEVICE_INFO>deviceInfo;

    void setDevPointer(pcap_if_t* device);
    void setDevName(QString devName);
    ~dataflow();

    void initDraw();            //初始化画布

public slots:
    void recvTotalData(unsigned long long totalData);
    void DrawLine();            //画线

signals:
    void send(DEVICE_INFO);

private:
    Ui::dataflow *ui;
    pcap_if_t* all_device;
    pcap_if_t* device;
    QString devName;
    void get_device_vector();
    PIP_ADAPTER_INFO getAllDev();

    float totalDataOfKB;
    float totalDataOfMB;
    float oldTotalDataOfMB;
    float insDataOfMB;

    QTimer *timer;              //计时器
    QChart *chart;              //画布
    QSplineSeries *series;      //线
    QDateTimeAxis *axisX;       //轴
    QValueAxis *axisY;

    QList<NICtraffic*>list_NICtraffic;
};

#endif // DATAFLOW_H
