// NULL
// NULL
// Author: ty
// This is my wireshack

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QWidget>
#include <QDebug>
#include <QVector>
#include <iphlpapi.h>
#include "dataflow.h"
#include "nictraffic.h"
#include "winsock2.h"
#include "pcap.h"
#include "datapackage.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    //显示网卡信息到combobox
    void ShowNetworkCard();
    //判别选中设备是否可使用，数据链路层协议是否为以太网协议
    int TestDevice();
    PIP_ADAPTER_INFO getAllDev();

    //通过设备名获取设备描述
    QString getDeviceDescription(QString devName);

public slots:
    void HandleMessage(datapackage data);

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);

signals:
    void sendTotalData(unsigned long long totalData);

private:
    Ui::MainWindow *ui;
    dataflow* dataFlowWidget;
    NICtraffic* nicTrafficWidget;

    pcap_if_t* all_device;
    pcap_if_t* device;
//    PIP_ADAPTER_INFO* all_device;
//    PIP_ADAPTER_INFO* device;
    pcap_t* device_pointer;
    QVector<datapackage>pData;

    int countNumber;
    int rowNumber;
    char errbuf[PCAP_ERRBUF_SIZE];

    unsigned long long totolDatalength;

    //WINAPI获取的设备名、设备描述
    typedef struct all_device_info {
        QString name;
        QString description;
    } ALL_DEVICE_INFO;
    QVector<all_device_info>allDeviceDescription;
};
#endif // MAINWINDOW_H
