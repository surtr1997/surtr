#include <pcap.h>
#include <QDebug>
#include "winsock2.h"
#include "dataflow.h"
#include "ui_dataflow.h"

#define TIMER_INERVAL 200

dataflow::dataflow(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::dataflow)
{
    ui->setupUi(this);

    devName = "";
    totalDataOfKB = 0;
    totalDataOfMB = 0;
    oldTotalDataOfMB = 0;
    insDataOfMB = 0;

    timer = new QTimer(this);                               //创建定时器
    connect(timer,SIGNAL(timeout()),this,SLOT(DrawLine())); //连接定时器与定时溢出处理槽函数

    initDraw();
    timer->start();
    timer->setInterval(TIMER_INERVAL);
}

dataflow::~dataflow()
{
    delete ui;
}

void dataflow::get_device_vector(){
    //检索网卡,成功返回设备链表，失败返回-1
    int if_find_device = pcap_findalldevs(&all_device, errbuf);
    if (if_find_device == -1) //失败
        return;
    else { //成功tong
        //通过WINAPI获取设备名、设备描述
        PIP_ADAPTER_INFO pAdapterInfo = this->getAllDev();
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        DEVICE_INFO devDes;
        for (pAdapter = pAdapterInfo; pAdapter != nullptr; pAdapter = pAdapter->Next) {
            devDes.name = pAdapter->AdapterName;
            devDes.name.prepend("\\Device\\NPF_\n");
            devDes.description = pAdapter->Description;
            qDebug() << devDes.name + " " + devDes.description;
            deviceInfo.append(devDes);
        }
    }
}

PIP_ADAPTER_INFO dataflow::getAllDev()
{
    PIP_ADAPTER_INFO pAdapterInfo;
    DWORD dwRetVal;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    pAdapterInfo = (PIP_ADAPTER_INFO)malloc(ulOutBufLen);
    if (!pAdapterInfo)
    {
        return nullptr;
    }

    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    // 第一次调用GetAdapterInfo获取ulOutBufLen大小
    if (ERROR_BUFFER_OVERFLOW == dwRetVal)
    {
        free(pAdapterInfo);
        pAdapterInfo  = (PIP_ADAPTER_INFO)malloc(ulOutBufLen);
        if (!pAdapterInfo)
        {
            return nullptr;
        }
        dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    }
    if (NO_ERROR == dwRetVal)
    {
        return pAdapterInfo;
    }

    if (pAdapterInfo != nullptr)
    {
        free(pAdapterInfo);
    }
    return nullptr;
}

void dataflow::setDevPointer(pcap_if_t* device){
    this->device = device;
}

void dataflow::setDevName(QString devName){
    this->devName = devName;
    ui->deviceName->setText(this->devName);
}

void dataflow::recvTotalData(unsigned long long totalData){
    totalDataOfKB = float(totalData)/1024; //B转化为KB
    totalDataOfMB = float(totalData)/1024/1024; //KB转化为MB
}

//初始化画布
void dataflow::initDraw()
{
    QPen penY(Qt::gray,1,Qt::SolidLine,Qt::FlatCap,Qt::RoundJoin);
    chart = new QChart();
    series = new QSplineSeries;
    axisX = new QDateTimeAxis();
    axisY = new QValueAxis();

    chart->legend()->hide();                           //隐藏图例
    chart->addSeries(series);                          //把线添加到chart
//    axisX->setTickCount(10);                           //设置坐标轴格数
//    axisY->setTickCount(5);
    axisX->setFormat("hh:mm:ss");                      //设置时间显示格式
    axisY->setMin(0);                                  //设置Y轴范围
    axisY->setMax(20);
//    axisX->setTitleText("实时时间");                     //设置X轴名称
    series->setColor(QColor(Qt::blue));

    //axisY->setLinePenColor(QColor(Qt::black));      //设置坐标轴颜色样式
    //axisX->setLinePenColor(QColor(Qt::black));
    axisY->setGridLineVisible(false);                  //设置XY轴网格不显示
    axisX->setGridLineVisible(false);
    axisY->setLinePen(penY);
    axisX->setLinePen(penY);

    chart->addAxis(axisX,Qt::AlignBottom);             //设置坐标轴位于chart中的位置
    chart->addAxis(axisY,Qt::AlignLeft);

    series->attachAxis(axisX);                         //把数据添加到坐标轴上
    series->attachAxis(axisY);

    axisY->setTitleText("MB/s");

    //把chart显示到窗口上
    ui->QChartview1->setChart(chart);
    ui->QChartview1->setRenderHint(QPainter::Antialiasing); //设置抗锯齿
}

//画数据、动态更新数据
void dataflow::DrawLine()
{
    QDateTime currentTime = QDateTime::currentDateTime();
    //设置坐标轴显示范围
    chart->axisX()->setMin(QDateTime::currentDateTime().addSecs(-60 * 1));       //系统当前时间的前一秒
    chart->axisX()->setMax(QDateTime::currentDateTime().addSecs(0));            //系统当前时间

    //增加新的点到曲线末端
    insDataOfMB = (totalDataOfMB - oldTotalDataOfMB)*(1000/TIMER_INERVAL);
    if (insDataOfMB >= 20)
        axisY->setMax(40);
    series->append(currentTime.toMSecsSinceEpoch(), insDataOfMB);
    QString insDataStr = QString::number(insDataOfMB, 'f', 2);
    ui->insData->setText("吞吐量: " + insDataStr + "  MB/S");
    oldTotalDataOfMB = totalDataOfMB;
}
