#ifndef NICTRAFFIC_H
#define NICTRAFFIC_H

#include <QWidget>
#include <QChartView>
#include <QtCharts>
#include "pcap.h"
#include "QtCharts/qchartview.h"
#include "Format.h"

QT_CHARTS_USE_NAMESPACE
namespace Ui {
class NICtraffic;
}

class NICtraffic : public QWidget
{
    Q_OBJECT
public:
    explicit NICtraffic(QWidget *parent = nullptr);
    void handleMessage(DEVICE_INFO devInfo);
    void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
    ~NICtraffic();

private:
    Ui::NICtraffic *ui;
    QString deviceName;
    QString deviceDescription;

public slots:

};

#endif // NICTRAFFIC_H
