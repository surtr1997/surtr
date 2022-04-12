#include <QDebug>
#include <QChart>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "capturethread.h"

using namespace QT_CHARTS_NAMESPACE;
using namespace std;
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    resize(QSize(1100, 800));
    statusBar()->showMessage("欢迎使用wireshark!");
    countNumber = 0;
    rowNumber = -1;
    totolDatalength = 0;

    //在工具栏添加按钮，禁用工具栏移动
    ui->toolBar->addSeparator();
    ui->toolBar->addAction(ui->actionrun_stop);
    ui->toolBar->addAction(ui->actiondataflow);
    ui->toolBar->addAction(ui->actionclear);
    ui->toolBar->addSeparator();
    ui->toolBar->addAction(ui->actionup);
    ui->toolBar->addAction(ui->actiondown);
    ui->toolBar->addSeparator();
    ui->toolBar->addAction(ui->actiontop);
    ui->toolBar->addAction(ui->actionend);
    ui->toolBar->setMovable(false);

    //设置表格行高为30px,列数为7
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->tableWidget->setColumnCount(7);
    QStringList title = {"No.", "Time", "Source", "Destnation", "Protocol", "Length", "Info"};
    ui->tableWidget->setHorizontalHeaderLabels((title));
    ui->tableWidget->setColumnWidth(0, 100);
    ui->tableWidget->setColumnWidth(1, 100);
    ui->tableWidget->setColumnWidth(2, 180);
    ui->tableWidget->setColumnWidth(3, 180);
    ui->tableWidget->setColumnWidth(4, 100);
    ui->tableWidget->setColumnWidth(5, 100);
    ui->tableWidget->setColumnWidth(6, 300);
    ui->tableWidget->setShowGrid(false);    //网格线不可见
    ui->tableWidget->verticalHeader()->setVisible(false);   //隐藏表格编号
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);   //自动选中所在行
    //表格内容不可修改
    ui->treeWidget->setHeaderHidden(true);

    ShowNetworkCard();

    capturethread* capture_thread = new capturethread;
    static bool index = false; //run_stop按钮状态变量
    connect(ui->actionrun_stop, &QAction::triggered, this, [=](){
        index = !index;//置反run_stop开关状态
        //statusBar()->clearMessage();
        if (index == true) {
            //清空之前内容，行数清零，数据包计数器清零
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            countNumber = 0;
            totolDatalength = 0;

            //释放数据包qvector内存
            int dataSize = 0;
            for (int i = 0; i < dataSize; i++) {
                free((char*)(this->pData[i].pkt_content));
                this->pData[i].pkt_content = nullptr;
            }
            QVector<datapackage>().swap(pData);

            //开关为开启状态，调用TestDevice方法
            int res = TestDevice();

            if (res != -1 && device_pointer) {
                capture_thread->setPointer(device_pointer);
                capture_thread->setIsDoneFlag();
                capture_thread->start();
                ui->actionrun_stop->setIcon(QIcon(":/停止.png"));
                ui->comboBox->setEnabled(false);
                statusBar()->showMessage(tr("抓包中..."), 5000);
                ui->actionclear->setEnabled(false);
            } else {
                index = !index;
                countNumber = 0;
            }
        } else {
            capture_thread->resetIsDoneFlag();
            capture_thread->quit();
            capture_thread->wait();
            ui->actionrun_stop->setIcon(QIcon(":/运行.png"));
            ui->comboBox->setEnabled(true);
            ui->actionclear->setEnabled(true);
            statusBar()->showMessage(tr("停止抓包"), 5000);
            pcap_close(device_pointer);
            device_pointer = nullptr;
        }
    });

    //流量波形图
    connect(ui->actiondataflow,&QAction::triggered,this,[=]{
        if (device != nullptr) {
            dataFlowWidget = new dataflow();
            dataFlowWidget->setWindowModality(Qt::ApplicationModal);

            QString device_name = device->name;//获取设备名
            QString device_description = getDeviceDescription(device_name);//获取完整设备描述
            dataFlowWidget->setDevName(device_description);
            connect(this, &MainWindow::sendTotalData, dataFlowWidget, &dataflow::recvTotalData);
            dataFlowWidget->show();
        }else return;
    });

    connect(ui->actionclear,&QAction::triggered,this,[=]{
        if(!index){
            //清空之前内容，行数清零，数据包计数器清零
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            countNumber = 0;
            totolDatalength = 0;

            //释放数据包qvector内存
            int dataSize = 0;
            for (int i = 0; i < dataSize; i++) {
                free((char*)(this->pData[i].pkt_content));
                this->pData[i].pkt_content = nullptr;
            }
            QVector<datapackage>().swap(pData);
        }else return;
    });

    connect(ui->actionup,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(index - 1,0);
            on_tableWidget_cellClicked(index - 1,0);
        }else return;
    });

    connect(ui->actiondown,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index >= 0 && index < ui->tableWidget->rowCount() - 1){
            ui->tableWidget->setCurrentCell(index + 1,0);
            on_tableWidget_cellClicked(index + 1,0);
        }else return;
    });

    connect(ui->actiontop,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->currentRow();
        if(index > 0){
            ui->tableWidget->setCurrentCell(0,0);
            on_tableWidget_cellClicked(0,0);
        }else return;
    });

    connect(ui->actionend,&QAction::triggered,this,[=]{
        int index = ui->tableWidget->rowCount()-1;
        if(index > 0){
            ui->tableWidget->setCurrentCell(index,0);
            on_tableWidget_cellClicked(index,0);
        }else return;
    });

    connect(capture_thread, &capturethread::send, this, &MainWindow::HandleMessage);
}

MainWindow::~MainWindow()
{
    int dataSize = pData.size();
    for (int i = 0; i < dataSize; i++) {
        free((char*)(this->pData[i].pkt_content));
        this->pData[i].pkt_content = nullptr;
    }
    QVector<datapackage>().swap(pData);
    delete ui;
}

QString MainWindow::getDeviceDescription(QString devName){
    QString devDes = "";
    for (int i =0; i < allDeviceDescription.size(); i++) {
        if (devName.contains(allDeviceDescription[i].name))
            devDes = allDeviceDescription[i].description;
    }
    return devDes;
}

//检索设备，显示网卡设备到combobox
void MainWindow::ShowNetworkCard() {
    //检索网卡,成功返回设备链表，失败返回-1
    int if_find_device = pcap_findalldevs(&all_device, errbuf);
    if (if_find_device == -1) {
        //失败，展示检索网卡错误信息
        ui->comboBox->addItem("error");
        statusBar()->showMessage("无法获取网卡列表 error: " + QString(errbuf), 5000);
        return;
    } else {
        //成功，展示所有网卡设备
        ui->comboBox->clear();
        ui->comboBox->addItem("pls choose card!");
        QVariant v(0);
        ui->comboBox->setItemData(0, v, Qt::UserRole - 1);

        //通过WINAPI获取完整设备描述，供combobox展示
        PIP_ADAPTER_INFO pAdapterInfo = this->getAllDev();
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        ALL_DEVICE_INFO devDes;
        for (pAdapter = pAdapterInfo; pAdapter != nullptr; pAdapter = pAdapter->Next) {
            devDes.name = pAdapter->AdapterName;
            devDes.description = pAdapter->Description;
            allDeviceDescription.append(devDes);
        }

        for (device = all_device; device != nullptr; device = device->next){
            QString device_name = device->name;//获取设备名
            //device_name.replace("\\Device\\NPF_", "");//更改设备名前缀，去除冗余
            QString device_description = getDeviceDescription(device_name);//获取完整设备描述
            QString device_item = (device_name + " " + device_description);//组合设备名、设备描述
            QPixmap icon  = style()->standardPixmap(QStyle::SP_DriveNetIcon);
            ui->comboBox->addItem(icon, device_item);//显示网卡设备信息到combobox
        }
        statusBar()->showMessage(tr("成功获取网卡列表"), 5000);

        //allDeviceDescription.clear();
        if (pAdapterInfo)
        {
            free(pAdapterInfo);
        }
    }
}

//device指向combobox选中的设备
void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int device_count = 0;
    if (index != 0)
        for (device = all_device; device_count++ < index - 1; device = device->next);
    //printf("device_count = %d\n", device_count);
    return;
}

//测试网卡是否可用
int MainWindow::TestDevice() {
    //检测选中设备是否可用
    if (device) {
        device_pointer = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    } else {
        statusBar()->showMessage("未检索到设备", 5000);
        return -1;
    }
    //检测选中设备指针是否可用，若失败，释放空间
    if (device_pointer == nullptr) {
        statusBar()->showMessage("捕获设备失败 error:" + QString(errbuf), 5000);
        pcap_freealldevs(all_device);
        device = nullptr;
        return -1;
    } else {
        //判断选中设备数据链路层协议是否为以太网协议,若失败，释放空间
        if (pcap_datalink(device_pointer) != DLT_EN10MB) {
            pcap_close(device_pointer);
            pcap_freealldevs(all_device);
            //device_pointer = nullptr;
            device = nullptr;
            statusBar()->showMessage("设备异常", 5000);
            return -1;
        }
        //成功后，设置窗口状态栏，展示通过检测的网卡名
        statusBar()->showMessage(tr("捕获设备成功"), 5000);
    }

    return 0;
}

void MainWindow::HandleMessage(datapackage data){
    ui->tableWidget->insertRow(countNumber);
    this->pData.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    if (type == "TCP")
        color = QColor(216, 191, 216);
    else if (type == "UDP")
        color = QColor(144, 238, 144);
    else if (type == "ARP")
        color = QColor(238, 238, 0);
    else if (type == "DNS")
        color = QColor(255, 255, 224);
    else if (type == "TLS" || type == "SSL")
        color = QColor(210, 149, 210);
    else
        color = QColor(255, 218, 185);
    ui->tableWidget->setItem(countNumber, 0, new QTableWidgetItem(QString::number(countNumber)));
    ui->tableWidget->setItem(countNumber, 1, new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(countNumber, 2, new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(countNumber, 3, new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber, 4, new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber, 5, new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber, 6, new QTableWidgetItem(data.getInfo()));
    totolDatalength += data.getDataLength().toInt();
    emit sendTotalData(totolDatalength);
    for (int i = 0; i < 7; i++) {
        ui->tableWidget->item(countNumber, i)->setBackgroundColor(color);
    }
    countNumber++;
}

void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if (row == rowNumber || row < 0)
        return;
    ui->treeWidget->clear();
    rowNumber = row;
    if (rowNumber < 0 || rowNumber > countNumber)
        return;
    QString desMac = pData[rowNumber].getDestination();
    QString srcMac = pData[rowNumber].getSource();
    QString type = pData[rowNumber].getMacType();
    QString tree = "Ethernet,Src:" + srcMac + " Des:" + desMac;
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList() << tree);
    ui->treeWidget->addTopLevelItem(item);
    item->addChild(new QTreeWidgetItem(QStringList() << "Destination:" + desMac));
    item->addChild(new QTreeWidgetItem(QStringList() << "Source:" + srcMac));
    item->addChild(new QTreeWidgetItem(QStringList() << "Type:" + type));
}


PIP_ADAPTER_INFO MainWindow::getAllDev()
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
