/*
 * Copyright (c) 2025 TU Dresden
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Mingyu Ma <mingyu.ma@tu-dresden.de>
 * Authors: Xi Cheng <>
 */

/**
 *          ┌────────────────┐
 *          │    Switch 0    │
 *          └─▲────────────┬─┘
 *            │            │
 *  ┌─────────┼─┐        ┌─▼─────────┐
 *  │  Host 1   │        │  Host     │
 *  └───────────┘        └───────────┘
 */

#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/core-module.h"
#include "ns3/custom-p2p-net-device.h"
#include "ns3/format-utils.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/p4-helper.h"
#include "ns3/p4-p2p-helper.h"
#include "ns3/p4-topology-reader-helper.h"
#include "ns3/packet-socket-address.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/pcap-file.h"

#include <filesystem>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("P4DDOSAttack");

// 仿真时间设置
unsigned long start = getTickCount(); // 仿真实际用时计算
double global_start_time = 0.0;
double sink_start_time = global_start_time;       // sink (接受端初始化) 时间
double client_start_time = sink_start_time;       // client (发送端初始化) 时间
double client_stop_time = client_start_time + 10; // 发送时间 10s
double sink_stop_time = client_stop_time + 5;     // sink 停止时间
double global_stop_time = sink_stop_time + 5;     // 全局停止时间

// Convert IP address to hexadecimal format
std::string
ConvertIpToHex(Ipv4Address ipAddr)
{
    std::ostringstream hexStream;
    uint32_t ip = ipAddr.Get(); // Get the IP address as a 32-bit integer
    hexStream << "0x" << std::hex << std::setfill('0') << std::setw(2)
              << ((ip >> 24) & 0xFF)                 // First byte
              << std::setw(2) << ((ip >> 16) & 0xFF) // Second byte
              << std::setw(2) << ((ip >> 8) & 0xFF)  // Third byte
              << std::setw(2) << (ip & 0xFF);        // Fourth byte
    return hexStream.str();
}

// Convert MAC address to hexadecimal format
std::string
ConvertMacToHex(Address macAddr)
{
    std::ostringstream hexStream;
    Mac48Address mac = Mac48Address::ConvertFrom(macAddr); // Convert Address to Mac48Address
    uint8_t buffer[6];
    mac.CopyTo(buffer); // Copy MAC address bytes into buffer

    hexStream << "0x";
    for (int i = 0; i < 6; ++i)
    {
        hexStream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
    }
    return hexStream.str();
}

int
main(int argc, char* argv[])
{
    LogComponentEnable("P4DDOSAttack", LOG_LEVEL_INFO);

    // ============================ parameters ============================
    std::string appDataRate = "3Mbps";
    std::string ns3_link_rate = "1000Mbps";
    bool enableTracePcap = false; // 是否启用 Pcap 跟踪，捕获发送端和接收端的pcap

    // ============================ P4 文件的路径和配置 ============================
    std::string p4JsonPath = "/home/mm/ns-3-dev-git/contrib/p4sim/examples/p4src/p4_ddos/ddos.json";
    std::string flowTablePath =
        "/home/mm/ns-3-dev-git/contrib/p4sim/examples/p4src/p4_ddos/flowtable_0.txt";
    std::string topoInput = "/home/mm/ns-3-dev-git/contrib/p4sim/examples/p4src/p4_ddos/topo.txt";
    std::string topoFormat("CSMA");

    // ============================  command line ============================
    CommandLine cmd;
    cmd.AddValue("pcap", "Trace packet pacp [true] or not[false]", enableTracePcap);
    cmd.Parse(argc, argv);

    // ============================ 构建网络和配置 ============================

    P4TopologyReaderHelper p4TopoHelper;
    p4TopoHelper.SetFileName(topoInput);
    p4TopoHelper.SetFileType(topoFormat);
    NS_LOG_INFO("*** Reading topology from file: " << topoInput << " with format: " << topoFormat);

    // Get the topology reader, and read the file, load in the m_linksList.
    Ptr<P4TopologyReader> topoReader = p4TopoHelper.GetTopologyReader();

    if (topoReader->LinksSize() == 0)
    {
        NS_LOG_ERROR("Problems reading the topology file. Failing.");
        return -1;
    }

    // get switch and host node
    NodeContainer terminals = topoReader->GetHostNodeContainer();
    NodeContainer switchNode = topoReader->GetSwitchNodeContainer();

    const unsigned int hostNum = terminals.GetN();
    const unsigned int switchNum = switchNode.GetN();
    NS_LOG_INFO("*** Host number: " << hostNum << ", Switch number: " << switchNum);

    // set default network link parameter
    P4PointToPointHelper p4p2p;
    p4p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate(ns3_link_rate)));
    p4p2p.SetChannelAttribute("Delay", TimeValue(MicroSeconds(10)));

    NetDeviceContainer hostDevices;
    NetDeviceContainer switchDevices;
    P4TopologyReader::ConstLinksIterator_t iter;
    for (iter = topoReader->LinksBegin(); iter != topoReader->LinksEnd(); iter++)
    {
        NetDeviceContainer link =
            p4p2p.Install(NodeContainer(iter->GetFromNode(), iter->GetToNode()));

        if (iter->GetFromType() == 's' && iter->GetToType() == 's')
        {
            switchDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else if (iter->GetFromType() == 's' && iter->GetToType() == 'h')
        {
            switchDevices.Add(link.Get(0));
            hostDevices.Add(link.Get(1));
        }
        else if (iter->GetFromType() == 'h' && iter->GetToType() == 's')
        {
            hostDevices.Add(link.Get(0));
            switchDevices.Add(link.Get(1));
        }
        else
        {
            NS_LOG_ERROR("link error!");
            abort();
        }
    }

    // ========================打印网络配置，检查是否正确========================

    InternetStackHelper internet;
    internet.Install(terminals);
    internet.Install(switchNode);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    std::vector<Ipv4InterfaceContainer> terminalInterfaces(hostNum);
    std::vector<std::string> hostIpv4(hostNum);

    for (unsigned int i = 0; i < hostNum; i++)
    {
        terminalInterfaces[i] = ipv4.Assign(terminals.Get(i)->GetDevice(0));
        hostIpv4[i] = Uint32IpToHex(terminalInterfaces[i].GetAddress(0).Get());
    }

    NS_LOG_INFO("Node IP and MAC addresses:");
    for (uint32_t i = 0; i < terminals.GetN(); ++i)
    {
        Ptr<Node> node = terminals.Get(i);
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        Ptr<NetDevice> netDevice = node->GetDevice(0);

        // Get the IP address
        Ipv4Address ipAddr =
            ipv4->GetAddress(1, 0)
                .GetLocal(); // Interface index 1 corresponds to the first assigned IP

        // Get the MAC address
        Ptr<NetDevice> device = node->GetDevice(0); // Assuming the first device is the desired one
        Mac48Address mac = Mac48Address::ConvertFrom(device->GetAddress());

        NS_LOG_INFO("Node " << i << ": IP = " << ipAddr << ", MAC = " << mac);

        // Convert to hexadecimal
        std::string ipHex = ConvertIpToHex(ipAddr);
        std::string macHex = ConvertMacToHex(mac);
        NS_LOG_INFO("Node " << i << ": IP = " << ipHex << ", MAC = " << macHex);
    }

    // ========================配置 P4 交换机 Switch NetDevice========================
    P4Helper p4SwitchHelper;
    p4SwitchHelper.SetDeviceAttribute("JsonPath", StringValue(p4JsonPath));
    p4SwitchHelper.SetDeviceAttribute("EnableTracing", BooleanValue(true));
    p4SwitchHelper.SetDeviceAttribute("FlowTablePath", StringValue(flowTablePath));
    p4SwitchHelper.SetDeviceAttribute("ChannelType", UintegerValue(1)); // P2P channel
    p4SwitchHelper.SetDeviceAttribute("SwitchRate", UintegerValue(1200));
    p4SwitchHelper.SetDeviceAttribute("QueueBufferSize", UintegerValue(1000));
    p4SwitchHelper.SetDeviceAttribute("P4SwitchArch",
                                      UintegerValue(0)); // v1model 0, psa 1, pna 2

    for (unsigned int i = 0; i < switchNum; i++)
    {
        p4SwitchHelper.Install(switchNode.Get(i), switchDevices);
    }

    // ======================== 配置 P4 终端设备 （发送端，接收端） ========================
    unsigned int serverI = 1;
    unsigned int clientI = 0;
    uint16_t servPort = 2000; // UDP port for the server

    // === 在客户端节点（h0）上配置 PacketSocket ===
    Ptr<Node> clientNode = terminals.Get(clientI);
    PacketSocketHelper packetSocket;
    packetSocket.Install(clientNode);

    // === 创建 PacketSocketAddress（直接绑定到网卡） ===
    PacketSocketAddress socketAddr;
    Ptr<Node> serverNode = terminals.Get(serverI);
    socketAddr.SetSingleDevice(clientNode->GetDevice(0)->GetIfIndex());
    socketAddr.SetPhysicalAddress(serverNode->GetDevice(0)->GetAddress()); // 目标 MAC 地址
    socketAddr.SetProtocol(0x0800);                                        // IPv4 协议号

    // === 使用 PcapFile 读取 PCAP 文件并发送 ===
    PcapFile pcapFile;
    pcapFile.Open("input.pcap", std::ios::in);

    uint32_t tsSec, tsUsec, inclLen, origLen, readLen;
    uint8_t data[65536]; // 最大支持 64KB 的数据包

    Time prevTime = Seconds(0);
    while (true)
    {
        // 读取 PCAP 记录头和数据
        pcapFile.Read(data, sizeof(data), tsSec, tsUsec, inclLen, origLen, readLen);
        if (pcapFile.Fail())
            break; // 文件结束或错误

        // 创建 NS-3 数据包
        Ptr<Packet> packet = Create<Packet>(data, readLen);

        // 计算时间间隔（PCAP 文件中的时间戳是相对于第一个包的）
        Time currentTime = Seconds(tsSec) + MicroSeconds(tsUsec);
        Time delay = (prevTime == Seconds(0)) ? Seconds(0) : (currentTime - prevTime);
        prevTime = currentTime;

        // 调度发送（自动按照 PCAP 的时间间隔发送）
        Simulator::Schedule(delay,
                            &PacketSocket::SendTo,
                            clientNode->GetObject<PacketSocket>(),
                            packet,
                            0,
                            socketAddr);
    }
    pcapFile.Close();

    // Normal Stream (生成的虚拟流量) == Second == send link h0 -----> h1
    servPort = 3000; // change the application port
    Ptr<Ipv4> ipv4_adder = serverNode->GetObject<Ipv4>();
    Ipv4Address serverAddr1 = ipv4_adder->GetAddress(1, 0).GetLocal();
    InetSocketAddress dst2 = InetSocketAddress(serverAddr1, servPort);
    PacketSinkHelper sink2 = PacketSinkHelper("ns3::UdpSocketFactory", dst2);
    ApplicationContainer sinkApp2 = sink2.Install(terminals.Get(serverI));

    sinkApp2.Start(Seconds(sink_start_time));
    sinkApp2.Stop(Seconds(sink_stop_time));

    OnOffHelper onOff2("ns3::UdpSocketFactory", dst2);
    onOff2.SetAttribute("DataRate", StringValue(appDataRate));
    onOff2.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onOff2.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer app2 = onOff2.Install(terminals.Get(clientI));
    app2.Start(Seconds(client_start_time));
    app2.Stop(Seconds(client_stop_time));

    // 捕获pcap文件，查看是否正确
    if (enableTracePcap)
    {
        p4p2p.EnablePcapAll("p4-ddos-attack");
    }

    // 配置完成，开始进行仿真！
    NS_LOG_INFO("Running simulation...");
    unsigned long simulate_start = getTickCount();
    Simulator::Stop(Seconds(global_stop_time));
    Simulator::Run();
    Simulator::Destroy();

    // 统计一下仿真用的时间！
    unsigned long end = getTickCount();
    NS_LOG_INFO("Simulate Running time: " << end - simulate_start << "ms" << std::endl
                                          << "Total Running time: " << end - start << "ms"
                                          << std::endl
                                          << "Run successfully!");

    return 0;
}
