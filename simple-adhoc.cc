/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 The Boeing Company
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
 */

// 
// This script configures two nodes on an 802.11b physical layer, with
// 802.11b NICs in adhoc mode, and by default, sends one packet of 1000 
// (application) bytes to the other node.  The physical layer is configured
// to receive at a fixed RSS (regardless of the distance and transmit
// power); therefore, changing position of the nodes has no effect. 
//
// There are a number of command-line options available to control
// the default behavior.  The list of available command-line options
// can be listed with the following command:
// ./waf --run "wifi-simple-adhoc --help"
//
// For instance, for this configuration, the physical layer will
// stop successfully receiving packets when rss drops below -97 dBm.
// To see this effect, try running:
//
// ./waf --run "wifi-simple-adhoc --rss=-97 --numPackets=20"
// ./waf --run "wifi-simple-adhoc --rss=-98 --numPackets=20"
// ./waf --run "wifi-simple-adhoc --rss=-99 --numPackets=20"
//
// Note that all ns-3 attributes (not just the ones exposed in the below
// script) can be changed at command line; see the documentation.
//
// This script can also be helpful to put the Wifi layer into verbose
// logging mode; this command will turn on all wifi logging:
// 
// ./waf --run "wifi-simple-adhoc --verbose=1"
//
// When you are done, you will notice two pcap trace files in your directory.
// If you have tcpdump installed, you can try this:
//
// tcpdump -r wifi-simple-adhoc-0-0.pcap -nn -tt
//

#include "ns3/core-module.h"
#include "ns3/event-id.h"
#include "ns3/simulator.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/netanim-module.h"
#include "ns3/ptr.h"
#include "ns3/packet.h"
#include "ns3/header.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace ns3;

class MyHeader : public Header 
{
public:

  MyHeader ();
  virtual ~MyHeader ();

  void SetData (uint16_t data);
  uint16_t GetData (void) const;

  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;
  virtual void Print (std::ostream &os) const;
  virtual void Serialize (Buffer::Iterator start) const;
  virtual uint32_t Deserialize (Buffer::Iterator start);
  virtual uint32_t GetSerializedSize (void) const;
private:
  uint16_t m_data;
};

MyHeader::MyHeader ()
{
  // default constructor
}
MyHeader::~MyHeader ()
{}

TypeId 
MyHeader::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::MyHeader")
    .SetParent<Header> ()
    ;
  return tid;
}
TypeId 
MyHeader::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void 
MyHeader::Print (std::ostream &os) const
{
  os << "data=" << m_data << std::endl;
}
uint32_t
MyHeader::GetSerializedSize (void) const
{
  return 2;
}
void
MyHeader::Serialize (Buffer::Iterator start) const
{
  start.WriteHtonU16 (m_data);
}
uint32_t
MyHeader::Deserialize (Buffer::Iterator start)
{
  m_data = start.ReadNtohU16 ();
  return 2;
}

void 
MyHeader::SetData (uint16_t data)
{
  m_data = data;
}
uint16_t 
MyHeader::GetData (void) const
{
  return m_data;
}

class MyReceiver
{

public: 
  MyReceiver (Ptr<Node> node, TypeId tid);
  Ptr<Socket> GetSocket ();
  void SetData (std::string m_value);
  std::string GetData ();
  //virtual ~MyReceiver ();
  void Bind (InetSocketAddress local);
  void Receive (Callback<void, Ptr<Socket> > ReceivePacket);
  void ReceivePacket (Ptr<Socket> socket);
  void Send (Ptr<Packet> msg);
  void SayHello (uint32_t pktCount, Time pktInterval);
  void SayMessage (uint32_t pktCount, Time interval);
  void SayKey (uint32_t pktCount, Time interval);
  Ptr<Node> GetNode ();
  uint16_t GetCurrKeyNum();
private:
  std::string m_data;
  Ptr<Socket> mySocket;
  Ptr<Node> myNode;
  TypeId mytid;
  uint16_t currentKeyNum;
};

MyReceiver::MyReceiver (Ptr<Node> node, TypeId tid)
{
  this -> myNode = node;
  this -> mytid = tid;
  this -> mySocket = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
  this -> Bind(local);
  InetSocketAddress remote = InetSocketAddress (Ipv4Address ("255.255.255.255"), 80);
  this -> mySocket ->SetAllowBroadcast (true);
  this -> mySocket -> Connect (remote);
  this -> m_data = "";
}

uint16_t
MyReceiver::GetCurrKeyNum ()
{
  return this -> currentKeyNum;
}

Ptr<Node>
MyReceiver::GetNode ()
{
  return this -> myNode;
}
void
MyReceiver::Receive (Callback<void, Ptr<Socket> > ReceivePacket)
{
    this -> mySocket -> SetRecvCallback (ReceivePacket);
}

void
MyReceiver::Bind (InetSocketAddress local)
{
    this -> mySocket -> Bind (local);
}

Ptr<Socket>
MyReceiver::GetSocket ()
{
    return MyReceiver::mySocket;
}

void
MyReceiver::SetData (std::string m_value)
{
  this -> m_data = m_value;
}

std::string MyReceiver::GetData() 
{
  return this -> m_data;
}

NS_LOG_COMPONENT_DEFINE ("WifiSimpleAdhoc");

void 
MyReceiver::ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  while ( packet = socket->Recv ())
    {

      packet->Print(std::cout);
      MyHeader nodeID, packetType;
      packet -> RemoveHeader(packetType);
      if (packetType.GetData() != (uint16_t) 1)
      {
        packet -> RemoveHeader(nodeID); //for hello message, this is sender. for key message, this is receiver
      }
      if (packetType.GetData() != (uint16_t) 0)
      {
        MyHeader keyNum;
        packet -> RemoveHeader(keyNum);
    NS_LOG_UNCOND ("key: "<< keyNum.GetData());
      }
    NS_LOG_UNCOND ("sender: "<< nodeID.GetData());
    NS_LOG_UNCOND ("type: "<< packetType.GetData());
/*
      uint8_t *outBuf = new uint8_t [packet -> GetSize()];
      packet->CopyData (outBuf, packet -> GetSize());
      
      std::ostringstream convert;
      for (uint32_t a = 0; a < packet -> GetSize(); a++) {
          convert << outBuf[a];
      }

      std::string output = convert.str();
      //uint32_t nodeID = socket -> GetNode()->GetId();
      this -> SetData (output);
//      NS_LOG_UNCOND (output );
*/
    }
} 

void MyReceiver::Send (Ptr<Packet> msg)
{
  this -> mySocket -> Send(msg);
}

void MyReceiver::SayHello (uint32_t pktCount, Time interval)
{
  MyHeader encHeader;
  encHeader.SetData(this -> mySocket ->GetNode () -> GetId ());
  MyHeader packetType;
  packetType.SetData((uint16_t) 0);
  Ptr<Packet> helloMsg = Create<Packet> (100);
  helloMsg -> AddHeader(encHeader);
  helloMsg -> AddHeader(packetType);
  Ptr<Packet> emptyMsg = Create<Packet> ();
  this -> Send (emptyMsg);
  this -> Send (helloMsg);
  EventId sendEvent;
  sendEvent = Simulator::Schedule (interval, &MyReceiver::SayHello, this, pktCount-1, interval);
  NS_LOG_UNCOND (sendEvent.GetTs());
}

void MyReceiver::SayMessage (uint32_t pktCount, Time interval)
{
//  MyHeader idHeader;
//  idHeader.SetData(this -> mySocket ->GetNode () -> GetId ());
  MyHeader msgKeyNum;
  msgKeyNum.SetData(this -> currentKeyNum);
  MyHeader packetType;
  packetType.SetData((uint16_t) 1);
  Ptr<Packet> encMsg = Create<Packet> (100);
  encMsg -> AddHeader(msgKeyNum);
//  encMsg -> AddHeader(idHeader);
  encMsg -> AddHeader(packetType);
  this -> Send (encMsg);
      EventId sendEvent;
  sendEvent = Simulator::Schedule (interval, &MyReceiver::SayMessage, this, pktCount-1, interval);
      //sendEvent = Simulator::Schedule (pktInterval, &MyReceiver::SayHello, this, pktCount-1, pktInterval);
      NS_LOG_UNCOND (sendEvent.GetTs());
}

void MyReceiver::SayKey(uint32_t pktCount, Time interval)
{
  MyHeader idHeader;
  idHeader.SetData(this -> mySocket ->GetNode () -> GetId ());
  MyHeader msgKeyNum;
  msgKeyNum.SetData(this -> currentKeyNum);
  MyHeader packetType;
  packetType.SetData((uint16_t) 1);
  Ptr<Packet> keyMsg = Create<Packet> (100);
  keyMsg -> AddHeader(msgKeyNum);
  keyMsg -> AddHeader(idHeader);
  keyMsg -> AddHeader(packetType);
  this -> Send (keyMsg);
  this -> currentKeyNum++;
  EventId sendEvent;
  sendEvent = Simulator::Schedule (interval, &MyReceiver::SayMessage, this, pktCount-1, interval);
      //sendEvent = Simulator::Schedule (pktInterval, &MyReceiver::SayHello, this, pktCount-1, pktInterval);
  NS_LOG_UNCOND (sendEvent.GetTs());
}

int main (int argc, char *argv[])
{
  std::string phyMode ("DsssRate1Mbps");
  double rss = -80;  // -dBm
  uint32_t packetSize = 1000; // bytes
  uint32_t numPackets = 10;
  double interval = 1.0; // seconds
  bool verbose = false;
  uint32_t users = 15;

  CommandLine cmd;

  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.AddValue ("rss", "received signal strength", rss);
  cmd.AddValue ("packetSize", "size of application packet sent", packetSize);
  cmd.AddValue ("numPackets", "number of packets generated", numPackets);
  cmd.AddValue ("interval", "interval (seconds) between packets", interval);
  cmd.AddValue ("verbose", "turn on all WifiNetDevice log components", verbose);

  cmd.Parse (argc, argv);
  // Convert to time object
  Time interPacketInterval = Seconds (interval);

  // disable fragmentation for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("2200"));
  // turn off RTS/CTS for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("2200"));
  // Fix non-unicast data rate to be the same as that of unicast
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", 
                      StringValue (phyMode));

  NodeContainer c;
        
  c.Create (users);

  // The below set of helpers will help us to put together the wifi NICs we want
  WifiHelper wifi;
  if (verbose)
    {
      wifi.EnableLogComponents ();  // Turn on all Wifi logging
    }
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  // This is one parameter that matters when using FixedRssLossModel
  // set it to zero; otherwise, gain will be added
  wifiPhy.Set ("RxGain", DoubleValue (0) ); 
  // ns-3 supports RadioTap and Prism tracing extensions for 802.11b
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO); 

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  // The below FixedRssLossModel will cause the rss to be fixed regardless
  // of the distance between the two stations, and the transmit power
   wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel","MaxRange",DoubleValue (10));
  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a non-QoS upper mac, and disable rate control
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));
  // Set it to adhoc mode
  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, c);

  // Note that with FixedRssLossModel, the positions below are not 
  // used for received signal strength. 
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0.0, 0.0, 0.0));
  positionAlloc->Add (Vector (5.0, 0.0, 0.0));
  //mobility.SetPositionAllocator (positionAlloc);

  mobility.SetPositionAllocator ("ns3::RandomDiscPositionAllocator",
  "X", StringValue ("10.0"),
  "Y", StringValue ("10.0"),
  "Rho", StringValue ("ns3::UniformRandomVariable[Min=0|Max=30]"));

  mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                             "Bounds", RectangleValue (Rectangle (-100, 100, -100, 100)),
                             "Distance", DoubleValue (1.0),
                             "Speed", StringValue ("ns3::ConstantRandomVariable[Constant=10.0]"));
  mobility.Install (c);

  InternetStackHelper internet;
  internet.Install (c);

  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("Assign IP Addresses.");
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i = ipv4.Assign (devices);

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");

  //routing 
  std::vector<MyReceiver* > myReceiverSink (users);
  for (uint32_t n = 0; n < users; n++) {
      MyReceiver *receiver = new MyReceiver (c.Get(n), tid);
      receiver -> Receive (MakeCallback (&MyReceiver::ReceivePacket, receiver));
      Simulator::Schedule (interPacketInterval, &MyReceiver::SayHello, receiver, numPackets, interPacketInterval);
//      receiver -> SayHello(numPackets, interPacketInterval);
      myReceiverSink.at(n) = receiver;
  }

  MyReceiver* source = myReceiverSink.at(9);
  Simulator::Schedule (Seconds (1.0), &MyReceiver::SayMessage, source, numPackets, Seconds (2.0));
/*  Simulator::ScheduleWithContext (source->GetNode ()->GetId (),
                                  Seconds (1.0), &MyReceiver::SayMessage, 
                                  source, numPackets, Seconds (2.0));
*/
  Simulator::Stop (Seconds (25.0));
  AnimationInterface anim ("simple-adhoc.xml");
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
