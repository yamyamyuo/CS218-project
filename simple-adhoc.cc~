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
#include "ns3/nstime.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/netanim-module.h"
#include "ns3/ptr.h"
#include "ns3/packet.h"
#include "ns3/header.h"

//new added
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <list>
#include <math.h>

using namespace ns3;

//the encounter list classes define
class EncounterTuple
{
public:
  EncounterTuple();
  EncounterTuple(uint32_t id, Time time);
  uint32_t node_id;
  Time timestamp;
  Time GetTime();
  uint32_t GetID();
};

class EncounterListItem
{
public:
  EncounterListItem(EncounterTuple *tuple);

  EncounterTuple curr_data;
  EncounterListItem* prev;
  EncounterListItem* next;
};

class EncounterList
{
public:
  EncounterList();
  EncounterList(int nodeSize, double factor, double lambda, Time validPeriod);
  void InsertItem(EncounterListItem *current);
  void DeleteItem(Time start, Time end);
  void Next();
  uint32_t calculateMaxScore(int nodeSize, Time curr_time);

  int nodeSize;
  double factor;
  double lambda;
  Time validPeriod;
  EncounterListItem* head;
  EncounterListItem* tail;
}; // class define ends;

// function define starts
 
EncounterTuple::EncounterTuple()
{
}

EncounterTuple::EncounterTuple(uint32_t id, Time time)
{
  node_id = id;
  timestamp = time;
}

Time
EncounterTuple::GetTime(){
  return this -> timestamp;
}

uint32_t
EncounterTuple::GetID()
{
  return this -> node_id;
}

EncounterListItem::EncounterListItem(EncounterTuple *tuple)
{
  curr_data.node_id = tuple -> node_id;
  curr_data.timestamp = tuple -> timestamp;
}

EncounterList::EncounterList()
{
  head = NULL;
  tail = NULL;
}

EncounterList::EncounterList(int nodeSize, double factor, double lambda, Time validPeriod) 
{
  head = NULL;
  tail = NULL;
  factor = factor;
  lambda = lambda;
  validPeriod = validPeriod;
  //factor = 1 / 2.0;
  //lambda = exp (-4);
  //validPeriod = 20;
}

void
EncounterList::InsertItem(EncounterListItem *current)
{
  if (head == NULL)
    head = current;
  current -> prev = tail;
  tail -> next = current;
  tail = current;
  current -> next = NULL;
}

void
EncounterList::DeleteItem(Time start, Time end)
{
  Time tx = head -> curr_data.GetTime();
  while (tx < end)
  {
    head = head -> next;
    head -> prev = NULL;
    tx = head -> curr_data.GetTime();
  }
}

/*  calculateMaxScore is to go through the whole EncounterList and find out the most popular node so far
    nodeSize[IN]   number of nodes in network 
    curr_time[IN]  current time
    max_id[OUT]    the id of the most popular node at present
    max_score[OUT] the score of that popular node 

*/
uint32_t 
EncounterList::calculateMaxScore(int nodeSize, Time curr_time) 
{
  std::vector<uint32_t> trustScore(nodeSize);
  EncounterListItem *p = head;
  while (p -> next != NULL )
  {
    EncounterTuple curr_tuple = p -> curr_data; 
    trustScore[curr_tuple.node_id] += pow (factor, lambda * (curr_time.GetSeconds() - curr_tuple.timestamp.GetSeconds()));
  }
  uint32_t max_id = -1;
  uint32_t max_score = 0;
  for (int i = 0 ; i < nodeSize ; i++) {
    if (trustScore[i] > max_score) {
      max_score = trustScore[i];
      max_id = i;  
    }
  }
  return max_id;
}

// encounter list function define ends

/**********
*
* MyHeader is a generic header that is 2 bytes. 
* This is to accomodate packets with varying headers for anonymity.
*
**********/
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

/******
*
* QItem used to maintain a queue|vector of unmatched keys and messages
*
******/
class QItem
{
public:
QItem(uint16_t pkt, uint16_t key);
uint16_t GetPktType ();
uint16_t GetKeyNum ();
uint64_t GetTimestmp ();
private:
  uint16_t pktType;
  uint16_t keyNum;
  uint64_t timestmp;
};

QItem::QItem(uint16_t pkt, uint16_t key)
{
  this -> pktType = pkt;
  this -> keyNum = key;
  Time t = Simulator::Now();
  this -> timestmp = t.GetMilliSeconds();
}

/*****
*
* MyReceiver is the wrapper for each node. This class contains the routing protocol. 
* Each node responding to packets as according to the protocol
*
*****/
class MyReceiver
{

public: 
  MyReceiver (Ptr<Node> node, TypeId tid);
  Ptr<Socket> GetSocket ();
  Ptr<Socket> GetHelloSocket ();
  Ptr<Socket> GetKeyMsgSocket ();
  Ptr<Socket> GetFwdSocket ();
  void SetData (std::string m_value);
  std::string GetData ();
  //virtual ~MyReceiver ();
  void Bind (InetSocketAddress local);
  void Receive (Callback<void, Ptr<Socket> > ReceivePacket);
  void ReceivePacket (Ptr<Socket> socket);
  void Send (Ptr<Packet> msg, Ptr<Socket> socket);
  void SayHello (uint32_t pktCount, Time pktInterval);
  void SayMessage (uint32_t pktCount, Time interval, uint16_t recvID);
  void SayKey (uint32_t pktCount, Time interval, uint16_t recvID);
  void Forward (uint16_t recvID, uint16_t pktT, uint16_t key);
  Ptr<Node> GetNode ();
  uint16_t GetCurrKeyNum();
private:
  std::vector<uint64_t> messageQ; //integer holds time stamp
  std::vector<uint64_t> keyQ;
  std::string m_data;
  Ptr<Socket> mySocket;
  Ptr<Socket> helloSocket;
  Ptr<Socket> keyMsgSocket;
  Ptr<Socket> fwdSocket;
  Ptr<Node> myNode;
  TypeId mytid;
  uint16_t currentKeyNum;
  EncounterList *myList;
};

MyReceiver::MyReceiver (Ptr<Node> node, TypeId tid)
{
  this -> messageQ.resize(999, 0);
  this -> keyQ.resize(999, 0);
  this -> myNode = node;
  this -> mytid = tid;
  this -> mySocket = Socket::CreateSocket (node, tid);
  this -> helloSocket = Socket::CreateSocket (node, tid);
  this -> keyMsgSocket = Socket::CreateSocket (node, tid);
  this -> fwdSocket = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
  this -> Bind(local);
  InetSocketAddress remote = InetSocketAddress (Ipv4Address ("255.255.255.255"), 80);
  this -> mySocket ->SetAllowBroadcast (true);
  this -> helloSocket ->SetAllowBroadcast (true);
  this -> keyMsgSocket ->SetAllowBroadcast (true);
  this -> fwdSocket ->SetAllowBroadcast (true);

  this -> mySocket -> Connect (remote);
  this -> helloSocket -> Connect (remote);
  this -> keyMsgSocket -> Connect (remote);
  this -> fwdSocket -> Connect (remote);
  this -> m_data = "";
  this -> myList = new EncounterList(500, 1/2.0, exp (-4), Time(NanoSeconds(200000000)));//we should test this data
}

Ptr<Socket>
MyReceiver::GetHelloSocket ()
{
  return this -> helloSocket;
}

Ptr<Socket>
MyReceiver::GetKeyMsgSocket ()
{
  return this -> keyMsgSocket;
}

Ptr<Socket>
MyReceiver::GetFwdSocket ()
{
  return this -> fwdSocket;
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
    this -> helloSocket -> SetRecvCallback (ReceivePacket);
    this -> keyMsgSocket -> SetRecvCallback (ReceivePacket);
    this -> fwdSocket -> SetRecvCallback (ReceivePacket);
}

void
MyReceiver::Bind (InetSocketAddress local)
{
    this -> mySocket -> Bind (local);
    this -> helloSocket -> Bind (local);
    this -> keyMsgSocket -> Bind (local);
    this -> fwdSocket -> Bind (local);
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
      NS_LOG_UNCOND ("type: "<< packetType.GetData());
      packet -> RemoveHeader(nodeID); //for hello message, this is sender. for key message, this is receiver
      NS_LOG_UNCOND ("id: "<< nodeID.GetData());
      
      if (packetType.GetData() != (uint16_t) 0)
      {
        MyHeader keyNum;
        packet -> RemoveHeader(keyNum);
        if (packetType.GetData() != (uint16_t) 1)
          NS_LOG_UNCOND ("msg: "<< keyNum.GetData());
        else
          NS_LOG_UNCOND ("key: "<< keyNum.GetData());
      }

      //when it is hellomsg Store in Encounter list for score calculation
      if (packetType.GetData() == (uint16_t) 0) 
      {
        Time timestamp = Now();
        EncounterTuple *newTuple = new EncounterTuple(packetType.GetData(), timestamp);
        EncounterListItem *listItem = new EncounterListItem(newTuple);
        myList -> InsertItem(listItem);
      }
      //if not hellomsg and header id is 999 or itself call forward function
      if (packetType.GetData() != (uint16_t) 0)
      {
          //Chih: check key/msg q
        Time t = Simulator::Now();
        if (packetType.GetData() == (uint16_t) 1) {
          //case when packet type is message
          //check if key exist
          //update msg q
        }
        if (packetType.GetData() == (uint16_t) 2) {
          //case when packet type is key
          //check if key exist
          for (int i = 0; i < 999; i++) {
            if (this -> keyQ[i] != 0) {
              
            }
          }
          //update msg q
        }
        //this -> timestmp = t.GetMilliSeconds();
        if (nodeID.GetData() == (uint16_t) 999 || 
            nodeID.GetData() == this -> mySocket ->GetNode () -> GetId ())
        {     
          //Pseudo code to monitor the max score. 
          //Time time = Now();
          uint16_t max_id = 8;
          //int &max_score = NULL;
          //myList -> calculateMaxScore(500, time, max_id, max_score);
          this -> Forward (max_id, packetType.GetData(), nodeID.GetData());
        }
      }
     
    }
} 

void MyReceiver::Send (Ptr<Packet> msg, Ptr<Socket> socket)
{
  socket -> Send(msg);
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
  this -> Send (emptyMsg, this -> helloSocket);
  this -> Send (helloMsg, this -> helloSocket);
  EventId sendEvent;
  sendEvent = Simulator::Schedule (interval, &MyReceiver::SayHello, this, pktCount-1, interval);
  //NS_LOG_UNCOND (sendEvent.GetTs());
}

void MyReceiver::SayMessage (uint32_t pktCount, Time interval, uint16_t recvID)
{
  MyHeader idHeader;
  idHeader.SetData(recvID);
  MyHeader msgKeyNum;
  msgKeyNum.SetData(this -> currentKeyNum);
  MyHeader packetType;
  packetType.SetData((uint16_t) 1);
  Ptr<Packet> encMsg = Create<Packet> (100);
  encMsg -> AddHeader(msgKeyNum);
  encMsg -> AddHeader(idHeader);
  encMsg -> AddHeader(packetType);
  this -> Send (encMsg, this -> keyMsgSocket);
  EventId sendEvent;
  sendEvent = Simulator::Schedule (interval, &MyReceiver::SayMessage, this, pktCount-1, interval, recvID);
  //sendEvent = Simulator::Schedule (pktInterval, &MyReceiver::SayHello, this, pktCount-1, pktInterval);
  NS_LOG_UNCOND (sendEvent.GetTs());
}

void MyReceiver::SayKey(uint32_t pktCount, Time interval, uint16_t recvID)
{
  MyHeader idHeader;
  idHeader.SetData(recvID);
  MyHeader msgKeyNum;
  msgKeyNum.SetData(this -> currentKeyNum);
  MyHeader packetType;
  packetType.SetData((uint16_t) 2);
  Ptr<Packet> keyMsg = Create<Packet> (100);
  keyMsg -> AddHeader(msgKeyNum);
  keyMsg -> AddHeader(idHeader);
  keyMsg -> AddHeader(packetType);
  this -> Send (keyMsg, this -> keyMsgSocket);
  this -> currentKeyNum++;

  EventId sendEvent;
  sendEvent = Simulator::Schedule (interval, &MyReceiver::SayKey, this, pktCount-1, interval, recvID);
  //NS_LOG_UNCOND (sendEvent.GetTs());
}

void MyReceiver::Forward (uint16_t recvID, uint16_t pktT, uint16_t key) 
{
  MyHeader rcv, pktType, keyNum;
  rcv.SetData(recvID);
  pktType.SetData(pktT);
  keyNum.SetData(key);
  Ptr<Packet> msg = Create<Packet> (100);
  msg -> AddHeader(keyNum);
  msg -> AddHeader(rcv);
  msg -> AddHeader(pktType);
  this -> Send (msg, this -> fwdSocket);
}

int main (int argc, char *argv[])
{
  std::string phyMode ("DsssRate1Mbps");
  double rss = -80;  // -dBm
  uint32_t packetSize = 1000; // bytes
  uint32_t numPackets = 10;
  double interval = 1.0; // seconds
  bool verbose = false;
  uint32_t users = 10;

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
Simulator::Schedule (Seconds (0.1), &MyReceiver::SayHello, receiver, numPackets, Seconds (2.0));
//      receiver -> SayHello(numPackets, interPacketInterval);
      myReceiverSink.at(n) = receiver;
  }

MyReceiver* source = myReceiverSink.at(2);
Simulator::Schedule (Seconds (0.5), &MyReceiver::SayMessage, source, numPackets, Seconds (2.0), (uint16_t) 999);
Simulator::Schedule (Seconds (1.5), &MyReceiver::SayKey, source, numPackets, Seconds (2.0), (uint16_t) 999);
// Simulator::ScheduleWithContext (source->GetNode ()->GetId (),
 //                                 Seconds (1.0), &MyReceiver::SayMessage, 
   //                               source, numPackets, Seconds (2.0));

  Simulator::Stop (Seconds (25.0));
  AnimationInterface anim ("simple-adhoc.xml");
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}
