void MyReceiver::sendMessage(uint16_t receiver_id, uint16_t packetType, uint32_t pktCount, Time pktInterval)
{
  if (pktCount <= 0) return;
  //message format(receiver_id, packetType, encrypted message/key_id)
  MyHeader idHeader;
  MyHeader typeHeader;
  Ptr<Packet> msg;
  if (packetType == 1)
    msg = Create<Packet> (reinterpret_cast<const uint8_t*> ("This is the encrypted message."), 1);
  else if (packetType == 2)
    msg = Create<Packet> (reinterpret_cast<const uint8_t*> ("This is the key."), 1);
  else 
  {
    std::cout<< "The message type is wrong." <<std::endl;
    return;
  }
  idHeader.SetData(receiver_id);
  typeHeader.SetData(packetType);  
  msg -> AddHeader(idHeader);
  msg -> AddHeader(typeHeader);
  this -> mySocket -> Send(msg);
  Simulator::Schedule (pktInterval, &MyReceiver::sendMessage, this, receiver_id, packetType, 1, pktInterval);
}
