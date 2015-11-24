#include <stdio.h>
#include <math.h>
#include "ScoreTable.h"
#include <vector>
#include <string>
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/nstime.h"
#include <iostream>
#include <map>
#include <list>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("ScoreTable");

EncounterTuple::EncounterTuple()
{
}

EncounterTuple::EncounterTuple(uint32_t id, Time time)
{
  node_id = id;
  timestamp = time;
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
  
}

ScoreTable::ScoreTable ()
{
  factor = 1 / 2.0;
  lambda = exp (-4);
  validPeriod = 20;
}

/*  calculateMaxScore is to go through the whole trustTable and find out the most popular node so far
    trustTable[IN] which contains <id, time> pair one node has encounterned so far
    nodeSize[IN]   number of nodes in network 
    currTime[IN]   current time
    max_id[OUT]    the id of the most popular node at present
    max_score[OUT] the score of that popular node 

*/
/*
void
ScoreTable::calculateMaxScore(int &max_id, int &max_score) {

int lastUpdateTime = currTime;
  std::vector<int> trustScore(nodeSize);
  for (uint32_t i = 0 ; i < trustTable.size() ; i++) {
    trustItem item = trustTable[i];
    trustScore[item.id] += pow (factor, lambda * (currTime - item.time)); 
  }
  max_id = 0;
  max_score = 0;
  for (int i = 0 ; i < nodeSize ; i++) {
    if (trustScore[i] > max_score) {
      max_score = trustScore[i];
      max_id = i;  
    }
  }

}

void
ScoreTable::updateTable(EncounterTable item) {

//add the new encounter item
  trustTable.push_back(item);
  //delete out-of-date item
  int eStart = 0;
  int eEnd = 0;  
  for (; trustTable[eEnd].time < (currTime) - validPeriod; eEnd++);
  trustTable.erase(eStart, eEnd);
}
*/

}// namespace ns3

int main()
{
  return 0;
}
