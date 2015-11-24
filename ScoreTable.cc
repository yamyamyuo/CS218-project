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
void
EncounterList::calculateMaxScore(int nodeSize, Time curr_time, int &max_id, int &max_score) 
{
  std::vector<int> trustScore(nodeSize);
  EncounterListItem *p = head;
  while (p -> next != NULL )
  {
    EncounterTuple curr_tuple = p -> curr_data; 
    trustScore[curr_tuple.node_id] += pow (factor, lambda * (curr_time.GetSeconds() - curr_tuple.timestamp.GetSeconds()));
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


/*
void
ScoreTable::calculateMaxScore(int &max_id, int &max_score) {

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

