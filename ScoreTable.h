#ifndef SCORETABLE_H
#define SCORETABLE_H

#include <stdint.h>
#include "vector"
#include <math.h>
#include "ns3/nstime.h"
#include <iostream>
#include <map>
#include <list>	

namespace ns3 {

class EncounterTuple
{
public:
  EncounterTuple();
  EncounterTuple(uint32_t id, Time time);
  uint32_t node_id;
  Time timestamp;
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
  void InsertItem(EncounterListItem *current);
  void DeleteItem(Time start, Time end);
  void Next();

  EncounterListItem* head;
  EncounterListItem* tail;
};


class ScoreTable
{
public:
  //std::vector<EncounterTable> trustTable;
  int currTime;
  int nodeSize;
  ScoreTable ();
  void calculateMaxScore(int &max_id, int &max_score);
  //void updateTable(EncounterTuple item);

private:
  double factor;
  double lambda;
  int validPeriod;
};


} //namespace ns3

#endif /*SCORETABLE_H*/
