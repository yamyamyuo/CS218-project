#ifndef SCORETABLE_H
#define SCORETABLE_H

#include <stdint.h>
#include "vector"
#include <math.h>
namespace ns3 {

class trustItem
{
public:
  int id;
  int time;
  void erase (int start, int end);
};

class ScoreTable
{
public:
  std::vector<trustItem> trustTable;
  int currTime;
  int nodeSize;
  ScoreTable ();
  void calculateMaxScore(int &max_id, int &max_score);
  void updateTable(trustItem item);

private:
  static double factor;
  static double lambda;
  static int validPeriod;
 
};


} //namespace ns3

#endif /*SCORETABLE_H*/
