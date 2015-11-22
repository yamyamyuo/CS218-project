#include <stdio.h>
#include <math.h>

class trustItem{
{
public:
  int id;
  int time;
};

class ScoreTable{
  private static int factor = 1 / 2;
  private static int lambda = exp(-4);
  private static int validPeriod = 20;
  vector<trustItem> trustTable;
  int currTime
  int nodeSize
};

ScoreTable::ScoreTable (){
}

/*  calculateMaxScore is to go through the whole trustTable and find out the most popular node so far
    trustTable[IN] which contains <id, time> pair one node has encounterned so far
    nodeSize[IN]   number of nodes in network 
    currTime[IN]   current time
    max_id[OUT]    the id of the most popular node at present
    max_score[OUT] the score of that popular node 
*/
//ScoreTable::calculateMaxScore(vector<trustItem> &trustTable, int nodeSize, int currTime, int &max_id, int &max_score) {
ScoreTable::calculateMaxScore(int &max_id, int &max_score) {
  lastUpdateTime = currTime;
  vector<int> trustScore(nodeSize);
  for (int i = 0 ; i < trustTable.size() ; i++) {
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

ScoreTable::updateTable(trustItem item) {
  //add the new encounter item
  trustTable.push_back(item);
  //delete out-of-date item
  int eStart = 0;
  int eEnd = 0;  
  for (; trustTable[eEnd].time < (currTime) - validPeriod; eEnd++);
  trustTable.erase(eStart, eEnd);
}
