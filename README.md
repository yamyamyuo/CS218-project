# CS218-project
Anonymous Social Tie routing

Procedure
social-tie building
send hello messages periodically to discover the neighbours in their transmitting range.
record encounting times in the local table of each node. In order to achieve this without acknowledge the neighbours who we are. We need to sign a unique ID to both nodes in each pair communication. We call it a (whatever) table.
every node compute its own social score by (algorithm given by 2014_social_tie_routing) and send the score to its neighbours periodically (or when they encounter others).
source node and other intermediate node pick the both popular and reliable node to send the message.
