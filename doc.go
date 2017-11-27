/*
The protocol has two messages:
	- Announce which is sent from the root down the tree
	- Reply which is sent back up to the root


A simple protocol uses four files:
- struct.go defines the messages sent around
- randshare.go defines the actions for each message
- randshare_test.go tests the protocol in a local test
*/
package randshare
