/*Package randsharepvss gathers the files used to create a randshare proctocol with PVSS feature.
The protocol has two messages:
	- A1 which is sent from the root down the tree
	- R1 which is sent back up to the root


A simple protocol uses four files:
- struct.go defines the messages sent around
- randshare.go defines the actions for each message
- randshare_test.go tests the protocol in a local test

*/
package randsharepvss
