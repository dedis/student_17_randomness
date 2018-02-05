/*Package demo gathers the files used to create a demonstration of a randshare proctocol run with PVSS feature.
The protocol has three messages:
	- the announce A1 which is used to brodcast encrypted shares
	- the vote V1 which is used to brodcast votes
	- the reply R1 which is used to brodcast decrypted shares

A simple protocol uses three files:
- struct.go defines the messages sent around
- randshare_with_pvss_demo.go defines the actions for each message
- randshare_with_pvss_demo_test.go tests the protocol in a local test
*/
package demo
