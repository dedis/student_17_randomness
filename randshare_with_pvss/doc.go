/*Package randsharepvss gathers the files used to create a randshare proctocol with PVSS feature.
The protocol has two messages:
	- the announce A1 which is used to brodcast encrypted shares
	- the reply R1 which is used to brodcast decrypted shares


A simple protocol uses four files:
- struct.go defines the messages sent around
- randshare.go defines the actions for each message
- randshare_test.go tests the protocol in a local test

*/
package randsharepvss
