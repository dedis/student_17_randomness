package randshare

/*
Struct holds the messages that will be sent around in the protocol. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

import (
	"sync"
	"time"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

// Name can be used from other packages to refer to this protocol.
const Name = "RandShare"

func init() {
	for _, p := range []interface{}{A1{}, R1{},
		StructA1{}, StructR1{}} {
		network.RegisterMessage(p)
	}
}

// Announce is used to pass a message to all children.
type A1 struct {
	Src     int
	Tgt     int
	B       abstract.Point
	Commits []abstract.Point
	Share   *pvss.PubVerShare //share   share.PubShare
}

// StructAnnounce just contains Announce and the data necessary to identify and
// process the message in the sda framework.
type StructA1 struct {
	*onet.TreeNode
	A1
}

// Reply returns the count of all children.
type R1 struct {
	Src         int
	Tgt         int
	PubVerShare *pvss.PubVerShare //positive : nil, negative : share
}

// StructReply just contains Reply and the data necessary to identify and
// process the message in the sda framework.
type StructR1 struct {
	*onet.TreeNode
	R1
}

type RandShare struct {
	mutex sync.Mutex
	*onet.TreeNodeInstance

	faulty    int
	nodes     int
	threshold int
	purpose   string
	time      time.Time
	X         []abstract.Point //pub keys
	encShares map[int]map[int]*pvss.PubVerShare
	decShares map[int]map[int]*pvss.PubVerShare
	//store the recovered secrets to compute the collective random string
	secrets       map[int]abstract.Point
	coStringReady bool
	Done          chan bool
}
