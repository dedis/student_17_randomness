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
	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

// Name can be used from other packages to refer to this protocol.
const Name = "RandShare"

func init() {
	for _, p := range []interface{}{Announce{}, Reply{}, Commitment{}, Share{},
		StructAnnounce{}, StructReply{}, StructCommitment{}, StructShare{}} {
		network.RegisterMessage(p)
	}
}

// Announce is used to pass a message to all children.
type Announce struct {
	//share   share.PubShare
	Src     int
	Tgt     int
	Share   share.PriShare
	B       abstract.Point
	Commits []abstract.Point
}

// StructAnnounce just contains Announce and the data necessary to identify and
// process the message in the sda framework.
type StructAnnounce struct {
	*onet.TreeNode
	Announce
}

// Reply returns the count of all children.
type Reply struct {
	Src  int
	Tgt  int
	Vote share.PriShare //positive : nil, negative : share
}

// StructReply just contains Reply and the data necessary to identify and
// process the message in the sda framework.
type StructReply struct {
	*onet.TreeNode
	Reply
}

type Commitment struct {
	Src  int
	Tgt  int
	Vote int
}

// StructCommitment just contains Commitment and the data necessary to identify and
// process the message in the sda framework.
type StructCommitment struct {
	*onet.TreeNode
	Commitment
}

type Share struct {
	Src    int
	Tgt    int
	Share  share.PriShare
	NPrime int
}

// StructShare just contains Share and the data necessary to identify and
// process the message in the sda framework.
type StructShare struct {
	*onet.TreeNode
	Share
}

type Vote struct {
	PositiveCounter int
	NegativeCounter int
}

type RandShare struct {
	mutex sync.Mutex
	*onet.TreeNodeInstance

	faulty    int
	nodes     int
	threshold int
	purpose   string
	time      time.Time
	nPrime    int
	//secret    abstract.Scalar
	//store announces that we receive
	announces map[int]*Announce
	//store replies before sending them 2.1 used in HandleAnnounce
	replies map[int]*Reply
	//keep track of votes for secret sj(0) used in HandleReply
	votes map[int]*Vote
	//keep track of commits before modif of tracker used in HandleCommitment
	commits map[int]*Vote
	//vector to keep trace of valid secret received (Vi) 2.5 used in HandleCommitment
	tracker map[int]int
	//store the shares for the recovery
	shares map[int]*share.PriShare
	Done   chan bool
}
