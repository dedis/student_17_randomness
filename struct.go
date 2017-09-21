package randshare

/*
Struct holds the messages that will be sent around in the protocol. You have
to define each message twice: once the actual message, and a second time
with the `*onet.TreeNode` embedded. The latter is used in the handler-function
so that it can find out who sent the message.
*/

import (
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
	Src     int
	Tgt     int
	share   share.PriShare
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
	Src  int //src
	Tgt  int //tgt
	Vote int
}

// StructReply just contains Reply and the data necessary to identify and
// process the message in the sda framework.
type StructCommitment struct {
	*onet.TreeNode
	Commitment
}

type Vote struct {
	PositiveCounter int
	NegativeCounter int
}

type Share struct {
	Src    int //src
	Tgt    int //tgt
	Share  share.PriShare
	NPrime int
}

type StructShare struct {
	*onet.TreeNode
	Share
}

type RandShare struct {
	*onet.TreeNodeInstance

	faulty    int
	nodes     int
	threshold int
	purpose   string
	time      time.Time

	//secret    abstract.Scalar

	//polynomial
	//polyCommit map[int][]abstract.Point

	//store announces that we receive
	announces map[int]*Announce

	//store replies before sending them 2.1
	replies map[int]*Reply

	//keep track of votes for secret si(0) 2.1 2.3
	votes map[int]*Vote

	//keep track of commits before modif of tracker 2.5
	commits map[int]*Vote

	//vector to keep trace of valid secret received (Vi) 2.5
	tracker map[int]int

	//store the shares for the recovery
	shares map[int]*share.PriShare

	Done chan bool
}
