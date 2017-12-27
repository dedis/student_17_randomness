package randshare

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
	Src     int
	Tgt     int
	Share   *share.PriShare
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
	Vote *share.PriShare //positive : nil, negative : share
}

// StructReply just contains Reply and the data necessary to identify and
// process the message in the sda framework.
type StructReply struct {
	*onet.TreeNode
	Reply
}

//Commitment is sent as a vote
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

//Share is used to send the shares as well as the number of good nodes
type Share struct {
	Src    int
	Tgt    int
	Share  *share.PriShare
	NPrime int
}

// StructShare just contains Share and the data necessary to identify and
// process the message in the sda framework.
type StructShare struct {
	*onet.TreeNode
	Share
}

//Vote gathers the negative and positive votes from all nodes
type Vote struct {
	PositiveCounter int //+1 if received a neg vote
	NegativeCounter int //+1 if received a neg vote
}

type RandShare struct {
	mutex                  sync.Mutex                      //mutex
	*onet.TreeNodeInstance                                 //tree
	faulty                 int                             //number of faulty nodes
	nodes                  int                             //number of nodes
	threshold              int                             //threhold (faulty + 1)
	purpose                string                          //purpose of protocol run
	time                   time.Time                       //time ellapsed since protocol started
	nPrime                 int                             //number of nodes after voting
	announces              map[int]*Announce               //store announces that we receive
	replies                map[int]*Reply                  //store replies before sending them 2.1 used in HandleAnnounce
	votes                  map[int]*Vote                   //keep track of votes for secret sj(0) used in HandleReply
	commits                map[int]*Vote                   //keep track of commits before modif of tracker used in HandleCommitment
	tracker                map[int]int                     //vector to keep trace of valid secret received (Vi) 2.5 used in HandleCommitment
	shares                 map[int]map[int]*share.PriShare //store the shares for the recovery of the secret sj(0)
	secrets                map[int]*abstract.Scalar        //store the recovered secrets to compute the collective random string
	coString               abstract.Scalar                 //collective string
	coStringReady          bool                            //is the collective string computed yet ?
	Done                   chan bool                       //are we done ?
}
