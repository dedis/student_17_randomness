package randsharepvss

import (
	"sync"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share/pvss"

	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

//Name can be used from other packages to refer to this protocol.
const Name = "RandShare"

//init registers the handlers
func init() {
	for _, p := range []interface{}{A1{}, S1{}, R1{},
		StructA1{}, StructS1{}, StructR1{}} {
		network.RegisterMessage(p)
	}
}

//Share is used to send the share along with its coordinates in the matrix encShare : (Src, PubVerShare.S.I)
type Share struct {
	Src         int               //The source
	PubVerShare *pvss.PubVerShare //The share
}

type Vote struct {
	Voted bool //a boolean to verify that a certain node doesn't vote twice
	Vote  int  //The vote associated to that node
}

// A1 is the announce.
type A1 struct {
	SessionID []byte              //SessionID to verify the validity of the reply
	Src       int                 //The sender
	B         abstract.Point      //Info about pubPoly of Src
	Commits   []abstract.Point    //Commits used with B to reconstruct pubPoly
	Shares    []*pvss.PubVerShare //The src th row of encrypted shares
	Purpose   string              //the purpose of the current ProtocolInstance
	Time      int64               //time given by initializer to compute sessionID
}

// StructA1 just contains Announce and the data necessary to identify and
// process the message in the sda framework.
type StructA1 struct {
	*onet.TreeNode //The tree
	A1             //The announce
}

//S1 is sent when a node reaches the 1st step.
type S1 struct {
	SessionID []byte        //SessionID to verify the validity
	Src       int           //The sender
	Votes     map[int]*Vote //The votes
}

// StructR1 just contains S1 and the data necessary to identify and
// process the message in the sda framework.
type StructS1 struct {
	*onet.TreeNode //The tree
	S1             //The reply
}

// R1 is the reply.
type R1 struct {
	SessionID []byte   //SessionID to verify the validity of the reply
	Src       int      //The sender
	Shares    []*Share //The decrypted shares of node Src
}

// StructR1 just contains R1 and the data necessary to identify and
// process the message in the sda framework.
type StructR1 struct {
	*onet.TreeNode //The tree
	R1             //The reply
}

//Transcript is given to a third party so that it can verify the porcess of creatino of our random srting
type Transcript struct {
	SessionID []byte                            //the sessionID
	Suite     abstract.Suite                    //The suite (rs.Suite())
	Nodes     int                               //Number of nodes
	Faulty    int                               //Number of faulty nodes
	Purpose   string                            //The purpose
	Time      int64                             //the starting time
	X         []abstract.Point                  //The public keys
	H         abstract.Point                    //the 2nd base
	EncShares map[int]map[int]*pvss.PubVerShare //The matrix of encrypted shares
	PubPolys  []*share.PubPoly                  //The pubPoly of every node
	DecShares map[int]map[int]*pvss.PubVerShare //The matrix of decrypted shares
	Votes     map[int]*Vote                     //The votes
	Secrets   map[int]abstract.Point            //The recovered secrets
}

//RandShare is our protocol struct
type RandShare struct {
	mutex                  sync.Mutex                        //Mutex to avoid concurrency
	*onet.TreeNodeInstance                                   //The tree of nodes
	nodes                  int                               //Number of nodes
	faulty                 int                               //Number of faulty nodes
	threshold              int                               //The threshold to recover values
	purpose                string                            //The purpose of the protocol
	startingTime           int64                             //starting time of the randshare protocol run
	sessionID              []byte                            //The SessionID number (see method SessionID)
	H                      abstract.Point                    //Our second base point created with SessionID
	pubPolys               []*share.PubPoly                  //The pubPoly of every node
	X                      []abstract.Point                  //The public keys
	encShares              map[int]map[int]*pvss.PubVerShare //Matrix of encrypted shares : ES_src_tgt = encShare[src][tgt]
	tracker                map[int]int                       //tracker[i] can be -1 not enough enc share verified, 0 nothing received, 1 we have enough enc shares
	votes                  map[int]*Vote                     //Indexes of good nodes is set at 1, sent when receieved an announce from everyone
	decShares              map[int]map[int]*pvss.PubVerShare //Matrix of decrypted shares : DS_src_tgt = decShare[src][tgt]
	secrets                map[int]abstract.Point            //Recovered secrets
	coStringReady          bool                              //Is the coString available ?
	coString               abstract.Point                    //Collective random string computed with the secrets
	Done                   chan bool                         //Is the protocol done ?
}
