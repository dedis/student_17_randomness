package randshare

import (
	"errors"
	"time"

	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/onet.v1"
)

func init() {
	onet.GlobalProtocolRegister("RandShare", NewRandShare)
}

// NewProtocol initialises the structure for use in one round
func NewRandShare(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &RandShare{
		TreeNodeInstance: n,
	}
	err := t.RegisterHandlers(t.HandleAnnounce, t.HandleReply, t.HandleCommitment, t.HandleShare)
	return t, err
}

func (rs *RandShare) Setup(nodes int, faulty int, purpose string) error {

	rs.nodes = nodes
	rs.faulty = faulty
	rs.threshold = faulty + 1
	rs.purpose = purpose
	rs.nPrime = -1
	//	rs.secret = secret

	//rs.polyCommit = make(map[int][]abstract.Point)

	rs.announces = make(map[int]*Announce)
	rs.replies = make(map[int]*Reply)
	rs.votes = make(map[int]*Vote)
	rs.commits = make(map[int]*Vote)
	rs.tracker = make(map[int]int)
	rs.shares = make(map[int]*share.PriShare)

	rs.Done = make(chan bool, 1)

	return nil
}

func (rs *RandShare) Start() error {
	rs.time = time.Now()
	//log.Lvlf1("randShare strarting")

	//compute priPoly si(x)
	//g := edwards25519.NewAES128SHA256Ed25519()

	priPoly := share.NewPriPoly(rs.Suite(), rs.threshold, nil, random.Stream)

	//compute shares si(x)
	shares := priPoly.Shares(rs.nodes)

	//compute pubPoly using commit
	pubPoly := priPoly.Commit(nil)

	b, commits := pubPoly.Info()

	//send share si(j)
	for j := 0; j < rs.nodes; j++ {

		announce := &Announce{
			Src:     rs.Index(),
			Tgt:     j,
			Share:   *shares[j],
			B:       b,
			Commits: commits,
		}

		if j != rs.Index() {
			if err := rs.SendTo(rs.List()[j], announce); err != nil {
				return err
			}
		} else {
			rs.announces[j] = announce
		}
	}

	return nil
}

func (rs *RandShare) HandleAnnounce(announce StructAnnounce) error {

	msg := &announce.Announce

	if rs.nodes == 0 { // if it's our first message, we do our stuff before anwsering
		//setup of our node
		nodes := len(rs.List())
		if err := rs.Setup(nodes, nodes/3, ""); err != nil {
			return err
		}
		//sending our announce
		priPoly := share.NewPriPoly(rs.Suite(), rs.threshold, nil, random.Stream)
		shares := priPoly.Shares(rs.nodes)
		pubPoly := priPoly.Commit(nil)
		b, commits := pubPoly.Info()

		for j := 0; j < rs.nodes; j++ {
			announce := &Announce{
				Src:     rs.Index(),
				Tgt:     j,
				Share:   *shares[j],
				B:       b,
				Commits: commits,
			}
			if j != rs.Index() {
				if err := rs.SendTo(rs.List()[j], announce); err != nil {
					return err
				}
			} else {
				rs.announces[j] = announce
			}
		}
	}

	//now we can handle the announce

	rs.announces[msg.Src] = msg

	reply := &Reply{Src: rs.Index(), Tgt: msg.Src}

	PubPoly := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)
	shareIsCorrect := PubPoly.Check(&msg.Share)

	if !shareIsCorrect {
		reply.Vote = msg.Share
	}

	rs.replies[msg.Src] = reply

	if len(rs.replies) == (rs.nodes - 1) { //if each share arrived, we send them
		for j := 0; j < rs.nodes; j++ {
			if j != rs.Index() {
				if err := rs.Broadcast(rs.replies[j]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (rs *RandShare) HandleReply(reply StructReply) error {

	msg := &reply.Reply

	if _, ok := rs.votes[msg.Tgt]; !ok {
		rs.votes[msg.Tgt] = &Vote{PositiveCounter: 0, NegativeCounter: 0}
	}

	if &msg.Vote != nil {
		rs.votes[msg.Tgt].PositiveCounter += 1
	} else {
		rs.votes[msg.Tgt].NegativeCounter += 1
	}

	//by default vote is neg
	commit := &Commitment{Src: rs.Index(), Tgt: msg.Tgt}

	if rs.votes[msg.Tgt].PositiveCounter > 2*rs.faulty {
		commit.Vote = 1
		if err := rs.Broadcast(commit); err != nil {
			return err
		}
	}
	if rs.votes[msg.Tgt].NegativeCounter > rs.faulty {
		commit.Vote = 0
		if err := rs.Broadcast(commit); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RandShare) HandleCommitment(commitment StructCommitment) error {

	msg := &commitment.Commitment
	//log.Lvlf1("node %+v received the commit %+v", rs.Index(), msg)

	if _, ok := rs.commits[msg.Tgt]; !ok {
		rs.commits[msg.Tgt] = &Vote{PositiveCounter: 0, NegativeCounter: 0}
	}
	if msg.Vote == 1 {
		rs.commits[msg.Tgt].PositiveCounter += 1
	} else {
		rs.commits[msg.Tgt].NegativeCounter += 1
	}

	if rs.commits[msg.Tgt].PositiveCounter > 2*rs.faulty {
		rs.tracker[msg.Tgt] = 1
	}
	if rs.commits[msg.Tgt].NegativeCounter > 2*rs.faulty {
		rs.tracker[msg.Tgt] = 0
	}

	if (len(rs.tracker) == (rs.nodes)) && (rs.nPrime == -1) { // we have all entries in the tracker and didn't send the share already
		rs.nPrime = 0
		//we count how many 1s
		for j := 0; j < rs.nodes; j++ {
			if rs.tracker[j] == 1 {
				rs.nPrime += 1
			}
		}
		share := &Share{Src: rs.Index(), NPrime: rs.nPrime}
		for j := 0; j < rs.nodes; j++ {
			share.Tgt = j
			if rs.tracker[j] == 1 {
				share.Share = rs.announces[j].Share
				//log.LLvlf1("sending the share %+v", share)
				//we send the share sj(i) to the root so that we can reconstruct the collective random string
				if err := rs.SendTo(rs.List()[0], share); err != nil {
					return err
				}
			}
		}
		if rs.nPrime <= rs.faulty {
			return errors.New("aborted")
		}
	}
	return nil
}

func (rs *RandShare) HandleShare(structShare StructShare) error {

	msg := &structShare.Share
	rs.shares[msg.Src] = &msg.Share

	if len(rs.shares) == rs.nPrime {

		//gathering shares in a list
		sharesList := make([]*share.PriShare, len(rs.shares))
		i := 0
		for s := range rs.shares {
			sharesList[i] = rs.shares[s]
			i++
		}

		if _, err := share.RecoverSecret(rs.Suite(), sharesList, rs.threshold, msg.NPrime); err != nil {
			rs.Done <- true
			return err
		}
		rs.Done <- true
	}
	return nil
}
