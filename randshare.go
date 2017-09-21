package randshare

import (
	"errors"
	"time"

	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
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
	//	rs.secret = secret

	//rs.polyCommit = make(map[int][]abstract.Point)

	rs.announces = make(map[int]*Announce)
	rs.replies = make(map[int]*Reply)
	rs.votes = make(map[int]*Vote)
	rs.tracker = make(map[int]int)
	rs.shares = make(map[int]*share.PriShare)

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
			share:   *shares[j],
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

	nodes := len(rs.List())
	err := rs.Setup(nodes, nodes/3, "")
	if err != nil {
		return err
	}

	rs.announces[msg.Src] = msg

	if msg.Src == 0 { // if we have a share from rs.List()[0] then we need to send our shares to the other nodes
		log.LLvl1(rs.Index())
		priPoly := share.NewPriPoly(rs.Suite(), rs.threshold, nil, random.Stream)
		shares := priPoly.Shares(rs.nodes)
		pubPoly := priPoly.Commit(nil)
		b, commits := pubPoly.Info()

		for j := 0; j < rs.nodes; j++ {
			announce := &Announce{
				Src:     rs.Index(),
				Tgt:     j,
				share:   *shares[j],
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

	reply := &Reply{Src: rs.Index(), Tgt: msg.Src}

	PubPoly := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)

	shareIsCorrect := PubPoly.Check(&msg.share)

	if !shareIsCorrect {
		reply.Vote = msg.share
	}

	rs.replies[msg.Src] = reply

	//if each share arrived, we send them
	if len(rs.replies) == (rs.nodes - 1) {
		for j := 0; j < rs.nodes; j++ {
			if err := rs.SendTo(rs.List()[j], rs.replies[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (rs *RandShare) HandleReply(reply StructReply) error {

	msg := &reply.Reply

	if _, ok := rs.votes[msg.Src]; !ok {
		rs.votes[msg.Src] = &Vote{PositiveCounter: 0, NegativeCounter: 0}
	}

	if &msg.Vote != nil {
		rs.votes[msg.Src].PositiveCounter += 1
	} else {
		rs.votes[msg.Src].NegativeCounter += 1
	}

	//by default vote is neg
	commit := &Commitment{Src: rs.Index(), Tgt: msg.Src}

	if rs.votes[msg.Src].PositiveCounter > 2*rs.faulty {
		commit.Vote = 1
		if err := rs.SendTo(rs.List()[msg.Src], commit); err != nil {
			return err
		}
	}
	if rs.votes[msg.Src].NegativeCounter > rs.faulty {
		commit.Vote = 0
		if err := rs.SendTo(rs.List()[msg.Src], commit); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RandShare) HandleCommitment(commitment StructCommitment) error {

	msg := &commitment.Commitment

	if _, ok := rs.commits[msg.Src]; !ok {
		rs.commits[msg.Src] = &Vote{PositiveCounter: 0, NegativeCounter: 0}
	}
	if msg.Vote == 1 {
		rs.commits[msg.Src].PositiveCounter += 1
	} else {
		rs.commits[msg.Src].NegativeCounter += 1
	}

	if rs.commits[msg.Src].PositiveCounter > 2*rs.faulty {
		rs.tracker[msg.Tgt] = 1
	}
	if rs.commits[msg.Src].NegativeCounter > 2*rs.faulty {
		rs.tracker[msg.Tgt] = 0
	}

	if len(rs.tracker) == (rs.nodes - 1) { // we have all entries in the tracker

		//we count how many 1s
		nPrime := 0
		for j := 0; j < rs.nodes; j++ {
			if j != rs.Index() {
				if rs.tracker[j] == 1 {
					nPrime = +1
				}
			}
		}
		share := &Share{Src: rs.Index(), NPrime: nPrime}
		for j := 0; j < rs.nodes; j++ {
			share.Tgt = j
			if j != rs.Index() {
				if rs.tracker[j] == 1 {
					share.Share = rs.announces[j].share
					if err := rs.SendTo(rs.List()[j], share); err != nil {
						return err
					}
				}
			}
		}
		if nPrime <= rs.faulty {
			return errors.New("aborted")
		}
	}
	return nil
}

func (rs *RandShare) HandleShare(structShare StructShare) error {

	msg := &structShare.Share
	rs.shares[msg.Src] = &msg.Share
	sharesList := make([]*share.PriShare, len(rs.shares))

	i := 0
	for s := range rs.shares {
		sharesList[i] = rs.shares[s]
		i++
	}
	share.RecoverSecret(rs.Suite(), sharesList, rs.threshold, msg.NPrime)
	return nil
}
