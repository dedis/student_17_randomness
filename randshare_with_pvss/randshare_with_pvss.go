package randshare

import (
	"time"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/crypto.v0/share/pvss"
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
	err := t.RegisterHandlers(t.HandleA1, t.HandleR1)
	return t, err
}

func (rs *RandShare) Setup(nodes int, faulty int, purpose string) error {

	rs.nodes = nodes
	rs.faulty = faulty
	rs.threshold = faulty + 1
	rs.purpose = purpose
	rs.X = make([]abstract.Point, rs.nodes)
	for j := 0; j < rs.nodes; j++ {
		rs.X[j] = rs.List()[j].ServerIdentity.Public
	}
	rs.encShares = make(map[int]map[int]*pvss.PubVerShare)
	rs.decShares = make(map[int]map[int]*pvss.PubVerShare)
	rs.secrets = make(map[int]abstract.Point)
	rs.coStringReady = false
	rs.Done = make(chan bool, 0)

	return nil
}

func (rs *RandShare) Start() error {
	rs.time = time.Now()

	encShares, pubPoly, err := pvss.EncShares(rs.Suite(), nil, rs.X, nil, rs.threshold)
	if err != nil {
		return err
	}

	b, commits := pubPoly.Info()

	for j := 0; j < rs.nodes; j++ {

		announce := &A1{
			Src:     rs.Index(),
			Tgt:     j,
			Share:   encShares[j],
			B:       b,
			Commits: commits,
		}

		if err := rs.Broadcast(announce); err != nil {
			return err
		}

		if j == rs.Index() {
			if _, ok := rs.encShares[rs.Index()]; !ok {
				rs.encShares[rs.Index()] = make(map[int]*pvss.PubVerShare)
			}
			rs.encShares[rs.Index()][j] = encShares[j]
		}
	}
	return nil
}

func (rs *RandShare) HandleA1(announce StructA1) error {

	msg := &announce.A1
	// if it's our first message, we set up rs and send our shares before anwsering
	if rs.nodes == 0 {
		nodes := len(rs.List())
		if err := rs.Setup(nodes, nodes/3, ""); err != nil {
			return err
		}

		//sending our encShares
		encShares, pubPoly, err := pvss.EncShares(rs.Suite(), nil, rs.X, nil, rs.threshold)
		if err != nil {
			return err
		}
		b, commits := pubPoly.Info()
		//sending it
		for j := 0; j < rs.nodes; j++ {
			announce := &A1{
				Src:     rs.Index(),
				Tgt:     j,
				Share:   encShares[j],
				B:       b,
				Commits: commits,
			}

			if err := rs.Broadcast(announce); err != nil {
				return err
			}

			if j == rs.Index() {
				if _, ok := rs.encShares[rs.Index()]; !ok {
					rs.encShares[rs.Index()] = make(map[int]*pvss.PubVerShare)
				}
				rs.encShares[rs.Index()][j] = encShares[j]
			}

		}
	}
	//dealing with the announce
	src := msg.Share.S.I // == to rs.Index()
	pubPoly := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)
	value := pubPoly.Eval(src).V
	//how can i get xi from Xi
	pubVerShare, err := pvss.DecShare(rs.Suite(), nil, rs.X[src], value, rs.Private(), msg.Share)
	if err != nil {
		return err
	}
	if _, ok := rs.encShares[j]; !ok {
		rs.encShares[j] = make(map[int]*pvss.PubVerShare)
	}
	rs.encShares[rs.Index()][j] = encShares[j]
	rs.encShares[msg.Src][msg.Tgt] = msg.Share

	reply := &R1{Src: rs.Index(), Tgt: src, PubVerShare: pubVerShare}

	if err := rs.Broadcast(reply); err != nil {
		return err
	}

	return nil
}

func (rs *RandShare) HandleR1(reply StructR1) error {
	msg := &reply.R1

	if _, ok := rs.decShares[msg.Tgt]; !ok {
		rs.decShares[msg.Tgt] = make(map[int]*pvss.PubVerShare)
	}

	//log.Lvlf1("args %+v, %+v, %+v", msg.X[msg.Tgt], rs.encShares[msg.Tgt], msg.PubVerShare)

	if err := pvss.VerifyDecShare(rs.Suite(), nil, rs.X[msg.Tgt], rs.encShares[msg.Tgt], msg.PubVerShare); err == nil {
		rs.decShares[msg.Tgt][msg.Src] = msg.PubVerShare
	}

	if len(rs.decShares[msg.Tgt]) >= rs.threshold {

		var decShareList []*pvss.PubVerShare
		for _, s := range rs.decShares[msg.Tgt] {
			decShareList = append(decShareList, s)
		}

		var encShareList []*pvss.PubVerShare
		for _, s := range rs.encShares {
			encShareList = append(encShareList, s)
		}

		secret, err := pvss.RecoverSecret(rs.Suite(), nil, rs.X, encShareList, decShareList, rs.threshold, rs.nodes)
		if err != nil {
			return err
		}
		rs.secrets[msg.Tgt] = secret
	}

	if (len(rs.secrets) >= rs.threshold) && !rs.coStringReady {
		coString := rs.Suite().Point().Null()
		for j := range rs.secrets {
			abstract.Point.Add(coString, coString, rs.secrets[j])
		}
		log.Lvlf1("Costring recovered at node %d is %+v", rs.Index(), coString)
		rs.coStringReady = true
		rs.Done <- true
	}

	return nil
}
