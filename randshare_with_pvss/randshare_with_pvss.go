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
	rs.pubPolys = make([]*share.PubPoly, rs.nodes)
	rs.encShares = make(map[int]map[int]*pvss.PubVerShare)
	rs.tracker = make(map[int]byte)
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
	rs.pubPolys[rs.Index()] = pubPoly
	b, commits := pubPoly.Info()

	for j := 0; j < rs.nodes; j++ {

		announce := &A1{
			Src:     rs.Index(),
			Share:   encShares[j],
			B:       b,
			Commits: commits,
		}

		if _, ok := rs.encShares[rs.Index()]; !ok {
			rs.encShares[rs.Index()] = make(map[int]*pvss.PubVerShare)
			rs.tracker[rs.Index()] = 1
		}
		rs.encShares[rs.Index()][j] = encShares[j]

		if err := rs.Broadcast(announce); err != nil {
			return err
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
		rs.pubPolys[rs.Index()] = pubPoly

		b, commits := pubPoly.Info()

		for j := 0; j < rs.nodes; j++ {
			announce := &A1{
				Src:     rs.Index(),
				Share:   encShares[j],
				B:       b,
				Commits: commits,
			}

			//we know they are correct, we can store them
			if _, ok := rs.encShares[rs.Index()]; !ok {
				rs.encShares[rs.Index()] = make(map[int]*pvss.PubVerShare)
				rs.tracker[rs.Index()] = 1
			}
			rs.encShares[rs.Index()][j] = encShares[j]

			if err := rs.Broadcast(announce); err != nil {
				return err
			}
		}
	}

	//dealing with the msg : storing the encShare received if correct
	shareIndex := msg.Share.S.I
	pubPolySrc := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)
	rs.pubPolys[msg.Src] = pubPolySrc
	value := pubPolySrc.Eval(shareIndex).V
	if err := pvss.VerifyEncShare(rs.Suite(), nil, rs.X[shareIndex], value, msg.Share); err == nil {
		//share is correct, we store it in the encShares map

		if _, ok := rs.encShares[msg.Src]; !ok {
			rs.encShares[msg.Src] = make(map[int]*pvss.PubVerShare)
		}
		rs.encShares[msg.Src][shareIndex] = msg.Share

	}

	if len(rs.encShares[msg.Src]) == rs.nodes { //the ligne encShares[msg.src] is full
		rs.tracker[msg.Src] = 1
	}

	if len(rs.tracker) == rs.nodes { //matrix is full
		var encShareList []*pvss.PubVerShare
		var values []abstract.Point
		var keys []abstract.Point

		for j := 0; j < rs.nodes; j++ {
			encShareList = append(encShareList, rs.encShares[j][rs.Index()])
			values = append(values, rs.pubPolys[j].Eval(rs.Index()).V)
			keys = append(keys, rs.X[rs.Index()])
		}

		_, _, validDecShares, err := pvss.DecShareBatch(rs.Suite(), nil, keys, values, rs.Private(), encShareList)
		if err != nil {
			return err
		}
		//they are correct we store them
		for j := 0; j < len(validDecShares); j++ {
			if _, ok := rs.decShares[j]; !ok {
				rs.decShares[j] = make(map[int]*pvss.PubVerShare)
			}
			rs.decShares[j][rs.Index()] = validDecShares[j]
		}
		log.LLvlf1("index %d, encshares %+v, correct %+v, dec %+v", rs.Index(), rs.encShares, validDecShares, rs.decShares) //the list of shares of the rs.Index()-th column

		//we brodcast our decShares
		reply := &R1{Src: rs.Index(), Shares: validDecShares}
		if err := rs.Broadcast(reply); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RandShare) HandleR1(reply StructR1) error {
	msg := &reply.R1
	log.LLvlf1("msg %+v", msg)
	//we store the correct decShares
	for j := 0; j < len(msg.Shares); j++ {
		/*if err := pvss.VerifyDecShare(rs.Suite(), nil, rs.X[msg.Src], rs.encShares[j][msg.Src], msg.Shares[j]); err != nil {
			log.LLvl1("lol")
			return err
		}
		//decShare is correct we store it*/

		if _, ok := rs.decShares[j]; !ok {
			rs.decShares[j] = make(map[int]*pvss.PubVerShare)
		}
		rs.decShares[j][msg.Src] = msg.Shares[j]

		if len(rs.decShares[j]) == rs.nodes { //the line is full : we recover secret

			log.Lvlf1("Getting here")
			var encShareList []*pvss.PubVerShare
			var decShareList []*pvss.PubVerShare
			for i := 0; i < rs.nodes; i++ {
				//we construct goodKeys and goddEncShares depending on
				encShareList = append(encShareList, rs.encShares[j][i])
				decShareList = append(decShareList, rs.decShares[j][i])
			}

			secret, err := pvss.RecoverSecret(rs.Suite(), nil, rs.X, encShareList, decShareList, rs.threshold, rs.nodes)
			if err != nil {
				log.LLvlf1("len(encShareList) %d, len(msg.Shares) %d versus threshold %d", len(encShareList), len(msg.Shares), rs.threshold)
				return err
			}
			rs.secrets[j] = secret

		}
		if (len(rs.secrets) == rs.nodes) && !rs.coStringReady {
			coString := rs.Suite().Point().Null()
			for j := range rs.secrets {
				abstract.Point.Add(coString, coString, rs.secrets[j])
			}
			log.Lvlf1("Costring recovered at node %d is %+v", rs.Index(), coString)
			rs.coStringReady = true
			rs.Done <- true
		}
	}
	return nil
}
