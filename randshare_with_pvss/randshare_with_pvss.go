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

	b, commits := pubPoly.Info()
	rs.pubPoly = pubPoly

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
		b, commits := pubPoly.Info()
		rs.pubPoly = pubPoly

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
	value := pubPolySrc.Eval(shareIndex).V
	if err := pvss.VerifyEncShare(rs.Suite(), nil, rs.X[shareIndex], value, msg.Share); err == nil {
		//share is correct, we store it in the encShares map
		if _, ok := rs.encShares[msg.Src]; !ok {
			rs.encShares[msg.Src] = make(map[int]*pvss.PubVerShare)
		}
		rs.encShares[msg.Src][shareIndex] = msg.Share
	}

	if len(rs.encShares[msg.Src]) == rs.nodes { // we have enough encShare to recover secret[msg.Src]

		//Note : optimization possible with only rs.nodes - rs.Threshold elem to have rs.Threshold
		//elem in common between encShare and DecShares to recover secret by pigeonhole principle

		rs.tracker[msg.Src] = 1
	}

	if len(rs.tracker) == rs.nodes { //we can recover all the secrets

		//we decrypt our secret and broadcast it
		/*option 1 : batch : our decShare struct becomes map[int][]PubVerShare*/
		var values []abstract.Point
		var encShareList []*pvss.PubVerShare

		for j := 0; j < rs.nodes; j++ {
			values = append(values, rs.pubPoly.Eval(j).V)
			encShareList = append(encShareList, rs.encShares[rs.Index()][j])
		}

		validPubKeys, validEncShares, validDecShares, _ := pvss.DecShareBatch(rs.Suite(), nil, rs.X, values, rs.Private(), encShareList)

		log.LLvlf1("node %d, validPubKeys %+v, validEncShares %+v, validDecShares %+v", rs.Index(), validPubKeys, validEncShares, validDecShares)

		//we brodcast our decShares
		reply := &R1{Src: rs.Index(), Shares: validDecShares}
		if err := rs.Broadcast(reply); err != nil {
			return err
		}
		/*option 2 : we do share by share and we store them in a map as encShares

			for j := 0; j < rs.nodes; j++ {
				pubVerShare, err := pvss.DecShare(rs.Suite(), nil, rs.X[j], rs.pubPolys[].Eval(j).V, rs.Private(), rs.encShares[rs.Index()][j])
				if err != nil {
					log.LLvl1("jgjhgs")
					return err
				}
				//we know that our decShares are correct, we store them
				if _, ok := rs.decShares[rs.Index()]; !ok {
					rs.decShares[rs.Index()] = make(map[int]*pvss.PubVerShare)
				}
				rs.decShares[rs.Index()][j] = pubVerShare

				//we brodcast our decShares
				reply := &R1{Src: rs.Index(), Shares: rs.decShares[rs.Index()]}
				if err := rs.Broadcast(reply); err != nil {
					return err
				}
			}
		}*/
	}
	return nil
}

func (rs *RandShare) HandleR1(reply StructR1) error {
	msg := &reply.R1

	//we store the correct decShares
	for j := 0; j < len(msg.Shares); j++ {

		/*
			log.LLvlf1("Args: J %d, rs.X[j] %+v, rs.encShares[msg.Src][j] %+v, msg.Shares[j] %+v", j, rs.X[j], rs.encShares[j][msg.Src], msg.Shares[j])
			var encShareList []*pvss.PubVerShare
			for _, dS := range rs.encShares[msg.Src] {
				encShareList = append(encShareList, dS)
			}



			if decShares, err := pvss.VerifyDecShareBatch(rs.Suite(), nil, rs.X, encShareList, msg.Shares); err != nil {

				log.LLvlf1("nope %+v", decShares)
				return err
			}*/
		log.LLvlf1("index %d", msg.Shares[j].S.I)
		if err := pvss.VerifyDecShare(rs.Suite(), nil, rs.X[msg.Src], rs.encShares[msg.Src][msg.Shares[j].S.I], msg.Shares[j]); err != nil {
			log.LLvlf1("hahaha no")
			return err
		}
		//decShare is correct we store it
		if _, ok := rs.decShares[msg.Src]; !ok {
			rs.decShares[msg.Src] = make(map[int]*pvss.PubVerShare)
		}
		rs.decShares[msg.Src][j] = msg.Shares[j]
	}

	if len(rs.decShares[msg.Src]) == rs.nodes {
		/*we need all the shares to be sure to match the
		encShares in order to reconstruct the secret[msg.Src]*/
		var values []abstract.Point
		var encShareList []*pvss.PubVerShare
		var decShareList []*pvss.PubVerShare
		for j := 0; j < rs.nodes; j++ {
			values = append(values, rs.pubPoly.Eval(j).V)
			encShareList = append(encShareList, rs.encShares[msg.Src][j])
			decShareList = append(decShareList, rs.decShares[msg.Src][j])
		}
		// not correct, my shares are not in the same order as rs.X

		for index, encShare := range rs.encShares[msg.Src] {
			encShareList = append(encShareList, encShare)
			decShareList = append(decShareList, rs.decShares[msg.Src][index])
		}
		//pb is indexes : my list doesn't have the good ones*/
		X, E, _ := pvss.VerifyEncShareBatch(rs.Suite(), nil, rs.X, values, encShareList)
		log.LLvlf1("id %d, values %+v, encList %+v, X %+v, E %+v", rs.Index(), values, encShareList, X, E)
		D, _ := pvss.VerifyDecShareBatch(rs.Suite(), nil, rs.X, encShareList, decShareList)
		log.LLvlf1("id %d, enc %+v, dec %+v, D %+v", rs.Index(), decShareList, encShareList, D[0])

		secret, err := pvss.RecoverSecret(rs.Suite(), nil, rs.X, encShareList, decShareList, rs.threshold, rs.nodes)
		if err != nil {
			return err
		}
		rs.secrets[msg.Src] = secret
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

	return nil
}
