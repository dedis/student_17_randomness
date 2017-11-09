package randsharepvss

import (
	"bytes"
	"errors"
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

	rs.time = time.Now().Unix() // time.Now.Unix()

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
		rs.mutex.Lock()
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
		rs.mutex.Unlock()
	}

	//dealing with the msg : storing the encShare received if correct
	shareIndex := msg.Share.S.I
	pubPolySrc := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)
	rs.mutex.Lock()
	rs.pubPolys[msg.Src] = pubPolySrc
	rs.mutex.Unlock()
	value := pubPolySrc.Eval(shareIndex).V
	if err := pvss.VerifyEncShare(rs.Suite(), nil, rs.X[shareIndex], value, msg.Share); err == nil {
		//share is correct, we store it in the encShares map

		if _, ok := rs.encShares[msg.Src]; !ok {
			rs.encShares[msg.Src] = make(map[int]*pvss.PubVerShare)
		}
		rs.mutex.Lock()
		rs.encShares[msg.Src][shareIndex] = msg.Share
		rs.mutex.Unlock()
	}

	if len(rs.encShares[msg.Src]) == rs.nodes { //the ligne encShares[msg.src] is full

		rs.mutex.Lock()
		rs.tracker[msg.Src] = 1
		rs.mutex.Unlock()
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

			//how to go from j to share-src ? : eval pub[j] at rs.Index and see if == ?
			if _, ok := rs.decShares[j]; !ok {
				rs.decShares[j] = make(map[int]*pvss.PubVerShare)
			}
			rs.mutex.Lock()
			rs.decShares[j][rs.Index()] = validDecShares[j]
			rs.mutex.Unlock()
		}

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

	//we store all the decShares (we don't have to verify as it will be in the RecoverSecret function)
	for j := 0; j < len(msg.Shares); j++ {
		if _, ok := rs.decShares[j]; !ok {
			rs.decShares[j] = make(map[int]*pvss.PubVerShare)
		}
		rs.mutex.Lock()
		rs.decShares[j][msg.Src] = msg.Shares[j]
		rs.mutex.Unlock()

		if len(rs.decShares[j]) == rs.nodes { //the line is full : we recover j-th secret

			var encShareList []*pvss.PubVerShare
			var decShareList []*pvss.PubVerShare
			for i := 0; i < rs.nodes; i++ {
				//we construct goodKeys and goddEncShares depending on
				encShareList = append(encShareList, rs.encShares[j][i])
				decShareList = append(decShareList, rs.decShares[j][i])
			}

			secret, err := pvss.RecoverSecret(rs.Suite(), nil, rs.X, encShareList, decShareList, rs.threshold, rs.nodes)
			if err != nil {
				return err
			}
			rs.mutex.Lock()
			rs.secrets[j] = secret
			rs.mutex.Unlock()

		}
		if (len(rs.secrets) == rs.nodes) && !rs.coStringReady {
			coString := rs.Suite().Point().Null()
			for j := range rs.secrets {
				abstract.Point.Add(coString, coString, rs.secrets[j])
			}
			log.Lvlf1("Costring recovered at node %d is %+v", rs.Index(), coString)
			rs.mutex.Lock()
			rs.coString = coString
			rs.mutex.Unlock()
			rs.coStringReady = true
			rs.Done <- true
		}
	}
	return nil
}

func (rs *RandShare) Random() ([]byte, *Transcript, error) {
	if !rs.coStringReady {
		return nil, nil, errors.New("Not ready")
	}
	rb, err := rs.coString.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	transcript := &Transcript{
		Suite:     rs.Suite(),
		Nodes:     rs.nodes,
		Faulty:    rs.faulty,
		Purpose:   rs.purpose,
		Time:      rs.time,
		X:         rs.X,
		PubPolys:  rs.pubPolys,
		EncShares: rs.encShares,
		DecShares: rs.decShares,
		secrets:   rs.secrets,
	}
	return rb, transcript, nil
}

func (rs *RandShare) Verify(random []byte, transcript *Transcript) error {

	//verification of encrypted Shares
	for rowId, encShareMap := range transcript.EncShares {
		for colId, encShare := range encShareMap {
			if err := pvss.VerifyEncShare(transcript.Suite, nil, transcript.X[rowId], transcript.PubPolys[colId].Eval(colId).V, encShare); err != nil {
				return err
			}
		}
	}

	//verification of decrypted shares
	for rowId, decShareMap := range transcript.DecShares {
		for colId, share := range decShareMap {
			if err := pvss.VerifyDecShare(transcript.Suite, nil, transcript.X[rowId], transcript.EncShares[rowId][colId], share); err != nil {
				return err
			}
		}
	}

	//verification of secrets
	for s := range transcript.secrets {
		var encShareList []*pvss.PubVerShare
		var decShareList []*pvss.PubVerShare
		for i := 0; i < rs.nodes; i++ {
			encShareList = append(encShareList, transcript.EncShares[s][i])
			decShareList = append(decShareList, transcript.DecShares[s][i])
		}

		secret, err := pvss.RecoverSecret(transcript.Suite, nil, transcript.X, encShareList, decShareList, transcript.Faulty+1, transcript.Nodes)
		if err != nil {
			return err
		}
		if secret != transcript.secrets[s] {
			return errors.New("Secret recovered is not correct")
		}
	}

	//verification of the final coString
	coString := transcript.Suite.Point().Null()
	for j := range transcript.secrets {
		abstract.Point.Add(coString, coString, transcript.secrets[j])
	}
	bs, err := coString.MarshalBinary()
	if err != nil {
		return err
	}

	if bytes.Equal(bs, random) {
		return errors.New("CoString isn't correct")
	}

	return nil
}
