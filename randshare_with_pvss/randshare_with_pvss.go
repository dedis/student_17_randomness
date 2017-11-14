package randsharepvss

import (
	"bytes"
	//"crypto"
	"errors"
	"time"

	"encoding/binary"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/share"
	"gopkg.in/dedis/crypto.v0/share/pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
)

func init() {
	onet.GlobalProtocolRegister("RandShare", NewRandShare)
}

// NewRandShare initialises the tree and network
func NewRandShare(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &RandShare{
		TreeNodeInstance: n,
	}
	err := t.RegisterHandlers(t.HandleA1, t.HandleR1)
	return t, err
}

//Setup initializes RandShare struct
func (rs *RandShare) Setup(nodes int, faulty int, purpose string) error {

	rs.nodes = nodes
	rs.faulty = faulty
	rs.threshold = faulty + 1
	rs.purpose = purpose
	rs.X = make([]abstract.Point, rs.nodes)
	for j := 0; j < rs.nodes; j++ {
		rs.X[j] = rs.List()[j].ServerIdentity.Public
	}
	rs.sessionID = rs.SessionID()
	rs.H, _ = rs.Suite().Point().Pick(nil, rs.Suite().Cipher(rs.sessionID))
	rs.pubPolys = make([]*share.PubPoly, rs.nodes)
	rs.encShares = make(map[int]map[int]*pvss.PubVerShare)
	rs.tracker = make(map[int]byte)
	rs.decShares = make(map[int]map[int]*pvss.PubVerShare)
	rs.secrets = make(map[int]abstract.Point)
	rs.coStringReady = false
	rs.Done = make(chan bool, 0)

	return nil
}

//Start starts the protocol from node 0
func (rs *RandShare) Start() error {

	rs.time = time.Now().Unix()

	encShares, pubPoly, err := pvss.EncShares(rs.Suite(), rs.H, rs.X, nil, rs.threshold)
	if err != nil {
		return err
	}
	rs.pubPolys[rs.Index()] = pubPoly
	b, commits := pubPoly.Info()

	for j := 0; j < rs.nodes; j++ {

		announce := &A1{
			SessionID: rs.SessionID(),
			Src:       rs.Index(),
			Share:     encShares[j],
			B:         b,
			Commits:   commits,
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

//HandleA1 handles the announce received is the sessionID is correct
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
		encShares, pubPoly, err := pvss.EncShares(rs.Suite(), rs.H, rs.X, nil, rs.threshold)
		if err != nil {
			return err
		}

		rs.pubPolys[rs.Index()] = pubPoly

		b, commits := pubPoly.Info()

		for j := 0; j < rs.nodes; j++ {
			announce := &A1{
				SessionID: rs.SessionID(),
				Src:       rs.Index(),
				Share:     encShares[j],
				B:         b,
				Commits:   commits,
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

	if !bytes.Equal(msg.SessionID, rs.sessionID) {
		return nil //If the sessionID is not correct we don't deal with the announce
	}

	//dealing with the msg : storing the encShare received if correct
	shareIndex := msg.Share.S.I
	pubPolySrc := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)
	rs.mutex.Lock()
	rs.pubPolys[msg.Src] = pubPolySrc
	rs.mutex.Unlock()
	value := pubPolySrc.Eval(shareIndex).V
	if err := pvss.VerifyEncShare(rs.Suite(), rs.H, rs.X[shareIndex], value, msg.Share); err == nil {
		//share is correct, we store it in the encShares map

		rs.mutex.Lock()
		if _, ok := rs.encShares[msg.Src]; !ok {
			rs.encShares[msg.Src] = make(map[int]*pvss.PubVerShare)
		}

		rs.encShares[msg.Src][shareIndex] = msg.Share
		rs.mutex.Unlock()
	}

	if len(rs.encShares[msg.Src]) == rs.threshold { //enough shares to recover

		rs.mutex.Lock()
		rs.tracker[msg.Src] = 1
		rs.mutex.Unlock()
	}

	if len(rs.tracker) == rs.nodes { //we can recover everything
		//we decrypt our shares one by one and send them (we put them in the Share struct before)

		var decShares []*Share //to store our dec shares
		for j := 0; j < rs.nodes; j++ {

			if _, ok := rs.encShares[j]; ok { //we have values on the line
				if encShare, ok := rs.encShares[j][rs.Index()]; ok { //we have a encrypted share on our column
					decShare, err := pvss.DecShare(rs.Suite(), rs.H, rs.X[rs.Index()], rs.pubPolys[j].Eval(rs.Index()).V, rs.Private(), encShare)
					if err != nil {
						return err
					}
					decShareStruct := &Share{Src: j, PubVerShare: decShare}
					decShares = append(decShares, decShareStruct)

					//the share is correct we store it
					rs.mutex.Lock()
					if _, ok := rs.decShares[j]; !ok {
						rs.decShares[j] = make(map[int]*pvss.PubVerShare)
					}
					rs.decShares[j][rs.Index()] = decShare
					rs.mutex.Unlock()
				}
			}
		}
		//we brodcast our decShares
		reply := &R1{SessionID: rs.SessionID(), Src: rs.Index(), Shares: decShares}
		if err := rs.Broadcast(reply); err != nil {
			return err
		}
	}
	return nil
}

//HandleR1 stores the decrypted shares and when we have enough, recover secrets
func (rs *RandShare) HandleR1(reply StructR1) error {

	msg := &reply.R1

	if !bytes.Equal(msg.SessionID, rs.sessionID) {
		return nil //If the sessionID is not correct we don't deal with the reply
	}

	//we store all the decShares (we don't have to verify as it will be in the RecoverSecret function)
	//verifing before storing
	for _, share := range msg.Shares {

		rs.mutex.Lock()
		if _, ok := rs.decShares[share.Src]; !ok {
			rs.decShares[share.Src] = make(map[int]*pvss.PubVerShare)
		}
		rs.decShares[share.Src][share.PubVerShare.S.I] = share.PubVerShare
		rs.mutex.Unlock()

		if len(rs.decShares[share.Src]) == rs.threshold { //we can recover src-th secret
			var encShareList []*pvss.PubVerShare
			var decShareList []*pvss.PubVerShare
			var keys []abstract.Point
			for i := 0; i < rs.nodes; i++ {
				if _, ok := rs.encShares[share.Src]; ok { //we have values on the line
					if encShare, ok := rs.encShares[share.Src][i]; ok { //we have a encrypted share on our column
						//we construct goodKeys and goddEncShares depending on
						encShareList = append(encShareList, encShare)
						decShareList = append(decShareList, share.PubVerShare)
						keys = append(keys, rs.X[i])
					}
				}
			}
			log.LLvlf1("Index %d, keys %+v, encShareList %+v, decShareList%+v", rs.Index(), keys, encShareList, decShareList)
			secret, err := pvss.RecoverSecret(rs.Suite(), rs.H, keys, encShareList, decShareList, rs.threshold, rs.nodes)
			if err != nil {
				//log.LLvlf1("RS INDEX %d recovering secret %d", rs.Index(), j)
				return err
			}
			rs.mutex.Lock()
			rs.secrets[share.Src] = secret
			rs.mutex.Unlock()

		}
		if (len(rs.secrets) == rs.nodes) && !rs.coStringReady {
			coString := rs.Suite().Point().Null()
			for j := range rs.secrets {
				abstract.Point.Add(coString, coString, rs.secrets[j])
			}
			rs.mutex.Lock()
			rs.coString = coString
			rs.mutex.Unlock()
			rs.coStringReady = true
			rs.Done <- true
		}
	}
	return nil
}

//Random returns the collective string created by our protocol and the
//associated transcript so that the secret can be verified by a third party
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
		H:         rs.H,
		PubPolys:  rs.pubPolys,
		EncShares: rs.encShares,
		DecShares: rs.decShares,
		secrets:   rs.secrets,
	}
	return rb, transcript, nil
}

//Verify is a method that verifies that following the transcript, we indeed created the random collective string
func (rs *RandShare) Verify(random []byte, transcript *Transcript) error {

	//verification of encrypted Shares
	for rowID, encShareMap := range transcript.EncShares {
		for colID, encShare := range encShareMap {
			if err := pvss.VerifyEncShare(transcript.Suite, transcript.H, transcript.X[colID], transcript.PubPolys[rowID].Eval(colID).V, encShare); err != nil {
				return err
			}
		}
	}

	//verification of decrypted shares
	for rowID, decShareMap := range transcript.DecShares {
		for colID, decShare := range decShareMap {
			if err := pvss.VerifyDecShare(transcript.Suite, transcript.H, transcript.X[colID], transcript.EncShares[rowID][colID], decShare); err != nil {
				return err
			}
		}
	}

	//verification of secrets
	for secretID, secretTransc := range transcript.secrets {
		var encShareList []*pvss.PubVerShare
		var decShareList []*pvss.PubVerShare
		for i := 0; i < rs.nodes; i++ {
			encShareList = append(encShareList, transcript.EncShares[secretID][i])
			decShareList = append(decShareList, transcript.DecShares[secretID][i])
		}

		secret, err := pvss.RecoverSecret(transcript.Suite, transcript.H, transcript.X, encShareList, decShareList, transcript.Faulty+1, transcript.Nodes)
		if err != nil {
			return err
		}
		if !secret.Equal(secretTransc) {
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

	if !bytes.Equal(bs, random) {
		return errors.New("CoString isn't correct")
	}

	return nil
}

//SessionID hashes the data hat caracterizes a particualar randShare protocol into a identifier
func (rs *RandShare) SessionID() []byte {

	//We put all the data into a byte buffer
	//data is composed of nodes, threhold, public keys
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, uint32(rs.nodes)); err != nil {
		return nil
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(rs.threshold)); err != nil {
		return nil
	}
	for _, key := range rs.X {
		keyB, err := key.MarshalBinary()
		if err != nil {
			return nil
		}
		if _, err := buf.Write((keyB)); err != nil {
			return nil
		}
	}
	//we hash our data and return it
	hash, _ := crypto.HashBytes(rs.Suite().Hash(), buf.Bytes())
	return hash
}
