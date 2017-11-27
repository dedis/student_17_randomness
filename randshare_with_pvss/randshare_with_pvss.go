package randsharepvss

import (
	"bytes"
	"errors"

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

//NewRandShare initialises the tree and network
func NewRandShare(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &RandShare{
		TreeNodeInstance: n,
	}
	err := t.RegisterHandlers(t.HandleA1, t.HandleR1)
	return t, err
}

//Setup initializes RandShare struct, computes the private keys and the second base point based on the sessionID
func (rs *RandShare) Setup(nodes int, faulty int, purpose string, time int64) error {

	rs.startingTime = time
	rs.nodes = nodes
	rs.faulty = faulty
	rs.threshold = faulty + 1
	rs.purpose = purpose
	rs.X = make([]abstract.Point, rs.nodes)
	for j := 0; j < rs.nodes; j++ {
		rs.X[j] = rs.List()[j].ServerIdentity.Public
	}

	rs.sessionID = SessionID(rs.Suite(), rs.nodes, rs.faulty, rs.X, rs.purpose, time)
	rs.H, _ = rs.Suite().Point().Pick(nil, rs.Suite().Cipher(rs.sessionID))

	rs.pubPolys = make([]*share.PubPoly, rs.nodes)
	rs.encShares = make(map[int]map[int]*pvss.PubVerShare)
	rs.tracker = make(map[int]byte)
	for i := 0; i < rs.nodes; i++ {
		rs.tracker[i] = 0
	}

	rs.decShares = make(map[int]map[int]*pvss.PubVerShare)

	for i := 0; i < rs.nodes; i++ {
		rs.encShares[i] = make(map[int]*pvss.PubVerShare)
		rs.decShares[i] = make(map[int]*pvss.PubVerShare)
	}

	rs.secrets = make(map[int]abstract.Point)
	rs.coStringReady = false
	rs.Done = make(chan bool, 0)

	return nil
}

//Start starts the protocol from node 0
func (rs *RandShare) Start() error {

	encShares, pubPoly, err := pvss.EncShares(rs.Suite(), rs.H, rs.X, nil, rs.threshold)
	if err != nil {
		return err
	}
	rs.pubPolys[rs.Index()] = pubPoly
	b, commits := pubPoly.Info()

	for j := 0; j < rs.nodes; j++ {

		announce := &A1{
			SessionID: rs.sessionID,
			Src:       rs.Index(),
			Share:     encShares[j],
			B:         b,
			Commits:   commits,
			Purpose:   rs.purpose,
			Time:      rs.startingTime,
		}

		//we know they are correct, we can store them and put the tracker to 1
		rs.encShares[rs.Index()][j] = encShares[j]
		rs.tracker[rs.Index()] = 1

		if err := rs.Broadcast(announce); err != nil {
			return err
		}
	}
	return nil
}

//HandleA1 handles the announces of the session
func (rs *RandShare) HandleA1(announce StructA1) error {

	msg := &announce.A1

	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	//if it's our first message, we set up rs and send our shares before anwsering
	if rs.nodes == 0 {
		//rs.mutex.Lock()
		nodes := len(rs.List())
		//2/3 would prevent network splitting attacks but less efficient
		if err := rs.Setup(nodes, nodes/3, msg.Purpose, msg.Time); err != nil {
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
				SessionID: rs.sessionID,
				Src:       rs.Index(),
				Share:     encShares[j],
				B:         b,
				Commits:   commits,
			}

			//we know they are correct, we can store them
			rs.encShares[rs.Index()][j] = encShares[j]
			rs.tracker[rs.Index()] = 1

			if err := rs.Broadcast(announce); err != nil {
				return err
			}
		}
		//rs.mutex.Unlock()
	}

	if !bytes.Equal(msg.SessionID, rs.sessionID) {
		return nil //If the sessionID is not correct we don't deal with the announce
	}
	if rs.tracker[msg.Src] != 1 { //if tracker is at 0 we need to store more shares

		shareIndex := msg.Share.S.I
		pubPolySrc := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)
		//rs.mutex.Lock()
		rs.pubPolys[msg.Src] = pubPolySrc
		//rs.mutex.Unlock()
		value := pubPolySrc.Eval(shareIndex).V
		if err := pvss.VerifyEncShare(rs.Suite(), rs.H, rs.X[shareIndex], value, msg.Share); err == nil {
			//share is correct, we store it in the encShares map
			//rs.mutex.Lock()
			rs.encShares[msg.Src][shareIndex] = msg.Share
			//rs.mutex.Unlock()
		}

		if len(rs.encShares[msg.Src]) == rs.threshold { //enough shares to recover
			//rs.mutex.Lock()
			rs.tracker[msg.Src] = 1
			//	rs.mutex.Unlock()
		}

		if len(rs.tracker) == rs.nodes { //we can recover everything
			//we decrypt our shares one by one and send them (we put them in the Share struct before)
			var decShares []*Share //to store our dec shares
			for j := 0; j < rs.nodes; j++ {
				if encShare, ok := rs.encShares[j][rs.Index()]; ok { //we have an encrypted share
					decShare, err := pvss.DecShare(rs.Suite(), rs.H, rs.X[rs.Index()], rs.pubPolys[j].Eval(rs.Index()).V, rs.Private(), encShare)
					if err != nil {
						return err
					}
					decShareStruct := &Share{Src: j, PubVerShare: decShare}
					decShares = append(decShares, decShareStruct)

					//the share is correct we store it
					//rs.mutex.Lock()
					rs.decShares[j][rs.Index()] = decShare
					//rs.mutex.Unlock()
				}
			}

			//we brodcast our decShares
			reply := &R1{SessionID: rs.sessionID, Src: rs.Index(), Shares: decShares}
			if err := rs.Broadcast(reply); err != nil {
				return err
			}
		}
	}
	return nil
}

//HandleR1 stores the decrypted shares and when we have enough, recovers the secrets
func (rs *RandShare) HandleR1(reply StructR1) error {

	msg := &reply.R1
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if !bytes.Equal(msg.SessionID, rs.sessionID) {
		return nil //If the sessionID is not correct we don't deal with the reply
	}

	for _, share := range msg.Shares {
		//for every share, if the secret is not computed yet for the share.src, we store threshold correct shares and recover the secret
		if _, ok := rs.secrets[share.Src]; !ok {
			if _, ok = rs.encShares[share.Src][share.PubVerShare.S.I]; ok {
				if err := pvss.VerifyDecShare(rs.Suite(), nil, rs.X[share.PubVerShare.S.I], rs.encShares[share.Src][share.PubVerShare.S.I], share.PubVerShare); err == nil {
					//rs.mutex.Lock()
					rs.decShares[share.Src][share.PubVerShare.S.I] = share.PubVerShare
					//rs.mutex.Unlock()
				}

				if len(rs.decShares[share.Src]) == rs.threshold { //we can recover src-th secret
					var encShareList []*pvss.PubVerShare
					var decShareList []*pvss.PubVerShare
					var keys []abstract.Point
					for i := 0; i < rs.nodes; i++ {
						if encShare, ok := rs.encShares[share.Src][i]; ok { //we have a encrypted share => we have a decShare
							//we construct goodKeys and goddEncShares depending on
							if decShare, ok := rs.decShares[share.Src][i]; ok {
								encShareList = append(encShareList, encShare)
								decShareList = append(decShareList, decShare)
								keys = append(keys, rs.X[i])
							}
						}
					}

					secret, err := pvss.RecoverSecret(rs.Suite(), nil, keys, encShareList, decShareList, rs.threshold, rs.nodes)
					if err != nil {
						log.LLvlf1("RS INDEX %d recovering secret %d", rs.Index(), share.Src)
						return err
					}
					//rs.mutex.Lock()
					rs.secrets[share.Src] = secret
					//rs.mutex.Unlock()
				}
			}
			if (len(rs.secrets) == rs.nodes) && !rs.coStringReady {
				coString := rs.Suite().Point().Null()
				for j := range rs.secrets {
					abstract.Point.Add(coString, coString, rs.secrets[j])
				}
				//rs.mutex.Lock()
				rs.coString = coString
				//rs.mutex.Unlock()
				rs.coStringReady = true
				rs.Done <- true
			}
		}
	}
	return nil
}

//Random returns the collective string created by our protocol and the
//associated transcript so that the secret can be verified by a third party
func (rs *RandShare) Random() ([]byte, *Transcript, error) {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()

	if !rs.coStringReady {
		return nil, nil, errors.New("Not ready")
	}
	rb, err := rs.coString.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	transcript := &Transcript{
		SessionID: rs.sessionID,
		Suite:     rs.Suite(),
		Nodes:     rs.nodes,
		Faulty:    rs.faulty,
		Purpose:   rs.purpose,
		Time:      rs.startingTime,
		X:         rs.X,
		H:         rs.H,
		PubPolys:  rs.pubPolys,
		EncShares: rs.encShares,
		DecShares: rs.decShares,
		secrets:   rs.secrets,
	}
	return rb, transcript, nil
}

//Verify is a method that verifies that we created the random collective string following the transcript
func Verify(random []byte, transcript *Transcript) error {

	//verification of sessionID
	sid := SessionID(transcript.Suite, transcript.Nodes, transcript.Faulty, transcript.X, transcript.Purpose, transcript.Time)
	if !bytes.Equal(transcript.SessionID, sid) {
		return errors.New("Wrong session identifier")
	}

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
			if err := pvss.VerifyDecShare(transcript.Suite, nil, transcript.X[colID], transcript.EncShares[rowID][colID], decShare); err != nil {
				return err
			}
		}
	}

	//verification of secrets
	for secretID, secretTransc := range transcript.secrets {

		//first we construct list of shares we use
		var encShareList []*pvss.PubVerShare
		var decShareList []*pvss.PubVerShare
		var keys []abstract.Point
		for j, share := range transcript.DecShares[secretID] {
			encShareList = append(encShareList, transcript.EncShares[secretID][j])
			decShareList = append(decShareList, share)
			keys = append(keys, transcript.X[j])
		}

		secret, err := pvss.RecoverSecret(transcript.Suite, nil, keys, encShareList, decShareList, transcript.Faulty+1, transcript.Nodes)
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

	//everything was correct
	return nil
}

//SessionID hashes the data(suite, nodes, faulty, public keys, purpose, strating time) that caracterizes a particualar randShare protocol into a session identifier
func SessionID(suite abstract.Suite, nodes int, faulty int, X []abstract.Point, purpose string, time int64) []byte {

	//We put all the data into a byte buffer
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, uint32(nodes)); err != nil {
		return nil
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(faulty)); err != nil {
		return nil
	}
	for _, key := range X {
		keyB, err := key.MarshalBinary()
		if err != nil {
			return nil
		}
		if _, err := buf.Write((keyB)); err != nil {
			return nil
		}
	}
	if _, err := buf.WriteString(purpose); err != nil {
		return nil
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(time)); err != nil {
		return nil
	}
	//we hash our data and return it
	hash, _ := crypto.HashBytes(suite.Hash(), buf.Bytes())
	return hash
}
