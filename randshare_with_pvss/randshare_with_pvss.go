package randsharepvss

import (
	"bytes"
	"errors"
	//"time"

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
	err := t.RegisterHandlers(t.HandleA1, t.HandleV1, t.HandleR1)
	return t, err
}

//Setup initializes RandShare struct, computes the private keys and the second base point based on the sessionID
func (rs *RandShare) Setup(nodes int, faulty int, purpose string, time int64) error {

	rs.startingTime = time
	rs.nodes = nodes
	rs.nPrime = 0
	rs.faulty = faulty
	rs.threshold = faulty + 1
	rs.purpose = purpose
	rs.X = rs.Roster().Publics()
	//rs.X = make([]abstract.Point, rs.nodes)
	rs.pubPolys = make([]*share.PubPoly, rs.nodes)
	rs.encShares = make(map[int]map[int]*pvss.PubVerShare)
	rs.tracker = make(map[int]int)
	rs.votes = make(map[int]*Vote)
	rs.decShares = make(map[int]map[int]*pvss.PubVerShare)

	for i := 0; i < rs.nodes; i++ {
		//rs.X[i] = rs.List()[i].ServerIdentity.Public
		rs.encShares[i] = make(map[int]*pvss.PubVerShare)
		rs.decShares[i] = make(map[int]*pvss.PubVerShare)
		rs.votes[i] = &Vote{Voted: false, Vote: 0}
	}

	rs.sessionID = SessionID(rs.Suite(), rs.nodes, rs.faulty, rs.X, rs.purpose, time)
	rs.H, _ = rs.Suite().Point().Pick(nil, rs.Suite().Cipher(rs.sessionID))

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
	rs.mutex.Lock()
	rs.pubPolys[rs.Index()] = pubPoly
	b, commits := pubPoly.Info()

	announce := &A1{
		SessionID: rs.sessionID,
		Src:       rs.Index(),
		Shares:    encShares,
		B:         b,
		Commits:   commits,
		Purpose:   rs.purpose,
		Time:      rs.startingTime,
	}

	for j := 0; j < rs.nodes; j++ {
		//we know they are correct, we can store them, put the tracker to 1 and update our vote
		rs.encShares[rs.Index()][j] = encShares[j]
		rs.tracker[rs.Index()] = 1
	}
	rs.mutex.Unlock()
	if err := rs.Broadcast(announce); err != nil {
		return err
	}
	return nil
}

//HandleA1 handles the announces of the session
func (rs *RandShare) HandleA1(announce StructA1) error {

	msg := &announce.A1

	if rs.nodes == 0 { //we need to setup rs and brodcast our encrypted shares
		rs.mutex.Lock()
		nodes := len(rs.List())
		if err := rs.Setup(nodes, nodes/3, msg.Purpose, msg.Time); err != nil {
			return err
		}
		encShares, pubPoly, err := pvss.EncShares(rs.Suite(), rs.H, rs.X, nil, rs.threshold)
		if err != nil {
			return err
		}
		rs.pubPolys[rs.Index()] = pubPoly
		b, commits := pubPoly.Info()
		announce := &A1{
			SessionID: rs.sessionID,
			Src:       rs.Index(),
			Shares:    encShares,
			B:         b,
			Commits:   commits,
			Purpose:   rs.purpose,
			Time:      rs.startingTime,
		}
		for j := 0; j < rs.nodes; j++ {
			//we know they are correct, we can store them
			rs.encShares[rs.Index()][j] = encShares[j]
			rs.tracker[rs.Index()] = 1
		}
		rs.mutex.Unlock()
		if err := rs.Broadcast(announce); err != nil {
			return err
		}
	}

	if _, ok := rs.tracker[msg.Src]; ok || !bytes.Equal(msg.SessionID, rs.sessionID) {
		return nil //If the sessionID is not correct or we already got shares from that sender we don't deal with the announce
	}

	rs.mutex.Lock()
	pubPolySrc := share.NewPubPoly(rs.Suite(), msg.B, msg.Commits)
	rs.pubPolys[msg.Src] = pubPolySrc
	//rs.mutex.Unlock()
	for _, share := range msg.Shares {
		shareIndex := share.S.I
		value := pubPolySrc.Eval(shareIndex).V

		if err := pvss.VerifyEncShare(rs.Suite(), rs.H, rs.X[shareIndex], value, share); err == nil {
			//share is correct, we store it in the encShares map
			//	rs.mutex.Lock()
			rs.encShares[msg.Src][shareIndex] = share
			//	rs.mutex.Unlock()
		}

		if len(rs.encShares[msg.Src]) > 2*rs.faulty {
			//	rs.mutex.Lock()
			rs.tracker[msg.Src] = 1
			//	rs.mutex.Unlock()
		} else {
			//	rs.mutex.Lock()
			rs.tracker[msg.Src] = -1
			//	rs.mutex.Unlock()
		}
	}
	if len(rs.tracker) == rs.nodes { //we had announce from everyone
		for index, vote := range rs.tracker {
			if vote == 1 { //we have at least 2*rs.faulty correct encrypted shares for that index
				//rs.mutex.Lock()
				rs.votes[index].Vote = 1
				//rs.mutex.Unlock()
			}
		}
		rs.votes[rs.Index()].Voted = true
		//we say that we are done by sending our votes
		step := &V1{SessionID: rs.sessionID, Src: rs.Index(), Votes: rs.votes}
		if err := rs.Broadcast(step); err != nil {
			return err
		}
	}
	rs.mutex.Unlock()
	return nil
}

//HandleV1 sends the decrypted shares when has received everyone's vote (means they are done storing their encrypted shares)
func (rs *RandShare) HandleV1(step StructV1) error {

	msg := &step.V1

	if !bytes.Equal(msg.SessionID, rs.sessionID) || rs.votes[msg.Src].Voted {
		return nil //If the sessionID is not correct or we already have a vote from that node we don't deal with the message
	}

	rs.mutex.Lock()
	for index, vote := range msg.Votes {
		rs.votes[index].Vote += vote.Vote
	}
	rs.votes[msg.Src].Voted = true
	rs.mutex.Unlock()
	for _, vote := range rs.votes {
		if !vote.Voted { //one node hasn't voted yet
			return nil
		}
	}

	//if we reach this step, everyone voted so we can
	//Compute the number n' of good nodes (thos with a vote greater than faulty), clean our tracker to use it in the next step and brodcast our shares
	for _, vote := range rs.votes {
		if vote.Vote > rs.faulty { //good node
			rs.mutex.Lock()
			rs.nPrime += 1
			rs.mutex.Unlock()
		}
	}

	if rs.nPrime < rs.faulty {
		return errors.New("Too many faulty nodes")
	}
	rs.mutex.Lock()
	rs.tracker = make(map[int]int)
	rs.mutex.Unlock()

	var decShares []*Share //The list we will send
	for j := 0; j < rs.nodes; j++ {
		if encShare, ok := rs.encShares[j][rs.Index()]; ok { //we have an encrypted share, we can thus verify the decryted share
			decShare, err := pvss.DecShare(rs.Suite(), rs.H, rs.X[rs.Index()], rs.pubPolys[j].Eval(rs.Index()).V, rs.Private(), encShare)
			if err != nil {
				return err
			}
			//our shares are correct we store them and add them to the shares we'll send
			rs.mutex.Lock()
			rs.decShares[j][rs.Index()] = decShare
			rs.mutex.Unlock()
			decShareStruct := &Share{Src: j, PubVerShare: decShare}
			decShares = append(decShares, decShareStruct)
		}
	}
	reply := &R1{SessionID: rs.sessionID, Src: rs.Index(), Shares: decShares}
	if err := rs.Broadcast(reply); err != nil {
		return err
	}
	return nil
}

//HandleR1 stores the decrypted shares and when we have enough, recovers the secret of good nodes
func (rs *RandShare) HandleR1(reply StructR1) error {

	msg := &reply.R1

	if _, ok := rs.tracker[msg.Src]; ok || !bytes.Equal(msg.SessionID, rs.sessionID) {
		return nil //If the sessionID is not correct or we had decrypted shares from that node already, we don't deal with the reply
	}
	rs.mutex.Lock()
	rs.tracker[msg.Src] = 1 //we received something
	rs.mutex.Unlock()
	for _, shareWr := range msg.Shares {
		if _, ok := rs.secrets[shareWr.Src]; !ok || (rs.votes[shareWr.Src].Vote <= rs.faulty) { //if the share.src-th secret is already recovered or has too many negative votes we don't deal with this share
			if encShare, ok := rs.encShares[shareWr.Src][msg.Src]; ok {
				if err := pvss.VerifyDecShare(rs.Suite(), nil, rs.X[msg.Src], encShare, shareWr.PubVerShare); err == nil {
					rs.mutex.Lock()
					rs.decShares[shareWr.Src][msg.Src] = shareWr.PubVerShare
					rs.mutex.Unlock()
				} else {
					//	log.LLvlf1("got here for %d ", rs.Index())

					if rs.Index() == 0 {
						//	log.LLvlf1("got here for %d with err %+v", rs.Index(), err)
					}
				}

				if len(rs.decShares[shareWr.Src]) == rs.threshold { //we can recover src-th secret

					//if len(rs.decShares[share.Src]) == rs.threshold + 1 { +1 as cant verif own share
					var encShareList []*pvss.PubVerShare
					var decShareList []*pvss.PubVerShare
					var keys []abstract.Point

					for i := 0; i < rs.nodes; i++ {
						if decShare, ok := rs.decShares[shareWr.Src][i]; ok {
							encShareList = append(encShareList, rs.encShares[shareWr.Src][i]) //we are sure to have an encShare as we verified it
							decShareList = append(decShareList, decShare)
							keys = append(keys, rs.X[i])
						}
					}

					secret, err := pvss.RecoverSecret(rs.Suite(), nil, keys, encShareList, decShareList, rs.threshold, rs.nPrime)
					if err != nil {
						/* beg of tests
						mapE := make(map[int]*pvss.PubVerShare)
						mapD := make(map[int]*pvss.PubVerShare)
						for _, share2 := range encShareList {
							mapE[share2.S.I] = share2
						}
						for _, share2 := range decShareList {
							mapD[share2.S.I] = share2
						}
						D, _ := pvss.VerifyDecShareBatch(rs.Suite(), nil, keys, encShareList, decShareList)
						log.LLvlf1("err %+v thres %d \nencshares %+v \ndechshares %+v \n D %+v", err, rs.threshold, mapE, mapD, D)
						for i := 0; i < len(keys); i++ {
							if err3 := pvss.VerifyDecShare(rs.Suite(), nil, keys[i], encShareList[i], decShareList[i]); err3 != nil {
								//public key should be good as keys[i].Equal(rs.X[rs.Index()])
								log.LLvlf1("err %+v for rs.Index %d, share %d at index %d", err3, rs.Index(), encShareList[i].S.I, i)
							}
						}
						/*end of test*/
						return err
					}

					rs.mutex.Lock()
					rs.secrets[shareWr.Src] = secret
					rs.mutex.Unlock()
				}
			}

			if (len(rs.secrets) == rs.nPrime) && !rs.coStringReady { //we can recover the secret for all good nodes
				coString := rs.Suite().Point().Null()
				for j := range rs.secrets {
					abstract.Point.Add(coString, coString, rs.secrets[j])
				}
				rs.mutex.Lock()
				rs.coString = coString
				rs.mutex.Unlock()
				log.LLvlf1("COSTRING RECOVERED AT NODE %d %+v", rs.Index(), coString)
				rs.coStringReady = true
				rs.Done <- true
			}
		} else {
			//log.LLvlf1("in the else")
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
		Votes:     rs.votes,
		Secrets:   rs.secrets,
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
	for secretID, secretTransc := range transcript.Secrets {

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
	for j := range transcript.Secrets {
		abstract.Point.Add(coString, coString, transcript.Secrets[j])
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
