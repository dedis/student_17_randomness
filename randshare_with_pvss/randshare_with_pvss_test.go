package randsharepvss

import (
	"testing"
	"time"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

func TestRandShare(t *testing.T) {

	var name = "RandShare"
	var nodes = 5
	var faulty = nodes / 3
	var purpose = "RandShare test run"

	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(nodes, true)
	defer local.CloseAll()

	log.Lvlf1("randShare starting")
	protocol, err := local.CreateProtocol(name, tree)
	if err != nil {
		t.Fatal("couldn't initialize", err)
	}
	rs := protocol.(*RandShare)
	err = rs.Setup(nodes, faulty, purpose)
	if err != nil {
		t.Fatal("couldn't initialize", err)
	}
	err = rs.Start()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-rs.Done:
		log.Lvlf1("RandShare done")
		random, transcript, err := rs.Random()
		if err != nil {
			t.Fatal(err)
		}
		if err = rs.Verify(random, transcript); err != nil {
			t.Fatal(err)
		}
		log.Lvlf1("RandShare verified")
	case <-time.After(time.Second * time.Duration(nodes) * 2):
		t.Fatal("RandShare timeout")
	}
}

/*func TestRandShareScale(t *testing.T) {

	var name = "RandShare"
	var nodes int = 15 + 1 //+ 1 because we need to count in node 0 even if we won't work with it
	var faulty = 1
	var purpose string = "RandShare test run"

	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(nodes, true)
	defer local.CloseAll()

	log.Lvlf1("randShare starting")
	protocol, err := local.CreateProtocol(name, tree)
	if err != nil {
		t.Fatal("couldn't initialize", err)
	}
	rs := protocol.(*RandShare)
	err = rs.Setup(nodes, faulty, purpose)
	if err != nil {
		t.Fatal("couldn't initialize", err)
	}
	err = rs.Start()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-rs.Done:
		log.Lvlf1("RandShare done")
	case <-time.After(time.Second * time.Duration(nodes) * 2):
		t.Fatal("RandShare timeout")
	}
}*/
