package randshare

import (
	"testing"
	"time"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

func TestRandShare(t *testing.T) {

	var name = "RandShare"
	var nodes int = 5
	var faulty = 1
	/*
		var nodes int = 3
		var faulty = 2
	*/
	var purpose string = "RandShare test run"

	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(nodes, true)
	defer local.CloseAll()

	log.Lvlf1("randShare strarting")
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
		//need to ckeck if correct
	case <-time.After(time.Second * time.Duration(nodes) * 2):
		t.Fatal("RandShare timeout")
	}
}
