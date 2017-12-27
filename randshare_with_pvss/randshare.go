package main

import (
	"fmt"
	"github.com/dedis/student_17_randomness/randsharepvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"time"
)

func main() {

	fmt.Print("How many nodes would you like to work with ? (between 0 and 100) : ")
	var input int
	fmt.Scanln(&input)
	fmt.Print(input)

	var name = "RandShare"
	var nodes = input
	var faulty = nodes / 3
	var purpose = "RandShare test run"

	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(nodes, true)
	defer local.CloseAll()

	log.Lvlf1("randShare starting")
	protocol, err := local.CreateProtocol(name, tree)
	if err != nil {
		log.LLvlf1("couldn't initialize %s", err)
		return
	}
	rs := protocol.(*RandShare)
	startingTime := time.Now().Unix()
	err = rs.Setup(nodes, faulty, purpose, startingTime)
	if err != nil {
		log.LLvlf1("couldn't initialize %s", err)
		return
	}
	err = rs.Start()
	if err != nil {
		log.LLvlf1("couldn't start %s", err)
		return
	}
	select {
	case <-rs.Done:
		log.Lvlf1("RandShare done")
		random, transcript, err := rs.Random()
		if err != nil {
			log.LLvlf1("Random failed %s", err)
			return
		}
		if err = Verify(random, transcript); err != nil {
			log.LLvlf1("couldn't verify %s", err)
			return
		}
		log.Lvlf1("RandShare verified")
	case <-time.After(time.Second * time.Duration(nodes) * 2):
		log.LLvlf1("RandShare timeout")
	}
}
