package main

import (
	"fmt"
	"github.com/dedis/student_17_randomness/randshare_with_pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"time"
)

func main() {

	fmt.Print("How many nodes ?  [0; 100] : ")
	var input int
	fmt.Scanln(&input)

	var name = "RandShare"
	var nodes = input
	var faulty = nodes / 3
	var purpose = "RandShare test run"

	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(nodes, true)
	defer local.CloseAll()

	fmt.Print("\nRandShare starting\n\n")
	protocol, err := local.CreateProtocol(name, tree)
	if err != nil {
		log.LLvlf1("couldn't initialize %s", err)
		return
	}
	rs := protocol.(*randsharepvss.RandShare)
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
		random, transcript, err := rs.Random()
		fmt.Printf("Collective randomness : %x\nTime stamp %s\n", random, time.Unix(startingTime, 0))
		if err != nil {
			log.LLvlf1("Random failed %s", err)
			return
		}
		if err = randsharepvss.Verify(random, transcript); err != nil {
			log.LLvlf1("couldn't verify %s", err)
			return
		}
		fmt.Print("Verification : ok\n")
	case <-time.After(time.Second * time.Duration(nodes) * 2):
		log.LLvlf1("RandShare timeout")
	}
}
