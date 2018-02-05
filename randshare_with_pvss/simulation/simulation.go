package main

import (
	"time"

	"github.com/BurntSushi/toml"
	"github.com/dedis/student_17_randomness/randshare_with_pvss"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/simul"
	"gopkg.in/dedis/onet.v1/simul/monitor"
)

func init() {
	onet.SimulationRegister("RandSharePVSS", NewRSSimulation)
}

// RSSimulation implements a RandShare simulation
type RSSimulation struct {
	onet.SimulationBFTree
	Servers int
	Faulty  int
	Purpose string
}

// NewRSSimulation creates a new RandShare simulation
func NewRSSimulation(config string) (onet.Simulation, error) {
	rss := &RSSimulation{}
	_, err := toml.Decode(config, rss)
	if err != nil {
		return nil, err
	}
	return rss, nil
}

// Setup configures a RandShare simulation with certain parameters
func (rss *RSSimulation) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sim := new(onet.SimulationConfig)
	rss.CreateRoster(sim, hosts, 2000)
	err := rss.CreateTree(sim)
	return sim, err
}

// Run initiates a RansShare simulation
func (rss *RSSimulation) Run(config *onet.SimulationConfig) error {
	randM := monitor.NewTimeMeasure("tgen-randshare")
	bandW := monitor.NewCounterIOMeasure("bw-randshare", config.Server)
	client, err := config.Overlay.CreateProtocol("RandShare", config.Tree, onet.NilServiceID)
	if err != nil {
		return err
	}
	rs, _ := client.(*randsharepvss.RandShare)
	strartingTime := time.Now().Unix()
	err = rs.Setup(rss.Hosts, rss.Hosts/3, "Test", strartingTime)
	if err != nil {
		return err
	}

	if err := rs.Start(); err != nil {
		log.Error("Error while starting protcol:", err)
	}

	select {
	case <-rs.Done:
		randM.Record()
		bandW.Record()
		random, transcript, err := rs.Random()
		if err != nil {
			return err
		}
		log.Lvlf1("RandShare - done\nCollective string : %x", random)
		log.Lvlf1("RandShare - collective randomness: ok")

		verifyM := monitor.NewTimeMeasure("tver-randshare")
		err = randsharepvss.Verify(random, transcript)
		if err != nil {
			return err
		}
		verifyM.Record()
		log.Lvlf1("RandShare - verification: ok")

	case <-time.After(time.Second * time.Duration(rss.Hosts) * 10):
		log.Print("RandShare - time out")
	}
	return nil
}

func main() {
	simul.Start()
}
