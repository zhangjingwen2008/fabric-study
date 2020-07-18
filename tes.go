package main

import (
	"fmt"
	"github.com/hyperledger/fabric-modified/common/channelconfig"
)

func main() {
	fmt.Println("------> Start")
	fmt.Printf(channelconfig.ConsortiumKey)
	fmt.Println()
	fmt.Println("------> End")
}

type DefaultTemplatorSupport interface {
	// ConsortiumsConfig returns the ordering system channel's Consortiums config.
	ConsortiumsConfig() (channelconfig.Consortiums, bool)
}
