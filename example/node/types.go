package node

import (
	"github.com/getamis/alice/types"
	"google.golang.org/protobuf/proto"
)

type PeerConfig struct {
	Port     int64  `yaml:"port"`
	Identity string `yaml:"identity"`
	Peers    []struct {
		Id   string `yaml:"id"`
		Port int64  `yaml:"port"`
	} `yaml:"peers"`
}

type Message interface {
	types.Message
	proto.Message
}

type Backend[M Message, R any] interface {
	AddMessage(senderId string, msg types.Message) error
	Start()
	Stop()
	GetResult() (R, error)
}
