// Code generated by protoc-gen-go. DO NOT EDIT.
// source: github.com/getamis/alice/crypto/homo/paillier/message.proto

package paillier

import (
	fmt "fmt"
	zkproof "github.com/getamis/alice/crypto/zkproof"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type PubKeyMessage struct {
	Proof                *zkproof.IntegerFactorizationProofMessage `protobuf:"bytes,1,opt,name=proof,proto3" json:"proof,omitempty"`
	G                    []byte                                    `protobuf:"bytes,2,opt,name=g,proto3" json:"g,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                  `json:"-"`
	XXX_unrecognized     []byte                                    `json:"-"`
	XXX_sizecache        int32                                     `json:"-"`
}

func (m *PubKeyMessage) Reset()         { *m = PubKeyMessage{} }
func (m *PubKeyMessage) String() string { return proto.CompactTextString(m) }
func (*PubKeyMessage) ProtoMessage()    {}
func (*PubKeyMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_3150a6ceeb3e2e19, []int{0}
}

func (m *PubKeyMessage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PubKeyMessage.Unmarshal(m, b)
}
func (m *PubKeyMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PubKeyMessage.Marshal(b, m, deterministic)
}
func (m *PubKeyMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PubKeyMessage.Merge(m, src)
}
func (m *PubKeyMessage) XXX_Size() int {
	return xxx_messageInfo_PubKeyMessage.Size(m)
}
func (m *PubKeyMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_PubKeyMessage.DiscardUnknown(m)
}

var xxx_messageInfo_PubKeyMessage proto.InternalMessageInfo

func (m *PubKeyMessage) GetProof() *zkproof.IntegerFactorizationProofMessage {
	if m != nil {
		return m.Proof
	}
	return nil
}

func (m *PubKeyMessage) GetG() []byte {
	if m != nil {
		return m.G
	}
	return nil
}

func init() {
	proto.RegisterType((*PubKeyMessage)(nil), "paillier.PubKeyMessage")
}

func init() {
	proto.RegisterFile("github.com/getamis/alice/crypto/homo/paillier/message.proto", fileDescriptor_3150a6ceeb3e2e19)
}

var fileDescriptor_3150a6ceeb3e2e19 = []byte{
	// 180 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xb2, 0x4e, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0x4f, 0x4f, 0x2d, 0x49, 0xcc, 0xcd, 0x2c, 0xd6, 0x4f,
	0xcc, 0xc9, 0x4c, 0x4e, 0xd5, 0x4f, 0x2e, 0xaa, 0x2c, 0x28, 0xc9, 0xd7, 0xcf, 0xc8, 0xcf, 0xcd,
	0xd7, 0x2f, 0x48, 0xcc, 0xcc, 0xc9, 0xc9, 0x4c, 0x2d, 0xd2, 0xcf, 0x4d, 0x2d, 0x2e, 0x4e, 0x4c,
	0x4f, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x80, 0x89, 0x4b, 0x99, 0x12, 0x32, 0xa6,
	0x2a, 0xbb, 0xa0, 0x28, 0x3f, 0x3f, 0x0d, 0xd5, 0x00, 0xa5, 0x38, 0x2e, 0xde, 0x80, 0xd2, 0x24,
	0xef, 0xd4, 0x4a, 0x5f, 0x88, 0xb0, 0x90, 0x3d, 0x17, 0x2b, 0x58, 0x9d, 0x04, 0xa3, 0x02, 0xa3,
	0x06, 0xb7, 0x91, 0xa6, 0x1e, 0x54, 0x9f, 0x9e, 0x67, 0x5e, 0x49, 0x6a, 0x7a, 0x6a, 0x91, 0x5b,
	0x62, 0x72, 0x49, 0x7e, 0x51, 0x66, 0x55, 0x62, 0x49, 0x66, 0x7e, 0x5e, 0x00, 0x48, 0x06, 0xaa,
	0x33, 0x08, 0xa2, 0x4f, 0x88, 0x87, 0x8b, 0x31, 0x5d, 0x82, 0x49, 0x81, 0x51, 0x83, 0x27, 0x88,
	0x31, 0x3d, 0x89, 0x0d, 0x6c, 0x8d, 0x31, 0x20, 0x00, 0x00, 0xff, 0xff, 0xea, 0x78, 0xaa, 0xed,
	0xe6, 0x00, 0x00, 0x00,
}