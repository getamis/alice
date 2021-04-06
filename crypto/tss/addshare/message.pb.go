// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.6.1
// source: github.com/getamis/alice/crypto/tss/addshare/message.proto

package addshare

import (
	birkhoffinterpolation "github.com/getamis/alice/crypto/birkhoffinterpolation"
	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	zkproof "github.com/getamis/alice/crypto/zkproof"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Type int32

const (
	Type_OldPeer Type = 0
	Type_NewBk   Type = 1
	Type_Compute Type = 2
	Type_Result  Type = 3
	Type_Verify  Type = 4
)

// Enum value maps for Type.
var (
	Type_name = map[int32]string{
		0: "OldPeer",
		1: "NewBk",
		2: "Compute",
		3: "Result",
		4: "Verify",
	}
	Type_value = map[string]int32{
		"OldPeer": 0,
		"NewBk":   1,
		"Compute": 2,
		"Result":  3,
		"Verify":  4,
	}
)

func (x Type) Enum() *Type {
	p := new(Type)
	*p = x
	return p
}

func (x Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Type) Descriptor() protoreflect.EnumDescriptor {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_enumTypes[0].Descriptor()
}

func (Type) Type() protoreflect.EnumType {
	return &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_enumTypes[0]
}

func (x Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Type.Descriptor instead.
func (Type) EnumDescriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP(), []int{0}
}

type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type Type   `protobuf:"varint,1,opt,name=type,proto3,enum=addshare.Type" json:"type,omitempty"`
	Id   string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	// Types that are assignable to Body:
	//	*Message_OldPeer
	//	*Message_NewBk
	//	*Message_Compute
	//	*Message_Result
	//	*Message_Verify
	Body isMessage_Body `protobuf_oneof:"body"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP(), []int{0}
}

func (x *Message) GetType() Type {
	if x != nil {
		return x.Type
	}
	return Type_OldPeer
}

func (x *Message) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (m *Message) GetBody() isMessage_Body {
	if m != nil {
		return m.Body
	}
	return nil
}

func (x *Message) GetOldPeer() *BodyOldPeer {
	if x, ok := x.GetBody().(*Message_OldPeer); ok {
		return x.OldPeer
	}
	return nil
}

func (x *Message) GetNewBk() *BodyNewBk {
	if x, ok := x.GetBody().(*Message_NewBk); ok {
		return x.NewBk
	}
	return nil
}

func (x *Message) GetCompute() *BodyCompute {
	if x, ok := x.GetBody().(*Message_Compute); ok {
		return x.Compute
	}
	return nil
}

func (x *Message) GetResult() *BodyResult {
	if x, ok := x.GetBody().(*Message_Result); ok {
		return x.Result
	}
	return nil
}

func (x *Message) GetVerify() *BodyVerify {
	if x, ok := x.GetBody().(*Message_Verify); ok {
		return x.Verify
	}
	return nil
}

type isMessage_Body interface {
	isMessage_Body()
}

type Message_OldPeer struct {
	OldPeer *BodyOldPeer `protobuf:"bytes,3,opt,name=old_peer,json=oldPeer,proto3,oneof"`
}

type Message_NewBk struct {
	NewBk *BodyNewBk `protobuf:"bytes,4,opt,name=new_bk,json=newBk,proto3,oneof"`
}

type Message_Compute struct {
	Compute *BodyCompute `protobuf:"bytes,5,opt,name=compute,proto3,oneof"`
}

type Message_Result struct {
	Result *BodyResult `protobuf:"bytes,6,opt,name=result,proto3,oneof"`
}

type Message_Verify struct {
	Verify *BodyVerify `protobuf:"bytes,7,opt,name=verify,proto3,oneof"`
}

func (*Message_OldPeer) isMessage_Body() {}

func (*Message_NewBk) isMessage_Body() {}

func (*Message_Compute) isMessage_Body() {}

func (*Message_Result) isMessage_Body() {}

func (*Message_Verify) isMessage_Body() {}

type BodyOldPeer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Bk          *birkhoffinterpolation.BkParameterMessage `protobuf:"bytes,1,opt,name=bk,proto3" json:"bk,omitempty"`
	SiGProofMsg *zkproof.SchnorrProofMessage              `protobuf:"bytes,2,opt,name=siGProofMsg,proto3" json:"siGProofMsg,omitempty"`
	Pubkey      *ecpointgrouplaw.EcPointMessage           `protobuf:"bytes,3,opt,name=pubkey,proto3" json:"pubkey,omitempty"`
	Threshold   uint32                                    `protobuf:"varint,4,opt,name=threshold,proto3" json:"threshold,omitempty"`
}

func (x *BodyOldPeer) Reset() {
	*x = BodyOldPeer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BodyOldPeer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BodyOldPeer) ProtoMessage() {}

func (x *BodyOldPeer) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BodyOldPeer.ProtoReflect.Descriptor instead.
func (*BodyOldPeer) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP(), []int{1}
}

func (x *BodyOldPeer) GetBk() *birkhoffinterpolation.BkParameterMessage {
	if x != nil {
		return x.Bk
	}
	return nil
}

func (x *BodyOldPeer) GetSiGProofMsg() *zkproof.SchnorrProofMessage {
	if x != nil {
		return x.SiGProofMsg
	}
	return nil
}

func (x *BodyOldPeer) GetPubkey() *ecpointgrouplaw.EcPointMessage {
	if x != nil {
		return x.Pubkey
	}
	return nil
}

func (x *BodyOldPeer) GetThreshold() uint32 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

type BodyNewBk struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Bk *birkhoffinterpolation.BkParameterMessage `protobuf:"bytes,1,opt,name=bk,proto3" json:"bk,omitempty"`
}

func (x *BodyNewBk) Reset() {
	*x = BodyNewBk{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BodyNewBk) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BodyNewBk) ProtoMessage() {}

func (x *BodyNewBk) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BodyNewBk.ProtoReflect.Descriptor instead.
func (*BodyNewBk) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP(), []int{2}
}

func (x *BodyNewBk) GetBk() *birkhoffinterpolation.BkParameterMessage {
	if x != nil {
		return x.Bk
	}
	return nil
}

type BodyCompute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Delta       []byte                       `protobuf:"bytes,1,opt,name=delta,proto3" json:"delta,omitempty"`
	SiGProofMsg *zkproof.SchnorrProofMessage `protobuf:"bytes,2,opt,name=siGProofMsg,proto3" json:"siGProofMsg,omitempty"`
}

func (x *BodyCompute) Reset() {
	*x = BodyCompute{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BodyCompute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BodyCompute) ProtoMessage() {}

func (x *BodyCompute) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BodyCompute.ProtoReflect.Descriptor instead.
func (*BodyCompute) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP(), []int{3}
}

func (x *BodyCompute) GetDelta() []byte {
	if x != nil {
		return x.Delta
	}
	return nil
}

func (x *BodyCompute) GetSiGProofMsg() *zkproof.SchnorrProofMessage {
	if x != nil {
		return x.SiGProofMsg
	}
	return nil
}

type BodyResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Delta []byte `protobuf:"bytes,1,opt,name=delta,proto3" json:"delta,omitempty"`
}

func (x *BodyResult) Reset() {
	*x = BodyResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BodyResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BodyResult) ProtoMessage() {}

func (x *BodyResult) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BodyResult.ProtoReflect.Descriptor instead.
func (*BodyResult) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP(), []int{4}
}

func (x *BodyResult) GetDelta() []byte {
	if x != nil {
		return x.Delta
	}
	return nil
}

type BodyVerify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SiGProofMsg *zkproof.SchnorrProofMessage `protobuf:"bytes,1,opt,name=siGProofMsg,proto3" json:"siGProofMsg,omitempty"`
}

func (x *BodyVerify) Reset() {
	*x = BodyVerify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BodyVerify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BodyVerify) ProtoMessage() {}

func (x *BodyVerify) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BodyVerify.ProtoReflect.Descriptor instead.
func (*BodyVerify) Descriptor() ([]byte, []int) {
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP(), []int{5}
}

func (x *BodyVerify) GetSiGProofMsg() *zkproof.SchnorrProofMessage {
	if x != nil {
		return x.SiGProofMsg
	}
	return nil
}

var File_github_com_getamis_alice_crypto_tss_addshare_message_proto protoreflect.FileDescriptor

var file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDesc = []byte{
	0x0a, 0x3a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74,
	0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x2f, 0x74, 0x73, 0x73, 0x2f, 0x61, 0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2f, 0x6d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x61, 0x64,
	0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x1a, 0x3e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65,
	0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x62, 0x69, 0x72, 0x6b, 0x68, 0x6f, 0x66, 0x66,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x70, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x62, 0x6b,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x3b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65,
	0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f, 0x65, 0x63, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x67,
	0x72, 0x6f, 0x75, 0x70, 0x6c, 0x61, 0x77, 0x2f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x67, 0x65, 0x74, 0x61, 0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0x2f, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2f, 0x6d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xba, 0x02, 0x0a, 0x07, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x22, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x0e, 0x2e, 0x61, 0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2e,
	0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x32, 0x0a, 0x08, 0x6f, 0x6c,
	0x64, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x61,
	0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2e, 0x42, 0x6f, 0x64, 0x79, 0x4f, 0x6c, 0x64, 0x50,
	0x65, 0x65, 0x72, 0x48, 0x00, 0x52, 0x07, 0x6f, 0x6c, 0x64, 0x50, 0x65, 0x65, 0x72, 0x12, 0x2c,
	0x0a, 0x06, 0x6e, 0x65, 0x77, 0x5f, 0x62, 0x6b, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13,
	0x2e, 0x61, 0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2e, 0x42, 0x6f, 0x64, 0x79, 0x4e, 0x65,
	0x77, 0x42, 0x6b, 0x48, 0x00, 0x52, 0x05, 0x6e, 0x65, 0x77, 0x42, 0x6b, 0x12, 0x31, 0x0a, 0x07,
	0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e,
	0x61, 0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2e, 0x42, 0x6f, 0x64, 0x79, 0x43, 0x6f, 0x6d,
	0x70, 0x75, 0x74, 0x65, 0x48, 0x00, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x12,
	0x2e, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x14, 0x2e, 0x61, 0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2e, 0x42, 0x6f, 0x64, 0x79, 0x52,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x48, 0x00, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x12,
	0x2e, 0x0a, 0x06, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x14, 0x2e, 0x61, 0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x2e, 0x42, 0x6f, 0x64, 0x79, 0x56,
	0x65, 0x72, 0x69, 0x66, 0x79, 0x48, 0x00, 0x52, 0x06, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x42,
	0x06, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0xdf, 0x01, 0x0a, 0x0b, 0x42, 0x6f, 0x64, 0x79,
	0x4f, 0x6c, 0x64, 0x50, 0x65, 0x65, 0x72, 0x12, 0x39, 0x0a, 0x02, 0x62, 0x6b, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x62, 0x69, 0x72, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x70, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x42, 0x6b, 0x50, 0x61,
	0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x02,
	0x62, 0x6b, 0x12, 0x3e, 0x0a, 0x0b, 0x73, 0x69, 0x47, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x73,
	0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f,
	0x66, 0x2e, 0x53, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0b, 0x73, 0x69, 0x47, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4d,
	0x73, 0x67, 0x12, 0x37, 0x0a, 0x06, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x65, 0x63, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x67, 0x72, 0x6f, 0x75,
	0x70, 0x6c, 0x61, 0x77, 0x2e, 0x45, 0x63, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x4d, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x52, 0x06, 0x70, 0x75, 0x62, 0x6b, 0x65, 0x79, 0x12, 0x1c, 0x0a, 0x09, 0x74,
	0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09,
	0x74, 0x68, 0x72, 0x65, 0x73, 0x68, 0x6f, 0x6c, 0x64, 0x22, 0x46, 0x0a, 0x09, 0x42, 0x6f, 0x64,
	0x79, 0x4e, 0x65, 0x77, 0x42, 0x6b, 0x12, 0x39, 0x0a, 0x02, 0x62, 0x6b, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x29, 0x2e, 0x62, 0x69, 0x72, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x70, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x42, 0x6b, 0x50, 0x61, 0x72,
	0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x02, 0x62,
	0x6b, 0x22, 0x63, 0x0a, 0x0b, 0x42, 0x6f, 0x64, 0x79, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x12, 0x3e, 0x0a, 0x0b, 0x73, 0x69, 0x47, 0x50, 0x72, 0x6f,
	0x6f, 0x66, 0x4d, 0x73, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x7a, 0x6b,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2e, 0x53, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x50, 0x72, 0x6f,
	0x6f, 0x66, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0b, 0x73, 0x69, 0x47, 0x50, 0x72,
	0x6f, 0x6f, 0x66, 0x4d, 0x73, 0x67, 0x22, 0x22, 0x0a, 0x0a, 0x42, 0x6f, 0x64, 0x79, 0x52, 0x65,
	0x73, 0x75, 0x6c, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x22, 0x4c, 0x0a, 0x0a, 0x42, 0x6f,
	0x64, 0x79, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x12, 0x3e, 0x0a, 0x0b, 0x73, 0x69, 0x47, 0x50,
	0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x73, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e,
	0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x2e, 0x53, 0x63, 0x68, 0x6e, 0x6f, 0x72, 0x72, 0x50,
	0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x52, 0x0b, 0x73, 0x69, 0x47,
	0x50, 0x72, 0x6f, 0x6f, 0x66, 0x4d, 0x73, 0x67, 0x2a, 0x43, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x0b, 0x0a, 0x07, 0x4f, 0x6c, 0x64, 0x50, 0x65, 0x65, 0x72, 0x10, 0x00, 0x12, 0x09, 0x0a,
	0x05, 0x4e, 0x65, 0x77, 0x42, 0x6b, 0x10, 0x01, 0x12, 0x0b, 0x0a, 0x07, 0x43, 0x6f, 0x6d, 0x70,
	0x75, 0x74, 0x65, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x10,
	0x03, 0x12, 0x0a, 0x0a, 0x06, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x10, 0x04, 0x42, 0x2e, 0x5a,
	0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x65, 0x74, 0x61,
	0x6d, 0x69, 0x73, 0x2f, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x2f, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x2f, 0x74, 0x73, 0x73, 0x2f, 0x61, 0x64, 0x64, 0x73, 0x68, 0x61, 0x72, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescOnce sync.Once
	file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescData = file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDesc
)

func file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescGZIP() []byte {
	file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescOnce.Do(func() {
		file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescData)
	})
	return file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDescData
}

var file_github_com_getamis_alice_crypto_tss_addshare_message_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_github_com_getamis_alice_crypto_tss_addshare_message_proto_goTypes = []interface{}{
	(Type)(0),           // 0: addshare.Type
	(*Message)(nil),     // 1: addshare.Message
	(*BodyOldPeer)(nil), // 2: addshare.BodyOldPeer
	(*BodyNewBk)(nil),   // 3: addshare.BodyNewBk
	(*BodyCompute)(nil), // 4: addshare.BodyCompute
	(*BodyResult)(nil),  // 5: addshare.BodyResult
	(*BodyVerify)(nil),  // 6: addshare.BodyVerify
	(*birkhoffinterpolation.BkParameterMessage)(nil), // 7: birkhoffinterpolation.BkParameterMessage
	(*zkproof.SchnorrProofMessage)(nil),              // 8: zkproof.SchnorrProofMessage
	(*ecpointgrouplaw.EcPointMessage)(nil),           // 9: ecpointgrouplaw.EcPointMessage
}
var file_github_com_getamis_alice_crypto_tss_addshare_message_proto_depIdxs = []int32{
	0,  // 0: addshare.Message.type:type_name -> addshare.Type
	2,  // 1: addshare.Message.old_peer:type_name -> addshare.BodyOldPeer
	3,  // 2: addshare.Message.new_bk:type_name -> addshare.BodyNewBk
	4,  // 3: addshare.Message.compute:type_name -> addshare.BodyCompute
	5,  // 4: addshare.Message.result:type_name -> addshare.BodyResult
	6,  // 5: addshare.Message.verify:type_name -> addshare.BodyVerify
	7,  // 6: addshare.BodyOldPeer.bk:type_name -> birkhoffinterpolation.BkParameterMessage
	8,  // 7: addshare.BodyOldPeer.siGProofMsg:type_name -> zkproof.SchnorrProofMessage
	9,  // 8: addshare.BodyOldPeer.pubkey:type_name -> ecpointgrouplaw.EcPointMessage
	7,  // 9: addshare.BodyNewBk.bk:type_name -> birkhoffinterpolation.BkParameterMessage
	8,  // 10: addshare.BodyCompute.siGProofMsg:type_name -> zkproof.SchnorrProofMessage
	8,  // 11: addshare.BodyVerify.siGProofMsg:type_name -> zkproof.SchnorrProofMessage
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_github_com_getamis_alice_crypto_tss_addshare_message_proto_init() }
func file_github_com_getamis_alice_crypto_tss_addshare_message_proto_init() {
	if File_github_com_getamis_alice_crypto_tss_addshare_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BodyOldPeer); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BodyNewBk); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BodyCompute); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BodyResult); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BodyVerify); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Message_OldPeer)(nil),
		(*Message_NewBk)(nil),
		(*Message_Compute)(nil),
		(*Message_Result)(nil),
		(*Message_Verify)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_getamis_alice_crypto_tss_addshare_message_proto_goTypes,
		DependencyIndexes: file_github_com_getamis_alice_crypto_tss_addshare_message_proto_depIdxs,
		EnumInfos:         file_github_com_getamis_alice_crypto_tss_addshare_message_proto_enumTypes,
		MessageInfos:      file_github_com_getamis_alice_crypto_tss_addshare_message_proto_msgTypes,
	}.Build()
	File_github_com_getamis_alice_crypto_tss_addshare_message_proto = out.File
	file_github_com_getamis_alice_crypto_tss_addshare_message_proto_rawDesc = nil
	file_github_com_getamis_alice_crypto_tss_addshare_message_proto_goTypes = nil
	file_github_com_getamis_alice_crypto_tss_addshare_message_proto_depIdxs = nil
}
