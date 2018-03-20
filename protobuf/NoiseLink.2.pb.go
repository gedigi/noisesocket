// Code generated by protoc-gen-go. DO NOT EDIT.
// source: NoiseLink.2.proto

/*
Package NoiseLink_2 is a generated protocol buffer package.

It is generated from these files:
	NoiseLink.2.proto

It has these top-level messages:
	NoiseLinkNegotiationDataRequest1
	NoiseLinkEarlyHandshakePayload
	NoiseLinkNegotiationDataResponse1
	NoiseLinkHandshakePayloadResponse1
	NoiseLinkHandshakePayloadRequest2
	NoiseZeroLinkHandshakePayloadRequest1
	NoiseZeroLinkHandshakePayloadResponse1
*/
package noisesocket

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type NoiseLinkNegotiationDataRequest1 struct {
	ServerName      string                          `protobuf:"bytes,1,opt,name=server_name,json=serverName" json:"server_name,omitempty"`
	InitialProtocol string                          `protobuf:"bytes,2,opt,name=initial_protocol,json=initialProtocol" json:"initial_protocol,omitempty"`
	SwitchProtocol  []string                        `protobuf:"bytes,3,rep,name=switch_protocol,json=switchProtocol" json:"switch_protocol,omitempty"`
	RetryProtocol   []string                        `protobuf:"bytes,4,rep,name=retry_protocol,json=retryProtocol" json:"retry_protocol,omitempty"`
	EarlyPayload    *NoiseLinkEarlyHandshakePayload `protobuf:"bytes,6,opt,name=early_payload,json=earlyPayload" json:"early_payload,omitempty"`
}

func (m *NoiseLinkNegotiationDataRequest1) Reset()         { *m = NoiseLinkNegotiationDataRequest1{} }
func (m *NoiseLinkNegotiationDataRequest1) String() string { return proto.CompactTextString(m) }
func (*NoiseLinkNegotiationDataRequest1) ProtoMessage()    {}
func (*NoiseLinkNegotiationDataRequest1) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{0}
}

func (m *NoiseLinkNegotiationDataRequest1) GetServerName() string {
	if m != nil {
		return m.ServerName
	}
	return ""
}

func (m *NoiseLinkNegotiationDataRequest1) GetInitialProtocol() string {
	if m != nil {
		return m.InitialProtocol
	}
	return ""
}

func (m *NoiseLinkNegotiationDataRequest1) GetSwitchProtocol() []string {
	if m != nil {
		return m.SwitchProtocol
	}
	return nil
}

func (m *NoiseLinkNegotiationDataRequest1) GetRetryProtocol() []string {
	if m != nil {
		return m.RetryProtocol
	}
	return nil
}

func (m *NoiseLinkNegotiationDataRequest1) GetEarlyPayload() *NoiseLinkEarlyHandshakePayload {
	if m != nil {
		return m.EarlyPayload
	}
	return nil
}

type NoiseLinkEarlyHandshakePayload struct {
	EvidenceRequestType []string `protobuf:"bytes,1,rep,name=evidence_request_type,json=evidenceRequestType" json:"evidence_request_type,omitempty"`
}

func (m *NoiseLinkEarlyHandshakePayload) Reset()                    { *m = NoiseLinkEarlyHandshakePayload{} }
func (m *NoiseLinkEarlyHandshakePayload) String() string            { return proto.CompactTextString(m) }
func (*NoiseLinkEarlyHandshakePayload) ProtoMessage()               {}
func (*NoiseLinkEarlyHandshakePayload) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *NoiseLinkEarlyHandshakePayload) GetEvidenceRequestType() []string {
	if m != nil {
		return m.EvidenceRequestType
	}
	return nil
}

type NoiseLinkNegotiationDataResponse1 struct {
	// Types that are valid to be assigned to Response:
	//	*NoiseLinkNegotiationDataResponse1_SwitchProtocol
	//	*NoiseLinkNegotiationDataResponse1_RetryProtocol
	//	*NoiseLinkNegotiationDataResponse1_Rejected
	Response isNoiseLinkNegotiationDataResponse1_Response `protobuf_oneof:"response"`
}

func (m *NoiseLinkNegotiationDataResponse1) Reset()         { *m = NoiseLinkNegotiationDataResponse1{} }
func (m *NoiseLinkNegotiationDataResponse1) String() string { return proto.CompactTextString(m) }
func (*NoiseLinkNegotiationDataResponse1) ProtoMessage()    {}
func (*NoiseLinkNegotiationDataResponse1) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{2}
}

type isNoiseLinkNegotiationDataResponse1_Response interface {
	isNoiseLinkNegotiationDataResponse1_Response()
}

type NoiseLinkNegotiationDataResponse1_SwitchProtocol struct {
	SwitchProtocol string `protobuf:"bytes,3,opt,name=switch_protocol,json=switchProtocol,oneof"`
}
type NoiseLinkNegotiationDataResponse1_RetryProtocol struct {
	RetryProtocol string `protobuf:"bytes,4,opt,name=retry_protocol,json=retryProtocol,oneof"`
}
type NoiseLinkNegotiationDataResponse1_Rejected struct {
	Rejected bool `protobuf:"varint,5,opt,name=rejected,oneof"`
}

func (*NoiseLinkNegotiationDataResponse1_SwitchProtocol) isNoiseLinkNegotiationDataResponse1_Response() {
}
func (*NoiseLinkNegotiationDataResponse1_RetryProtocol) isNoiseLinkNegotiationDataResponse1_Response() {
}
func (*NoiseLinkNegotiationDataResponse1_Rejected) isNoiseLinkNegotiationDataResponse1_Response() {}

func (m *NoiseLinkNegotiationDataResponse1) GetResponse() isNoiseLinkNegotiationDataResponse1_Response {
	if m != nil {
		return m.Response
	}
	return nil
}

func (m *NoiseLinkNegotiationDataResponse1) GetSwitchProtocol() string {
	if x, ok := m.GetResponse().(*NoiseLinkNegotiationDataResponse1_SwitchProtocol); ok {
		return x.SwitchProtocol
	}
	return ""
}

func (m *NoiseLinkNegotiationDataResponse1) GetRetryProtocol() string {
	if x, ok := m.GetResponse().(*NoiseLinkNegotiationDataResponse1_RetryProtocol); ok {
		return x.RetryProtocol
	}
	return ""
}

func (m *NoiseLinkNegotiationDataResponse1) GetRejected() bool {
	if x, ok := m.GetResponse().(*NoiseLinkNegotiationDataResponse1_Rejected); ok {
		return x.Rejected
	}
	return false
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*NoiseLinkNegotiationDataResponse1) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _NoiseLinkNegotiationDataResponse1_OneofMarshaler, _NoiseLinkNegotiationDataResponse1_OneofUnmarshaler, _NoiseLinkNegotiationDataResponse1_OneofSizer, []interface{}{
		(*NoiseLinkNegotiationDataResponse1_SwitchProtocol)(nil),
		(*NoiseLinkNegotiationDataResponse1_RetryProtocol)(nil),
		(*NoiseLinkNegotiationDataResponse1_Rejected)(nil),
	}
}

func _NoiseLinkNegotiationDataResponse1_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*NoiseLinkNegotiationDataResponse1)
	// response
	switch x := m.Response.(type) {
	case *NoiseLinkNegotiationDataResponse1_SwitchProtocol:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.SwitchProtocol)
	case *NoiseLinkNegotiationDataResponse1_RetryProtocol:
		b.EncodeVarint(4<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.RetryProtocol)
	case *NoiseLinkNegotiationDataResponse1_Rejected:
		t := uint64(0)
		if x.Rejected {
			t = 1
		}
		b.EncodeVarint(5<<3 | proto.WireVarint)
		b.EncodeVarint(t)
	case nil:
	default:
		return fmt.Errorf("NoiseLinkNegotiationDataResponse1.Response has unexpected type %T", x)
	}
	return nil
}

func _NoiseLinkNegotiationDataResponse1_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*NoiseLinkNegotiationDataResponse1)
	switch tag {
	case 3: // response.switch_protocol
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Response = &NoiseLinkNegotiationDataResponse1_SwitchProtocol{x}
		return true, err
	case 4: // response.retry_protocol
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Response = &NoiseLinkNegotiationDataResponse1_RetryProtocol{x}
		return true, err
	case 5: // response.rejected
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Response = &NoiseLinkNegotiationDataResponse1_Rejected{x != 0}
		return true, err
	default:
		return false, nil
	}
}

func _NoiseLinkNegotiationDataResponse1_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*NoiseLinkNegotiationDataResponse1)
	// response
	switch x := m.Response.(type) {
	case *NoiseLinkNegotiationDataResponse1_SwitchProtocol:
		n += proto.SizeVarint(3<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.SwitchProtocol)))
		n += len(x.SwitchProtocol)
	case *NoiseLinkNegotiationDataResponse1_RetryProtocol:
		n += proto.SizeVarint(4<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.RetryProtocol)))
		n += len(x.RetryProtocol)
	case *NoiseLinkNegotiationDataResponse1_Rejected:
		n += proto.SizeVarint(5<<3 | proto.WireVarint)
		n += 1
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type NoiseLinkHandshakePayloadResponse1 struct {
	EvidenceRequestType []string `protobuf:"bytes,1,rep,name=evidence_request_type,json=evidenceRequestType" json:"evidence_request_type,omitempty"`
	EvidenceBlobType    []string `protobuf:"bytes,2,rep,name=evidence_blob_type,json=evidenceBlobType" json:"evidence_blob_type,omitempty"`
	EvidenceBlob        [][]byte `protobuf:"bytes,3,rep,name=evidence_blob,json=evidenceBlob,proto3" json:"evidence_blob,omitempty"`
}

func (m *NoiseLinkHandshakePayloadResponse1) Reset()         { *m = NoiseLinkHandshakePayloadResponse1{} }
func (m *NoiseLinkHandshakePayloadResponse1) String() string { return proto.CompactTextString(m) }
func (*NoiseLinkHandshakePayloadResponse1) ProtoMessage()    {}
func (*NoiseLinkHandshakePayloadResponse1) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{3}
}

func (m *NoiseLinkHandshakePayloadResponse1) GetEvidenceRequestType() []string {
	if m != nil {
		return m.EvidenceRequestType
	}
	return nil
}

func (m *NoiseLinkHandshakePayloadResponse1) GetEvidenceBlobType() []string {
	if m != nil {
		return m.EvidenceBlobType
	}
	return nil
}

func (m *NoiseLinkHandshakePayloadResponse1) GetEvidenceBlob() [][]byte {
	if m != nil {
		return m.EvidenceBlob
	}
	return nil
}

type NoiseLinkHandshakePayloadRequest2 struct {
	EvidenceBlobType []string `protobuf:"bytes,2,rep,name=evidence_blob_type,json=evidenceBlobType" json:"evidence_blob_type,omitempty"`
	EvidenceBlob     [][]byte `protobuf:"bytes,3,rep,name=evidence_blob,json=evidenceBlob,proto3" json:"evidence_blob,omitempty"`
}

func (m *NoiseLinkHandshakePayloadRequest2) Reset()         { *m = NoiseLinkHandshakePayloadRequest2{} }
func (m *NoiseLinkHandshakePayloadRequest2) String() string { return proto.CompactTextString(m) }
func (*NoiseLinkHandshakePayloadRequest2) ProtoMessage()    {}
func (*NoiseLinkHandshakePayloadRequest2) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{4}
}

func (m *NoiseLinkHandshakePayloadRequest2) GetEvidenceBlobType() []string {
	if m != nil {
		return m.EvidenceBlobType
	}
	return nil
}

func (m *NoiseLinkHandshakePayloadRequest2) GetEvidenceBlob() [][]byte {
	if m != nil {
		return m.EvidenceBlob
	}
	return nil
}

type NoiseZeroLinkHandshakePayloadRequest1 struct {
	EvidenceRequestType []string `protobuf:"bytes,1,rep,name=evidence_request_type,json=evidenceRequestType" json:"evidence_request_type,omitempty"`
	EvidenceBlobType    []string `protobuf:"bytes,2,rep,name=evidence_blob_type,json=evidenceBlobType" json:"evidence_blob_type,omitempty"`
	EvidenceBlob        [][]byte `protobuf:"bytes,3,rep,name=evidence_blob,json=evidenceBlob,proto3" json:"evidence_blob,omitempty"`
}

func (m *NoiseZeroLinkHandshakePayloadRequest1) Reset()         { *m = NoiseZeroLinkHandshakePayloadRequest1{} }
func (m *NoiseZeroLinkHandshakePayloadRequest1) String() string { return proto.CompactTextString(m) }
func (*NoiseZeroLinkHandshakePayloadRequest1) ProtoMessage()    {}
func (*NoiseZeroLinkHandshakePayloadRequest1) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{5}
}

func (m *NoiseZeroLinkHandshakePayloadRequest1) GetEvidenceRequestType() []string {
	if m != nil {
		return m.EvidenceRequestType
	}
	return nil
}

func (m *NoiseZeroLinkHandshakePayloadRequest1) GetEvidenceBlobType() []string {
	if m != nil {
		return m.EvidenceBlobType
	}
	return nil
}

func (m *NoiseZeroLinkHandshakePayloadRequest1) GetEvidenceBlob() [][]byte {
	if m != nil {
		return m.EvidenceBlob
	}
	return nil
}

type NoiseZeroLinkHandshakePayloadResponse1 struct {
	EvidenceBlobType []string `protobuf:"bytes,2,rep,name=evidence_blob_type,json=evidenceBlobType" json:"evidence_blob_type,omitempty"`
	EvidenceBlob     [][]byte `protobuf:"bytes,3,rep,name=evidence_blob,json=evidenceBlob,proto3" json:"evidence_blob,omitempty"`
}

func (m *NoiseZeroLinkHandshakePayloadResponse1) Reset() {
	*m = NoiseZeroLinkHandshakePayloadResponse1{}
}
func (m *NoiseZeroLinkHandshakePayloadResponse1) String() string { return proto.CompactTextString(m) }
func (*NoiseZeroLinkHandshakePayloadResponse1) ProtoMessage()    {}
func (*NoiseZeroLinkHandshakePayloadResponse1) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{6}
}

func (m *NoiseZeroLinkHandshakePayloadResponse1) GetEvidenceBlobType() []string {
	if m != nil {
		return m.EvidenceBlobType
	}
	return nil
}

func (m *NoiseZeroLinkHandshakePayloadResponse1) GetEvidenceBlob() [][]byte {
	if m != nil {
		return m.EvidenceBlob
	}
	return nil
}

func init() {
	proto.RegisterType((*NoiseLinkNegotiationDataRequest1)(nil), "NoiseLinkNegotiationDataRequest1")
	proto.RegisterType((*NoiseLinkEarlyHandshakePayload)(nil), "NoiseLinkEarlyHandshakePayload")
	proto.RegisterType((*NoiseLinkNegotiationDataResponse1)(nil), "NoiseLinkNegotiationDataResponse1")
	proto.RegisterType((*NoiseLinkHandshakePayloadResponse1)(nil), "NoiseLinkHandshakePayloadResponse1")
	proto.RegisterType((*NoiseLinkHandshakePayloadRequest2)(nil), "NoiseLinkHandshakePayloadRequest2")
	proto.RegisterType((*NoiseZeroLinkHandshakePayloadRequest1)(nil), "NoiseZeroLinkHandshakePayloadRequest1")
	proto.RegisterType((*NoiseZeroLinkHandshakePayloadResponse1)(nil), "NoiseZeroLinkHandshakePayloadResponse1")
}

func init() { proto.RegisterFile("NoiseLink.2.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 399 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xcc, 0x92, 0xcf, 0xea, 0xd3, 0x40,
	0x10, 0xc7, 0x7f, 0xdb, 0x6a, 0x69, 0xa7, 0x7f, 0x8d, 0x08, 0x39, 0x88, 0x8d, 0x91, 0xda, 0x14,
	0xa4, 0xd0, 0xf8, 0x06, 0xa5, 0x42, 0x0f, 0x52, 0x4a, 0xe8, 0xc9, 0x4b, 0xd8, 0x24, 0x83, 0x5d,
	0x9b, 0x66, 0xe3, 0x66, 0xad, 0x04, 0xaf, 0xbe, 0x88, 0x67, 0xc1, 0x67, 0x94, 0x6c, 0xd2, 0x6d,
	0xb5, 0xb5, 0x82, 0x28, 0x78, 0xcc, 0x77, 0x3e, 0x93, 0x99, 0xfd, 0xec, 0xc2, 0x83, 0x15, 0x67,
	0x19, 0xbe, 0x66, 0xc9, 0x6e, 0xea, 0x4e, 0x53, 0xc1, 0x25, 0xb7, 0x3f, 0xd7, 0xc0, 0xd2, 0xe9,
	0x0a, 0xdf, 0x72, 0xc9, 0xa8, 0x64, 0x3c, 0x59, 0x50, 0x49, 0x3d, 0x7c, 0xff, 0x01, 0x33, 0x39,
	0x33, 0x86, 0xd0, 0xce, 0x50, 0x1c, 0x50, 0xf8, 0x09, 0xdd, 0xa3, 0x49, 0x2c, 0xe2, 0xb4, 0x3c,
	0x28, 0xa3, 0x15, 0xdd, 0xa3, 0x31, 0x81, 0x01, 0x4b, 0x98, 0x64, 0x34, 0xf6, 0xd5, 0x6f, 0x43,
	0x1e, 0x9b, 0x35, 0x45, 0xf5, 0xab, 0x7c, 0x5d, 0xc5, 0xc6, 0x18, 0xfa, 0xd9, 0x47, 0x26, 0xc3,
	0xed, 0x89, 0xac, 0x5b, 0x75, 0xa7, 0xe5, 0xf5, 0xca, 0x58, 0x83, 0x23, 0xe8, 0x09, 0x94, 0x22,
	0x3f, 0x71, 0xf7, 0x14, 0xd7, 0x55, 0xa9, 0xc6, 0x16, 0xd0, 0x45, 0x2a, 0xe2, 0xdc, 0x4f, 0x69,
	0x1e, 0x73, 0x1a, 0x99, 0x0d, 0x8b, 0x38, 0x6d, 0x77, 0x38, 0xd5, 0xa7, 0x7a, 0x55, 0x94, 0x97,
	0x34, 0x89, 0xb2, 0x2d, 0xdd, 0xe1, 0xba, 0xc4, 0xbc, 0x8e, 0xea, 0xaa, 0xbe, 0xec, 0x0d, 0x3c,
	0xb9, 0xcd, 0x1b, 0x2e, 0x3c, 0xc2, 0x03, 0x8b, 0x30, 0x09, 0xd1, 0x17, 0xa5, 0x18, 0x5f, 0xe6,
	0x69, 0x61, 0xa3, 0xd8, 0xea, 0xe1, 0xb1, 0x58, 0x49, 0xdb, 0xe4, 0x29, 0xda, 0x5f, 0x08, 0x3c,
	0xfd, 0xb5, 0xdc, 0x2c, 0xe5, 0x49, 0x86, 0x33, 0x63, 0x72, 0xcd, 0x08, 0x71, 0x5a, 0xcb, 0xbb,
	0x0b, 0x27, 0xe3, 0x2b, 0x4e, 0x4a, 0xf2, 0x27, 0x2b, 0x8f, 0xa1, 0x29, 0xf0, 0x1d, 0x86, 0x12,
	0x23, 0xf3, 0xbe, 0x45, 0x9c, 0xe6, 0xf2, 0xce, 0xd3, 0xc9, 0x1c, 0x8a, 0x6a, 0x39, 0xde, 0xfe,
	0x4a, 0xc0, 0xd6, 0x3b, 0x5e, 0x58, 0xd2, 0x4b, 0xfe, 0xc1, 0xf1, 0x8d, 0x17, 0x60, 0xe8, 0x9e,
	0x20, 0xe6, 0x41, 0xd9, 0x50, 0x53, 0x0d, 0x83, 0x63, 0x65, 0x1e, 0xf3, 0x40, 0xd1, 0xcf, 0xa0,
	0xfb, 0x03, 0xad, 0x9e, 0x45, 0xc7, 0xeb, 0x9c, 0x83, 0xf6, 0xe1, 0x4c, 0xe8, 0xe5, 0xb2, 0x6a,
	0xb4, 0xfb, 0x2f, 0xe6, 0x7e, 0x23, 0x30, 0x52, 0x83, 0xdf, 0xa0, 0xe0, 0x37, 0x86, 0xff, 0x37,
	0xa2, 0x3e, 0xc1, 0xf3, 0xdf, 0xec, 0x7b, 0xbc, 0xd9, 0xbf, 0x3f, 0x3c, 0x68, 0xa8, 0xe7, 0xf9,
	0xf2, 0x7b, 0x00, 0x00, 0x00, 0xff, 0xff, 0x25, 0xc1, 0xdb, 0x5e, 0x70, 0x04, 0x00, 0x00,
}
