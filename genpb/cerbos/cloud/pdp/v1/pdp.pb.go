// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: cerbos/cloud/pdp/v1/pdp.proto

package pdpv1

import (
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Identifier struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Instance      string                 `protobuf:"bytes,1,opt,name=instance,proto3" json:"instance,omitempty"`
	Version       string                 `protobuf:"bytes,2,opt,name=version,proto3" json:"version,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Identifier) Reset() {
	*x = Identifier{}
	mi := &file_cerbos_cloud_pdp_v1_pdp_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Identifier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Identifier) ProtoMessage() {}

func (x *Identifier) ProtoReflect() protoreflect.Message {
	mi := &file_cerbos_cloud_pdp_v1_pdp_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Identifier.ProtoReflect.Descriptor instead.
func (*Identifier) Descriptor() ([]byte, []int) {
	return file_cerbos_cloud_pdp_v1_pdp_proto_rawDescGZIP(), []int{0}
}

func (x *Identifier) GetInstance() string {
	if x != nil {
		return x.Instance
	}
	return ""
}

func (x *Identifier) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

var File_cerbos_cloud_pdp_v1_pdp_proto protoreflect.FileDescriptor

const file_cerbos_cloud_pdp_v1_pdp_proto_rawDesc = "" +
	"\n" +
	"\x1dcerbos/cloud/pdp/v1/pdp.proto\x12\x13cerbos.cloud.pdp.v1\x1a\x1bbuf/validate/validate.proto\"T\n" +
	"\n" +
	"Identifier\x12#\n" +
	"\binstance\x18\x01 \x01(\tB\a\xbaH\x04r\x02\x10\x01R\binstance\x12!\n" +
	"\aversion\x18\x02 \x01(\tB\a\xbaH\x04r\x02\x10\x01R\aversionBt\n" +
	"\x1bdev.cerbos.api.cloud.v1.pdpZ;github.com/cerbos/cloud-api/genpb/cerbos/cloud/pdp/v1;pdpv1\xaa\x02\x17Cerbos.Api.Cloud.V1.Pdpb\x06proto3"

var (
	file_cerbos_cloud_pdp_v1_pdp_proto_rawDescOnce sync.Once
	file_cerbos_cloud_pdp_v1_pdp_proto_rawDescData []byte
)

func file_cerbos_cloud_pdp_v1_pdp_proto_rawDescGZIP() []byte {
	file_cerbos_cloud_pdp_v1_pdp_proto_rawDescOnce.Do(func() {
		file_cerbos_cloud_pdp_v1_pdp_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_cerbos_cloud_pdp_v1_pdp_proto_rawDesc), len(file_cerbos_cloud_pdp_v1_pdp_proto_rawDesc)))
	})
	return file_cerbos_cloud_pdp_v1_pdp_proto_rawDescData
}

var file_cerbos_cloud_pdp_v1_pdp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_cerbos_cloud_pdp_v1_pdp_proto_goTypes = []any{
	(*Identifier)(nil), // 0: cerbos.cloud.pdp.v1.Identifier
}
var file_cerbos_cloud_pdp_v1_pdp_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_cerbos_cloud_pdp_v1_pdp_proto_init() }
func file_cerbos_cloud_pdp_v1_pdp_proto_init() {
	if File_cerbos_cloud_pdp_v1_pdp_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_cerbos_cloud_pdp_v1_pdp_proto_rawDesc), len(file_cerbos_cloud_pdp_v1_pdp_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cerbos_cloud_pdp_v1_pdp_proto_goTypes,
		DependencyIndexes: file_cerbos_cloud_pdp_v1_pdp_proto_depIdxs,
		MessageInfos:      file_cerbos_cloud_pdp_v1_pdp_proto_msgTypes,
	}.Build()
	File_cerbos_cloud_pdp_v1_pdp_proto = out.File
	file_cerbos_cloud_pdp_v1_pdp_proto_goTypes = nil
	file_cerbos_cloud_pdp_v1_pdp_proto_depIdxs = nil
}
