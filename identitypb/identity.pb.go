// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: identity.proto

package identitypb

import (
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

type GetExpireSessionCookieRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetExpireSessionCookieRequest) Reset() {
	*x = GetExpireSessionCookieRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_identity_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetExpireSessionCookieRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetExpireSessionCookieRequest) ProtoMessage() {}

func (x *GetExpireSessionCookieRequest) ProtoReflect() protoreflect.Message {
	mi := &file_identity_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetExpireSessionCookieRequest.ProtoReflect.Descriptor instead.
func (*GetExpireSessionCookieRequest) Descriptor() ([]byte, []int) {
	return file_identity_proto_rawDescGZIP(), []int{0}
}

type Cookie struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name     string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Value    string `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	Domain   string `protobuf:"bytes,3,opt,name=domain,proto3" json:"domain,omitempty"`
	Path     string `protobuf:"bytes,4,opt,name=path,proto3" json:"path,omitempty"`
	Expires  int64  `protobuf:"varint,5,opt,name=expires,proto3" json:"expires,omitempty"`
	SameSite string `protobuf:"bytes,6,opt,name=same_site,json=sameSite,proto3" json:"same_site,omitempty"`
	HttpOnly bool   `protobuf:"varint,7,opt,name=http_only,json=httpOnly,proto3" json:"http_only,omitempty"`
	Secure   bool   `protobuf:"varint,8,opt,name=secure,proto3" json:"secure,omitempty"`
}

func (x *Cookie) Reset() {
	*x = Cookie{}
	if protoimpl.UnsafeEnabled {
		mi := &file_identity_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Cookie) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Cookie) ProtoMessage() {}

func (x *Cookie) ProtoReflect() protoreflect.Message {
	mi := &file_identity_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Cookie.ProtoReflect.Descriptor instead.
func (*Cookie) Descriptor() ([]byte, []int) {
	return file_identity_proto_rawDescGZIP(), []int{1}
}

func (x *Cookie) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Cookie) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Cookie) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *Cookie) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *Cookie) GetExpires() int64 {
	if x != nil {
		return x.Expires
	}
	return 0
}

func (x *Cookie) GetSameSite() string {
	if x != nil {
		return x.SameSite
	}
	return ""
}

func (x *Cookie) GetHttpOnly() bool {
	if x != nil {
		return x.HttpOnly
	}
	return false
}

func (x *Cookie) GetSecure() bool {
	if x != nil {
		return x.Secure
	}
	return false
}

var File_identity_proto protoreflect.FileDescriptor

var file_identity_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0a, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x70, 0x62, 0x22, 0x1f, 0x0a, 0x1d,
	0x47, 0x65, 0x74, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0xca, 0x01,
	0x0a, 0x06, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61,
	0x74, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x18,
	0x0a, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x61, 0x6d, 0x65,
	0x5f, 0x73, 0x69, 0x74, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x73, 0x61, 0x6d,
	0x65, 0x53, 0x69, 0x74, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x6f, 0x6e,
	0x6c, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x68, 0x74, 0x74, 0x70, 0x4f, 0x6e,
	0x6c, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x06, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x32, 0x6a, 0x0a, 0x0f, 0x49, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x57, 0x0a,
	0x16, 0x47, 0x65, 0x74, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x12, 0x29, 0x2e, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x70, 0x62, 0x2e, 0x47, 0x65, 0x74, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x12, 0x2e, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x70, 0x62, 0x2e,
	0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x42, 0x15, 0x5a, 0x13, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x2f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x70, 0x62, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_identity_proto_rawDescOnce sync.Once
	file_identity_proto_rawDescData = file_identity_proto_rawDesc
)

func file_identity_proto_rawDescGZIP() []byte {
	file_identity_proto_rawDescOnce.Do(func() {
		file_identity_proto_rawDescData = protoimpl.X.CompressGZIP(file_identity_proto_rawDescData)
	})
	return file_identity_proto_rawDescData
}

var file_identity_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_identity_proto_goTypes = []interface{}{
	(*GetExpireSessionCookieRequest)(nil), // 0: identitypb.GetExpireSessionCookieRequest
	(*Cookie)(nil),                        // 1: identitypb.Cookie
}
var file_identity_proto_depIdxs = []int32{
	0, // 0: identitypb.IdentityService.GetExpireSessionCookie:input_type -> identitypb.GetExpireSessionCookieRequest
	1, // 1: identitypb.IdentityService.GetExpireSessionCookie:output_type -> identitypb.Cookie
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_identity_proto_init() }
func file_identity_proto_init() {
	if File_identity_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_identity_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetExpireSessionCookieRequest); i {
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
		file_identity_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Cookie); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_identity_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_identity_proto_goTypes,
		DependencyIndexes: file_identity_proto_depIdxs,
		MessageInfos:      file_identity_proto_msgTypes,
	}.Build()
	File_identity_proto = out.File
	file_identity_proto_rawDesc = nil
	file_identity_proto_goTypes = nil
	file_identity_proto_depIdxs = nil
}
