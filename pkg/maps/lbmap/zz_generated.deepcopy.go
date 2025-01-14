// +build !ignore_autogenerated

// Copyright 2017-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by deepcopy-gen. DO NOT EDIT.

package lbmap

import (
	bpf "github.com/cilium/cilium/pkg/bpf"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Backend4Key) DeepCopyInto(out *Backend4Key) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Backend4Key.
func (in *Backend4Key) DeepCopy() *Backend4Key {
	if in == nil {
		return nil
	}
	out := new(Backend4Key)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *Backend4Key) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Backend4Value) DeepCopyInto(out *Backend4Value) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Backend4Value.
func (in *Backend4Value) DeepCopy() *Backend4Value {
	if in == nil {
		return nil
	}
	out := new(Backend4Value)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *Backend4Value) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Backend6Key) DeepCopyInto(out *Backend6Key) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Backend6Key.
func (in *Backend6Key) DeepCopy() *Backend6Key {
	if in == nil {
		return nil
	}
	out := new(Backend6Key)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *Backend6Key) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Backend6Value) DeepCopyInto(out *Backend6Value) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Backend6Value.
func (in *Backend6Value) DeepCopy() *Backend6Value {
	if in == nil {
		return nil
	}
	out := new(Backend6Value)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *Backend6Value) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RevNat4Key) DeepCopyInto(out *RevNat4Key) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RevNat4Key.
func (in *RevNat4Key) DeepCopy() *RevNat4Key {
	if in == nil {
		return nil
	}
	out := new(RevNat4Key)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *RevNat4Key) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RevNat4Value) DeepCopyInto(out *RevNat4Value) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RevNat4Value.
func (in *RevNat4Value) DeepCopy() *RevNat4Value {
	if in == nil {
		return nil
	}
	out := new(RevNat4Value)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *RevNat4Value) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RevNat6Key) DeepCopyInto(out *RevNat6Key) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RevNat6Key.
func (in *RevNat6Key) DeepCopy() *RevNat6Key {
	if in == nil {
		return nil
	}
	out := new(RevNat6Key)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *RevNat6Key) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RevNat6Value) DeepCopyInto(out *RevNat6Value) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RevNat6Value.
func (in *RevNat6Value) DeepCopy() *RevNat6Value {
	if in == nil {
		return nil
	}
	out := new(RevNat6Value)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *RevNat6Value) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service4Key) DeepCopyInto(out *Service4Key) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service4Key.
func (in *Service4Key) DeepCopy() *Service4Key {
	if in == nil {
		return nil
	}
	out := new(Service4Key)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *Service4Key) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service4KeyV2) DeepCopyInto(out *Service4KeyV2) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	in.Pad.DeepCopyInto(&out.Pad)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service4KeyV2.
func (in *Service4KeyV2) DeepCopy() *Service4KeyV2 {
	if in == nil {
		return nil
	}
	out := new(Service4KeyV2)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *Service4KeyV2) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service4Value) DeepCopyInto(out *Service4Value) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service4Value.
func (in *Service4Value) DeepCopy() *Service4Value {
	if in == nil {
		return nil
	}
	out := new(Service4Value)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *Service4Value) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service4ValueV2) DeepCopyInto(out *Service4ValueV2) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service4ValueV2.
func (in *Service4ValueV2) DeepCopy() *Service4ValueV2 {
	if in == nil {
		return nil
	}
	out := new(Service4ValueV2)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *Service4ValueV2) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service6Key) DeepCopyInto(out *Service6Key) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service6Key.
func (in *Service6Key) DeepCopy() *Service6Key {
	if in == nil {
		return nil
	}
	out := new(Service6Key)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *Service6Key) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service6KeyV2) DeepCopyInto(out *Service6KeyV2) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	in.Pad.DeepCopyInto(&out.Pad)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service6KeyV2.
func (in *Service6KeyV2) DeepCopy() *Service6KeyV2 {
	if in == nil {
		return nil
	}
	out := new(Service6KeyV2)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *Service6KeyV2) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service6Value) DeepCopyInto(out *Service6Value) {
	*out = *in
	in.Address.DeepCopyInto(&out.Address)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service6Value.
func (in *Service6Value) DeepCopy() *Service6Value {
	if in == nil {
		return nil
	}
	out := new(Service6Value)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *Service6Value) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Service6ValueV2) DeepCopyInto(out *Service6ValueV2) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Service6ValueV2.
func (in *Service6ValueV2) DeepCopy() *Service6ValueV2 {
	if in == nil {
		return nil
	}
	out := new(Service6ValueV2)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *Service6ValueV2) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
