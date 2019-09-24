// Copyright 2016-2019 Authors of Cilium
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

package main

import (
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// OnIPIdentityCacheChange listens to ipcache updates and forwards them to the monitor
func (d *Daemon) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr net.IPNet,
	oldHostIP, newHostIP net.IP, oldID *identity.NumericIdentity, newID identity.NumericIdentity,
	encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	var (
		k8sNamespace, k8sPodName string
		newIdentity, oldIdentity uint32
		oldIdentityPtr           *uint32
	)

	if k8sMeta != nil {
		k8sNamespace = k8sMeta.Namespace
		k8sPodName = k8sMeta.PodName
	}

	newIdentity = newID.Uint32()
	if oldID != nil {
		oldIdentity = (*oldID).Uint32()
		oldIdentityPtr = &oldIdentity
	}

	repr, err := monitorAPI.IPCacheNotificationRepr(cidr.String(), newIdentity, oldIdentityPtr,
		newHostIP, oldHostIP, encryptKey, k8sNamespace, k8sPodName)
	if err == nil {
		switch modType {
		case ipcache.Upsert:
			d.SendNotification(monitorAPI.AgentNotifyIPCacheUpserted, repr)
		case ipcache.Delete:
			d.SendNotification(monitorAPI.AgentNotifyIPCacheDeleted, repr)
		}
	}
}

// OnIPIdentityCacheGC is required to implement IPIdentityMappingListener.
func (d *Daemon) OnIPIdentityCacheGC() {
	// Nothing to do, this event is currently not useful to monitor clients
}
