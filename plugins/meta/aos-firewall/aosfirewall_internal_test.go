// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2021 EPAM Systems Inc.
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
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
)

/*******************************************************************************
 * Tests
 ******************************************************************************/

var _ = Describe("Aos Firewall", func() {
	const IFNAME string = "eth0"
	var originalNS, targetNS ns.NetNS
	var err error

	fullConf := []byte(`
{
  "name": "test",
  "type": "aos-firewall",
  "uuid": "aaaa-aaaa",
  "iptablesAdminChainName": "AOS_TEST_SERVICE1",
  "runtimeStatePath": "/run/containers/cni/aos-firewall/aos-firewall-test.conf",
  "inputAccess": [
    {
      "port": "1:1000",
      "protocol": "tcp"
    }
  ],
  "outputAccess": [
    {
      "uuid": "bbbb-bbbb",
      "port": "257",
      "protocol": "tcp"
    }
  ],
  "cniVersion": "0.4.0",
  "ifName": "vethbdcda373",
  "prevResult": {
    "interfaces": [
      {
        "name": "test-br0",
        "mac": "9a:5a:e1:60:47:43"
      },
      {
        "name": "vethef205b6c",
        "mac": "82:27:ed:f9:0b:49"
      },
      {
        "name": "eth0",
        "mac": "0a:79:86:2f:cf:71",
        "sandbox": "/proc/9504/ns/net"
      }
    ],
    "ips": [
      {
        "version": "4",
        "interface": 2,
        "address": "1.1.0.2/16",
        "gateway": "1.1.0.1"
      }
    ],
    "routes": [
      {
        "dst": "0.0.0.0/0"
      }
    ],
    "dns": {
      "nameservers": [
        "1.1.0.1"
      ]
    }
  }
}`)
	BeforeEach(func() {
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) (err error) {
			defer GinkgoRecover()

			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: IFNAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(IFNAME)
			Expect(err).NotTo(HaveOccurred())

			return err
		})
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
	})

	It("aos-firewall add/check/delete", func() {
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData:   fullConf,
		}

		err = originalNS.Do(func(ns.NetNS) (err error) {
			defer GinkgoRecover()
			r, _, err := testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, fullConf, func() (err error) {
				return cmdAdd(args)
			})
			_ = r
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdCheck(targetNS.Path(), args.ContainerID, IFNAME, fullConf, func() (err error) {
				return cmdCheck(args)
			})
			Expect(err).NotTo(HaveOccurred())

			err = testutils.CmdDel(targetNS.Path(), args.ContainerID, IFNAME, func() (err error) {
				return cmdDel(args)
			})
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
	})
})
