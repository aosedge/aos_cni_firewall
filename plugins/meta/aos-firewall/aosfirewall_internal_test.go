// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2021 Renesas Electronics Corporation.
// Copyright (C) 2021 EPAM Systems, Inc.
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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/*******************************************************************************
 * Consts
 ******************************************************************************/

const fullConf = `
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
	"cniVersion": "0.4.0",
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
 }`

const noPrevResultConfig = `
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
   "ifName": "vethbdcda373"
 }`

const servicePrevResultTepmlate = `
 {
	 "cniVersion":"0.4.0",
	 "dns":{},
	 "interfaces":[],
	 "ips":[
		 {
			 "address":"1.1.0.1/16",
			 "gateway":"1.1.0.0",
			 "interface":2,
			 "version":"4"
		 }
	 ],
	 "routes":[
		 {
			 "dst":"0.0.0.0/0"
		 }
	 ]
 } `

/*******************************************************************************
 * Types
 ******************************************************************************/

type testContainer struct {
	name                   string
	ipnet                  string
	vethIn                 string
	vethOut                string
	chain                  string
	br                     *testBridge
	uuid                   string
	allowPublicConnections bool
	ns                     ns.NetNS
	args                   *skel.CmdArgs
	outputEntries          []OutputAccessEntry
}

type testBridge struct {
	name   string
	ipnet  string
	bridge *netlink.Bridge
}

/*******************************************************************************
 * Tests
 ******************************************************************************/

var _ = Describe("Aos Firewall", func() {
	const IFNAME string = "eth0"
	var originalNS, targetNS ns.NetNS
	var br1, br2 testBridge
	var cont11, cont12, cont2 testContainer
	var err error

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
			StdinData:   []byte(fullConf),
		}

		err = originalNS.Do(func(ns.NetNS) (err error) {
			defer GinkgoRecover()
			_, _, err = testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, []byte(fullConf), func() (err error) {
				return cmdAdd(args)
			})
			Expect(err).To(HaveOccurred())

			err = testutils.CmdCheck(targetNS.Path(), args.ContainerID, IFNAME, []byte(fullConf), func() (err error) {
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

	doTestAdd := func(config []byte) (err error) {
		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      IFNAME,
			StdinData:   config,
		}

		return originalNS.Do(func(ns.NetNS) (err error) {
			defer GinkgoRecover()
			_, _, err = testutils.CmdAdd(targetNS.Path(), args.ContainerID, IFNAME, []byte(fullConf), func() (err error) {
				return cmdAdd(args)
			})

			return err
		})
	}

	Context("aos-firewall add negative tests", func() {
		It("cmdAdd no prevResult", func() {
			const conf = `
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
			}`

			err := doTestAdd([]byte(conf))
			Expect(err).To(HaveOccurred())
		})

		It("cmdAdd with `dummyport` port as input Access", func() {
			const conf = `
			{
			  "name": "test",
			  "type": "aos-firewall",
			  "uuid": "aaaa-aaaa",
			  "iptablesAdminChainName": "AOS_TEST_SERVICE1",
			  "runtimeStatePath": "/run/containers/cni/aos-firewall/aos-firewall-test.conf",
			  "inputAccess": [
				{
				  "port": "1:dummyport",
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
			}`

			err := doTestAdd([]byte(conf))
			Expect(err).To(HaveOccurred())
		})

		It("cmdAdd with wrong cni version", func() {
			const conf = `
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
			  "cniVersion": "0.23.0",
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
			}`

			err := doTestAdd([]byte(conf))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Traffic tests", func() {
		BeforeEach(func() {
			br1 = testBridge{name: "bbr1", ipnet: "11.1.0.1/16"}
			br2 = testBridge{name: "bbr2", ipnet: "22.2.0.1/16"}

			br1.bridge, err = createBridge(br1.name, br1.ipnet, 1500, false, false)
			Expect(err).NotTo(HaveOccurred())

			br2.bridge, err = createBridge(br2.name, br2.ipnet, 1500, false, false)
			Expect(err).NotTo(HaveOccurred())

			cont11 = testContainer{
				name: "cont11", ipnet: "11.1.0.10/24", vethIn: "in11",
				vethOut: "out11", chain: "CONT11", br: &br1, uuid: "1111-1111",
				allowPublicConnections: false,
			}

			cont12 = testContainer{
				name: "cont12", ipnet: "11.1.0.12/24", vethIn: "in12",
				vethOut: "out12", chain: "CONT12", br: &br1, uuid: "1211-1111",
				allowPublicConnections: false,
			}

			cont2 = testContainer{
				name: "cont2", ipnet: "22.2.0.10/24", vethIn: "in2",
				vethOut: "out2", chain: "CONT2", br: &br2, uuid: "2222-2222",
				allowPublicConnections: true,
			}

			cont11.outputEntries = []OutputAccessEntry{
				{Proto: "tcp", DstPort: "202", SrcIP: "11.1.0.10", DstIP: "22.2.0.10"},
				{Proto: "tcp", DstPort: "300", SrcIP: "11.1.0.10", DstIP: "22.2.0.10"},
			}

			cont12.outputEntries = []OutputAccessEntry{
				{Proto: "tcp", DstPort: "202", SrcIP: "11.1.0.12", DstIP: "22.2.0.10"},
				{Proto: "tcp", DstPort: "300", SrcIP: "11.1.0.12", DstIP: "22.2.0.10"},
			}

			cont2.outputEntries = []OutputAccessEntry{
				{Proto: "tcp", DstPort: "202", SrcIP: "22.2.0.10", DstIP: "11.1.0.10"},
				{Proto: "tcp", DstPort: "300", SrcIP: "22.2.0.10", DstIP: "11.1.0.10"},
				{Proto: "tcp", DstPort: "202", SrcIP: "22.2.0.10", DstIP: "11.1.0.12"},
				{Proto: "tcp", DstPort: "300", SrcIP: "22.2.0.10", DstIP: "11.1.0.12"},
			}

			err = buildContainer(&cont11)
			Expect(err).NotTo(HaveOccurred())
			err = buildContainer(&cont12)
			Expect(err).NotTo(HaveOccurred())
			err = buildContainer(&cont2)
			Expect(err).NotTo(HaveOccurred())

			cont11.args, err = doAddContainer(cont11, cont2.uuid)
			Expect(err).NotTo(HaveOccurred())

			cont12.args, err = doAddContainer(cont12, cont2.uuid)
			Expect(err).NotTo(HaveOccurred())

			cont2.args, err = doAddContainer(cont2, cont11.uuid)
			Expect(err).NotTo(HaveOccurred())

		})

		AfterEach(func() {
			err = doDelContainer(cont11.args)
			Expect(err).NotTo(HaveOccurred())

			err = doDelContainer(cont12.args)
			Expect(err).NotTo(HaveOccurred())

			err = doDelContainer(cont2.args)
			Expect(err).NotTo(HaveOccurred())

			Expect(clearContainer(&cont11)).To(Succeed())
			Expect(clearContainer(&cont12)).To(Succeed())
			Expect(clearContainer(&cont2)).To(Succeed())

			Expect(removeBridge(br1.bridge)).To(Succeed())
			Expect(removeBridge(br2.bridge)).To(Succeed())
		})

		It("Pass traffic between contaiers", func() {
			contIP11, _, err := net.ParseCIDR(cont11.ipnet)
			Expect(err).NotTo(HaveOccurred())

			contIP12, _, err := net.ParseCIDR(cont12.ipnet)
			Expect(err).NotTo(HaveOccurred())

			contIP2, _, err := net.ParseCIDR(cont2.ipnet)
			Expect(err).NotTo(HaveOccurred())

			//send traffic from 11 to 2
			err = cont11.ns.Do(func(hostNs ns.NetNS) (err error) {
				defer GinkgoRecover()

				By("trace container 2 port 202 tcp")
				if err = traceroute(contIP2.String(), "202", "202", "tcp"); err != nil {
					return err
				}

				By("trace container 2 port 202 udp")
				if err = traceroute(contIP2.String(), "202", "202", "udp"); err == nil {
					return fmt.Errorf("trace to %s udp shouldn't pass", contIP2.String())
				}

				By("trace container 2 port 302 tcp")
				if err = traceroute(contIP2.String(), "302", "302", "tcp"); err == nil {
					return fmt.Errorf("trace to %s tcp port 302 shouldn't pass", contIP2.String())
				}

				By("trace container 12 port 302 tcp")
				if err = traceroute(contIP12.String(), "302", "302", "tcp"); err != nil {
					return err
				}

				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			//send traffic from 2 to 11
			err = cont2.ns.Do(func(hostNs ns.NetNS) (err error) {
				defer GinkgoRecover()

				By("trace container 11 port 202 tcp")
				if err = traceroute(contIP11.String(), "202", "202", "tcp"); err != nil {
					return err
				}

				By("trace container 11 port 202 udp")
				if err = traceroute(contIP11.String(), "202", "202", "udp"); err == nil {
					return fmt.Errorf("trace to %s udp shouldn't pass", contIP11.String())
				}

				By("trace container 11 port 302 tcp")
				if err = traceroute(contIP11.String(), "302", "302", "tcp"); err == nil {
					return fmt.Errorf("trace to %s tcp port 302 shouldn't pass", contIP11.String())
				}

				return nil
			})
			Expect(err).NotTo(HaveOccurred())

			//Check internet connection for container 11
			err = cont11.ns.Do(func(hostNs ns.NetNS) (err error) {
				defer GinkgoRecover()

				return traceroute("8.8.8.8", "80", "80", "tcp")
			})
			Expect(err).To(HaveOccurred())

			//Check internet connection for container 2
			err = cont2.ns.Do(func(hostNs ns.NetNS) (err error) {
				defer GinkgoRecover()

				return traceroute("8.8.8.8", "80", "80", "tcp")
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("Restoring connections after add and remove container", func() {
			contIP11, _, err := net.ParseCIDR(cont11.ipnet)
			Expect(err).NotTo(HaveOccurred())

			contIP12, _, err := net.ParseCIDR(cont12.ipnet)
			Expect(err).NotTo(HaveOccurred())

			contIP2, _, err := net.ParseCIDR(cont2.ipnet)
			Expect(err).NotTo(HaveOccurred())

			By("Check connections Container11 to Container12 and Container2")
			err = doCheckTraffic(&cont11, contIP2.String())
			Expect(err).NotTo(HaveOccurred())

			err = doCheckTraffic(&cont11, contIP12.String())
			Expect(err).NotTo(HaveOccurred())

			By("Check connections Container2 to Container12 and Container11")
			err = doCheckTraffic(&cont2, contIP12.String())
			Expect(err).NotTo(HaveOccurred())

			err = doCheckTraffic(&cont2, contIP11.String())
			Expect(err).NotTo(HaveOccurred())

			By("Delete cont12")
			err = doDelContainer(cont12.args)
			Expect(err).NotTo(HaveOccurred())

			By("Check connections Container11 to Container12 and Container2")
			err = doCheckTraffic(&cont11, contIP2.String())
			Expect(err).NotTo(HaveOccurred())

			err = doCheckTraffic(&cont11, contIP12.String())
			Expect(err).To(HaveOccurred())

			By("Check connections Container2 to Container12 and Container11")
			err = doCheckTraffic(&cont2, contIP11.String())
			Expect(err).NotTo(HaveOccurred())

			By("Add cont12")
			cont12.args, err = doAddContainer(cont12, cont2.uuid)
			Expect(err).NotTo(HaveOccurred())

			By("Check conections to Container12 and Container2")
			err = doCheckTraffic(&cont11, contIP2.String())
			Expect(err).NotTo(HaveOccurred())

			err = doCheckTraffic(&cont11, contIP12.String())
			Expect(err).NotTo(HaveOccurred())

			err = doCheckTraffic(&cont2, contIP12.String())
			Expect(err).NotTo(HaveOccurred())

			err = doCheckTraffic(&cont2, contIP11.String())
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

/*******************************************************************************
 * Private
 ******************************************************************************/

func execCmd(bin string, args ...string) (err error) {
	output, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("CMD %s, err: %s, output: %s", strings.Join(args, " "), err, string(output))
	}

	return nil
}

func createVeth(hostVethIfName string, containerNamespace string, containerVethIfName string, containerIP string) (err error) {
	contNsName := filepath.Base(containerNamespace)

	err = execCmd("ip", "link", "add", hostVethIfName, "type", "veth", "peer", "name", containerVethIfName, "netns", contNsName)
	if err != nil {
		return err
	}

	err = execCmd("ip", "link", "set", "dev", hostVethIfName, "up")
	if err != nil {
		return err
	}

	err = execCmd("ip", "netns", "exec", contNsName, "ip", "addr", "add", "dev", containerVethIfName, containerIP)
	if err != nil {
		return err
	}

	err = execCmd("ip", "netns", "exec", contNsName, "ip", "link", "set", containerVethIfName, "up")
	if err != nil {
		return err
	}

	return nil
}

func bridgeByName(name string) (br *netlink.Bridge, err error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}
	br, ok := l.(*netlink.Bridge)
	if !ok {
		return nil, fmt.Errorf("%q already exists but is not a bridge", name)
	}
	return br, nil
}

func createBridge(brName string, brIP string, mtu int, promiscMode, vlanFiltering bool) (bridge *netlink.Bridge, err error) {
	err = execCmd("ip", "link", "add", "name", brName, "type", "bridge")
	if err != nil {
		return nil, err
	}

	err = execCmd("ip", "link", "set", brName, "up")
	if err != nil {
		return nil, err
	}

	err = execCmd("ip", "addr", "add", "dev", brName, brIP)
	if err != nil {
		return nil, err
	}

	return bridgeByName(brName)
}

func removeBridge(bridge *netlink.Bridge) (err error) {
	return netlink.LinkDel(bridge)
}

func addLinkToBridge(linkName string, bridge *netlink.Bridge) (err error) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to find link %q: %v", linkName, err)
	}

	return netlink.LinkSetMaster(link, bridge)
}

func removeLink(linkName string) (err error) {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to find link %q: %v", linkName, err)
	}
	return netlink.LinkDel(link)
}

func addDefaultRoute(netns ns.NetNS, linkName string, gw string) (err error) {
	return netns.Do(func(ns.NetNS) (err error) {
		defer GinkgoRecover()

		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("can't get link: %s", err)
		}
		gwIP, _, err := net.ParseCIDR(gw)
		if err != nil {
			return err
		}

		return ip.AddDefaultRoute(gwIP, link)
	})
}

func addNatRoute(chainName string, peerIP net.IP, subnetIP net.IP) (err error) {
	iptable, err := iptables.New()
	if err != nil {
		return err
	}

	err = iptable.NewChain("nat", chainName)
	if err != nil {
		return err
	}

	err = iptable.Append("nat", "POSTROUTING", "-s", peerIP.String()+"/32", "-j", chainName)
	if err != nil {
		return err
	}

	err = iptable.Append("nat", chainName, "-d", subnetIP.String()+"/16", "-j", "ACCEPT")
	if err != nil {
		return err
	}

	return iptable.Append("nat", chainName, "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE")
}

func removeNatRoute(chainName string, peerIP net.IP) (err error) {
	iptable, err := iptables.New()
	if err != nil {
		return err
	}

	err = iptable.ClearChain("nat", chainName)
	if err != nil {
		return err
	}

	err = iptable.Delete("nat", "POSTROUTING", "-s", peerIP.String()+"/32", "-j", chainName)
	if err != nil {
		return err
	}

	return iptable.DeleteChain("nat", chainName)
}

func getMacFromLink(name string) (mac string) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return ""
	}

	return link.Attrs().HardwareAddr.String()
}

func getInterfaceEntry(name string, netNs *ns.NetNS) (i *current.Interface, err error) {
	var macAddr string
	if netNs != nil {
		err = (*netNs).Do(func(ns.NetNS) (err error) {
			macAddr = getMacFromLink(name)
			return nil
		})
	} else {
		macAddr = getMacFromLink(name)
	}

	i = &current.Interface{Name: name, Mac: macAddr}

	if netNs != nil {
		i.Sandbox = (*netNs).Path()
	}
	return i, nil
}

func buildServiceConfig(containerID string, cont testContainer, outputUUID string) (args *skel.CmdArgs, err error) {
	args = &skel.CmdArgs{
		ContainerID: containerID,
		Netns:       cont.ns.Path(),
		IfName:      cont.vethIn,
	}

	config := pluginConf{
		NetConf: types.NetConf{
			CNIVersion: "0.4.0",
			Name:       cont.chain,
			Type:       "aos-firewall",
			IPAM:       types.IPAM{},
			DNS:        types.DNS{},
		},
		InputAccess: []InputAccessEntry{
			InputAccessEntry{
				Port:     "1:1000",
				Protocol: "tcp",
			},
		},
		OutputAccess:           cont.outputEntries,
		IptablesAdminChainName: cont.chain,
		AllowPublicConnections: cont.allowPublicConnections,
		UUID:                   cont.uuid,
	}

	var prevResult current.Result
	if err = json.Unmarshal([]byte(servicePrevResultTepmlate), &prevResult); err != nil {
		return nil, fmt.Errorf("failed to parse prevresult configuration: %v", err)
	}

	// Fill up Prev Result

	// Interfaces
	i, err := getInterfaceEntry(cont.br.name, nil)
	if err != nil {
		return nil, err
	}

	prevResult.Interfaces = append(prevResult.Interfaces, i)

	i, err = getInterfaceEntry(cont.vethOut, nil)
	if err != nil {
		return nil, err
	}

	prevResult.Interfaces = append(prevResult.Interfaces, i)

	i, err = getInterfaceEntry(cont.vethIn, &cont.ns)
	if err != nil {
		return nil, err
	}

	prevResult.Interfaces = append(prevResult.Interfaces, i)

	// IPs
	gwIP, _, err := net.ParseCIDR(cont.br.ipnet)
	if err != nil {
		return nil, err
	}

	contIP, addr, err := net.ParseCIDR(cont.ipnet)
	if err != nil {
		return nil, err
	}
	// Reassign IP as cont it because ParseCIDR returns IpNet with masked ip:
	// 11.1.0.10/24 will be translated to 11.1.0.0 255.255.255.0
	addr.IP = contIP

	prevResult.IPs[0].Address = *addr
	prevResult.IPs[0].Gateway = gwIP

	config.RawPrevResult = map[string]interface{}{
		"cniVersion": prevResult.CNIVersion,
		"interfaces": prevResult.Interfaces,
		"ips":        prevResult.IPs,
		"routes":     prevResult.Routes,
		"dns":        prevResult.DNS,
	}

	stdinBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	args.StdinData = stdinBytes
	return args, nil
}

func buildContainer(cont *testContainer) (err error) {
	cont.ns, err = testutils.NewNS()
	if err != nil {
		return err
	}

	err = createVeth(cont.vethOut, cont.ns.Path(), cont.vethIn, cont.ipnet)
	if err != nil {
		return err
	}

	err = addLinkToBridge(cont.vethOut, cont.br.bridge)
	if err != nil {
		return err
	}

	err = addDefaultRoute(cont.ns, cont.vethIn, cont.br.ipnet)
	if err != nil {
		return err
	}

	contIP, _, err := net.ParseCIDR(cont.ipnet)
	if err != nil {
		return err
	}

	brIP, _, err := net.ParseCIDR(cont.br.ipnet)
	if err != nil {
		return err
	}

	err = addNatRoute(cont.chain, contIP, brIP)
	if err != nil {
		return err
	}

	return nil
}

func clearContainer(cont *testContainer) (err error) {
	if err = removeLink(cont.vethOut); err != nil {
		return err
	}

	if err = cont.ns.Close(); err != nil {
		return err
	}

	contIP, _, err := net.ParseCIDR(cont.ipnet)
	if err != nil {
		return err
	}
	if err = removeNatRoute(cont.chain, contIP); err != nil {
		return err
	}

	return nil
}

func doAddContainer(cont testContainer, outputUUID string) (args *skel.CmdArgs, err error) {
	args, err = buildServiceConfig(cont.name, cont, outputUUID)
	if err != nil {
		return nil, err
	}

	_, _, err = testutils.CmdAdd(args.Netns, args.ContainerID, args.IfName, args.StdinData, func() (err error) {
		return cmdAdd(args)
	})

	return args, err
}

func doDelContainer(args *skel.CmdArgs) (err error) {
	return testutils.CmdDel(args.Netns, args.ContainerID, args.IfName, func() (err error) {
		return cmdDel(args)
	})
}

func traceroute(daddr string, sport, dport string, prot string) (err error) {
	args := []string{
		"-p", dport,
		"--sport=" + sport,
		"-m", "2",
		daddr,
	}

	if prot == "tcp" {
		args = append(args, "-T")
	}

	bin := "traceroute"
	cmd := exec.Command(bin, args...)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("traceroute failed. args: %s err: %s", strings.Join(args, " "), err)
	}

	if bytes.Contains(stdout.Bytes(), []byte("*")) {
		return fmt.Errorf("can't trace route to host: %s", daddr)
	}

	return nil
}

func doCheckTraffic(cont *testContainer, destIP string) (err error) {
	err = (*cont).ns.Do(func(hostNs ns.NetNS) (err error) {
		defer GinkgoRecover()

		if err = traceroute(destIP, "202", "202", "tcp"); err != nil {
			return err
		}

		return nil
	})

	return err
}
