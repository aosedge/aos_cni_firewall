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

package firewall

import (
	"fmt"
	"net"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/coreos/go-iptables/iptables"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/*******************************************************************************
 * Const
 ******************************************************************************/

const (
	runtimeConfigPath = "/run/firewall_test/aos-firewall-test.conf"
)

/*******************************************************************************
 * Tests
 ******************************************************************************/

func listFilterRules(chain string) (rules []string, err error) {
	ipt, err := iptables.New()
	if err != nil {
		return []string{}, err
	}
	rules, err = ipt.List("filter", chain)
	if err != nil {
		return []string{}, err
	}

	return rules[1:], nil
}

var _ = Describe("Firewall", func() {
	var err error
	var fw *Firewall

	var iconf1 current.IPConfig
	var iconf2 current.IPConfig
	var chain1 *AccessChain
	var chain2 *AccessChain

	BeforeEach(func() {
		fw, err = New(runtimeConfigPath)
		Expect(err).NotTo(HaveOccurred())

		iconf1 = current.IPConfig{}
		iconf2 = current.IPConfig{}

		iconf1.Address.IP = net.IPv4(10, 0, 0, 2)
		iconf1.Gateway = net.IPv4(10, 0, 0, 1)
		iconf1.Address.Mask = net.IPv4Mask(0xff, 0xff, 0, 0)

		iconf2.Address.IP = net.IPv4(20, 0, 0, 2)
		iconf2.Gateway = net.IPv4(20, 0, 0, 1)
		iconf2.Address.Mask = net.IPv4Mask(0xff, 0xff, 0, 0)

		chain1 = NewAccessChain("AOS_TEST_SERVICE1", "0000-0000-0000-0000", iconf1.Address, iconf1.Gateway, true)
		chain1.AddInRule("1001:1002,1005", "tcp")
		chain1.AddInRule("1006", "tcp")
		chain1.AddInRule("1000:1010", "udp")
		chain1.AddOutRule("1111-1111-1111-1111", "2001:2002", "tcp")
		chain1.AddOutRule("1111-1111-1111-1111", "2002", "udp")

		chain2 = NewAccessChain("AOS_TEST_SERVICE2", "1111-1111-1111-1111", iconf2.Address, iconf2.Gateway, true)
		chain2.AddInRule("2000:2002,2004", "tcp")
		chain2.AddInRule("2005", "tcp")
		chain2.AddInRule("6000", "udp")
		chain2.AddOutRule("0000-0000-0000-0000", "1002", "tcp")
		chain2.AddOutRule("0000-0000-0000-0000", "1003", "udp")

	})

	It("Add One Way connection", func() {
		chain1 = NewAccessChain("AOS_TEST_SERVICE1", "0000-0000-0000-0000", iconf1.Address, iconf1.Gateway, true)
		chain1.AddOutRule("1111-1111-1111-1111", "9000", "tcp")

		chain2 = NewAccessChain("AOS_TEST_SERVICE2", "1111-1111-1111-1111", iconf2.Address, iconf2.Gateway, true)
		chain2.AddInRule("9000", "tcp")

		err = fw.Add(chain2)
		Expect(err).NotTo(HaveOccurred())

		err = fw.Check(chain1)
		Expect(err).NotTo(HaveOccurred())

		err = fw.Add(chain1)
		Expect(err).NotTo(HaveOccurred())

		rules, err := listFilterRules(chain2.Name)
		Expect(err).NotTo(HaveOccurred())

		Expect(rules).To(Equal([]string{
			fmt.Sprintf("-A %s -s 20.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain2.Name),
			fmt.Sprintf("-A %s -s 20.0.0.0/16 -p udp -m udp -j ACCEPT", chain2.Name),
			fmt.Sprintf("-A %s -s 10.0.0.2/32 -p tcp -m tcp --dport 9000 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain2.Name),
			fmt.Sprintf("-A %s -s 0.0.0.0/16 -p tcp -m tcp --dport 9000 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN", chain2.Name),
			fmt.Sprintf("-A %s -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP", chain2.Name),
			fmt.Sprintf("-A %s -p udp -m udp -j DROP", chain2.Name),
		}))
	})

	It("No exposed ports were provided", func() {
		var iconf3 current.IPConfig

		iconf3.Address.IP = net.IPv4(30, 0, 0, 2)
		iconf3.Gateway = net.IPv4(30, 0, 0, 1)
		iconf3.Address.Mask = net.IPv4Mask(0xff, 0xff, 0, 0)

		// No in rules were provided
		chain3 := NewAccessChain("AOS_TEST_SERVICE3", "3333-3333-3333-3333", iconf3.Address, iconf3.Gateway, true)
		chain3.AddOutRule("0000-0000-0000-0000", "1002", "tcp")
		chain3.AddOutRule("0000-0000-0000-0000", "1003", "udp")

		err = fw.Add(chain3)
		Expect(err).NotTo(HaveOccurred())

		err = fw.Check(chain3)
		Expect(err).NotTo(HaveOccurred())

		rules, err := listFilterRules(chain3.Name)
		Expect(err).NotTo(HaveOccurred())

		err = fw.Del(chain3.ContainerID)
		Expect(err).NotTo(HaveOccurred())

		Expect(rules).To(Equal([]string{
			fmt.Sprintf("-A %s -s 30.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain3.Name),
			fmt.Sprintf("-A %s -s 30.0.0.0/16 -p udp -m udp -j ACCEPT", chain3.Name),
			fmt.Sprintf("-A %s -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP", chain3.Name),
			fmt.Sprintf("-A %s -p udp -m udp -j DROP", chain3.Name),
		}))
	})

	Describe("Test Iptables Rules", func() {
		It("Add Chain1", func() {
			err = fw.Add(chain1)
			Expect(err).NotTo(HaveOccurred())

			err = fw.Check(chain1)
			Expect(err).NotTo(HaveOccurred())

			rules, err := listFilterRules(chain1.Name)
			Expect(err).NotTo(HaveOccurred())

			Expect(rules).To(Equal([]string{
				fmt.Sprintf("-A %s -s 10.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain1.Name),
				fmt.Sprintf("-A %s -s 10.0.0.0/16 -p udp -m udp -j ACCEPT", chain1.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 1001:1002,1005,1006 -j RETURN", chain1.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p udp -m udp -m multiport --dports 1000:1010 -j RETURN", chain1.Name),
				fmt.Sprintf("-A %s -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP", chain1.Name),
				fmt.Sprintf("-A %s -p udp -m udp -j DROP", chain1.Name),
			}))
		})

		It("Add Chain2", func() {
			err = fw.Add(chain2)
			Expect(err).NotTo(HaveOccurred())

			err = fw.Check(chain2)
			Expect(err).NotTo(HaveOccurred())

			rules, err := listFilterRules(chain2.Name)
			Expect(err).NotTo(HaveOccurred())

			Expect(rules).To(Equal([]string{
				fmt.Sprintf("-A %s -s 20.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain2.Name),
				fmt.Sprintf("-A %s -s 20.0.0.0/16 -p udp -m udp -j ACCEPT", chain2.Name),
				fmt.Sprintf("-A %s -s 10.0.0.2/32 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 2001:2002 -j ACCEPT", chain2.Name),
				fmt.Sprintf("-A %s -s 10.0.0.2/32 -p udp -m udp --dport 2002 -j ACCEPT", chain2.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 2000:2002,2004,2005 -j RETURN", chain2.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p udp -m udp --dport 6000 -j RETURN", chain2.Name),
				fmt.Sprintf("-A %s -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP", chain2.Name),
				fmt.Sprintf("-A %s -p udp -m udp -j DROP", chain2.Name),
			}))

			rules, err = listFilterRules(chain1.Name)
			Expect(err).NotTo(HaveOccurred())

			err = fw.Check(chain1)
			Expect(err).NotTo(HaveOccurred())

			Expect(rules).To(Equal([]string{
				fmt.Sprintf("-A %s -s 10.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain1.Name),
				fmt.Sprintf("-A %s -s 10.0.0.0/16 -p udp -m udp -j ACCEPT", chain1.Name),
				fmt.Sprintf("-A %s -s 20.0.0.2/32 -p tcp -m tcp --dport 1002 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain1.Name),
				fmt.Sprintf("-A %s -s 20.0.0.2/32 -p udp -m udp --dport 1003 -j ACCEPT", chain1.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 1001:1002,1005,1006 -j RETURN", chain1.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p udp -m udp -m multiport --dports 1000:1010 -j RETURN", chain1.Name),
				fmt.Sprintf("-A %s -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP", chain1.Name),
				fmt.Sprintf("-A %s -p udp -m udp -j DROP", chain1.Name),
			}))
		})

		It("Delete Chain1", func() {
			err = fw.Del(chain1.ContainerID)
			Expect(err).NotTo(HaveOccurred())

			rules, err := listFilterRules(chain1.Name)
			Expect(rules).To(Equal([]string{}))

			err = fw.Check(chain1)
			Expect(err).NotTo(HaveOccurred())

			rules, err = listFilterRules(chain2.Name)
			Expect(err).NotTo(HaveOccurred())
			Expect(rules).To(Equal([]string{
				fmt.Sprintf("-A %s -s 20.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT", chain2.Name),
				fmt.Sprintf("-A %s -s 20.0.0.0/16 -p udp -m udp -j ACCEPT", chain2.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 2000:2002,2004,2005 -j RETURN", chain2.Name),
				fmt.Sprintf("-A %s -s 0.0.0.0/16 -p udp -m udp --dport 6000 -j RETURN", chain2.Name),
				fmt.Sprintf("-A %s -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP", chain2.Name),
				fmt.Sprintf("-A %s -p udp -m udp -j DROP", chain2.Name),
			}))

			err = fw.Del(chain2.ContainerID)
			Expect(err).NotTo(HaveOccurred())

			rules, err = listFilterRules(chain2.Name)
			Expect(rules).To(Equal([]string{}))

			err = fw.Check(chain1)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
