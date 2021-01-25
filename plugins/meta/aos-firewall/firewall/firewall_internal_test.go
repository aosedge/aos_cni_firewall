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
	"net"

	"github.com/containernetworking/cni/pkg/types/current"
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
			"-A AOS_TEST_SERVICE2 -s 20.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
			"-A AOS_TEST_SERVICE2 -s 20.0.0.0/16 -p udp -m udp -j ACCEPT",
			"-A AOS_TEST_SERVICE2 -s 10.0.0.2/32 -p tcp -m tcp --dport 9000 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
			"-A AOS_TEST_SERVICE2 -s 0.0.0.0/16 -p tcp -m tcp --dport 9000 --tcp-flags FIN,SYN,RST,ACK SYN -j RETURN",
			"-A AOS_TEST_SERVICE2 -s 0.0.0.0/16 -p udp -m udp -j RETURN",
			"-A AOS_TEST_SERVICE2 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
			"-A AOS_TEST_SERVICE2 -p udp -m udp -j DROP",
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
				"-A AOS_TEST_SERVICE1 -s 10.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
				"-A AOS_TEST_SERVICE1 -s 10.0.0.0/16 -p udp -m udp -j ACCEPT",
				"-A AOS_TEST_SERVICE1 -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 1001:1002,1005,1006 -j RETURN",
				"-A AOS_TEST_SERVICE1 -s 0.0.0.0/16 -p udp -m udp -m multiport --dports 1000:1010 -j RETURN",
				"-A AOS_TEST_SERVICE1 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
				"-A AOS_TEST_SERVICE1 -p udp -m udp -j DROP",
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
				"-A AOS_TEST_SERVICE2 -s 20.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
				"-A AOS_TEST_SERVICE2 -s 20.0.0.0/16 -p udp -m udp -j ACCEPT",
				"-A AOS_TEST_SERVICE2 -s 10.0.0.2/32 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 2001:2002 -j ACCEPT",
				"-A AOS_TEST_SERVICE2 -s 10.0.0.2/32 -p udp -m udp --dport 2002 -j ACCEPT",
				"-A AOS_TEST_SERVICE2 -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 2000:2002,2004,2005 -j RETURN",
				"-A AOS_TEST_SERVICE2 -s 0.0.0.0/16 -p udp -m udp --dport 6000 -j RETURN",
				"-A AOS_TEST_SERVICE2 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
				"-A AOS_TEST_SERVICE2 -p udp -m udp -j DROP",
			}))

			rules, err = listFilterRules(chain1.Name)
			Expect(err).NotTo(HaveOccurred())

			err = fw.Check(chain1)
			Expect(err).NotTo(HaveOccurred())

			Expect(rules).To(Equal([]string{
				"-A AOS_TEST_SERVICE1 -s 10.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
				"-A AOS_TEST_SERVICE1 -s 10.0.0.0/16 -p udp -m udp -j ACCEPT",
				"-A AOS_TEST_SERVICE1 -s 20.0.0.2/32 -p tcp -m tcp --dport 1002 --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
				"-A AOS_TEST_SERVICE1 -s 20.0.0.2/32 -p udp -m udp --dport 1003 -j ACCEPT",
				"-A AOS_TEST_SERVICE1 -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 1001:1002,1005,1006 -j RETURN",
				"-A AOS_TEST_SERVICE1 -s 0.0.0.0/16 -p udp -m udp -m multiport --dports 1000:1010 -j RETURN",
				"-A AOS_TEST_SERVICE1 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
				"-A AOS_TEST_SERVICE1 -p udp -m udp -j DROP",
			}))
		})

		It("Delete Chain1", func() {
			err = fw.Del(chain1)
			Expect(err).NotTo(HaveOccurred())

			rules, err := listFilterRules(chain1.Name)
			Expect(rules).To(Equal([]string{}))

			err = fw.Check(chain1)
			Expect(err).NotTo(HaveOccurred())

			rules, err = listFilterRules(chain2.Name)
			Expect(err).NotTo(HaveOccurred())
			Expect(rules).To(Equal([]string{
				"-A AOS_TEST_SERVICE2 -s 20.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT",
				"-A AOS_TEST_SERVICE2 -s 20.0.0.0/16 -p udp -m udp -j ACCEPT",
				"-A AOS_TEST_SERVICE2 -s 0.0.0.0/16 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m multiport --dports 2000:2002,2004,2005 -j RETURN",
				"-A AOS_TEST_SERVICE2 -s 0.0.0.0/16 -p udp -m udp --dport 6000 -j RETURN",
				"-A AOS_TEST_SERVICE2 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP",
				"-A AOS_TEST_SERVICE2 -p udp -m udp -j DROP",
			}))

			err = fw.Del(chain2)
			Expect(err).NotTo(HaveOccurred())

			rules, err = listFilterRules(chain2.Name)
			Expect(rules).To(Equal([]string{}))

			err = fw.Check(chain1)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
