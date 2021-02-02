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
	"strconv"
	"strings"

	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
)

const (
	icmpProtocol     = "icmp"
	tcpProtocol      = "tcp"
	udpProtocol      = "udp"
	forwardChainName = "AOS-FORWARD"
	outputChainName  = "AOS-OUTPUT"
	maxPortsNumber   = 15
)

const (
	tableAppend iptableAction = iota
	tableInsert
	tableDelete
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// AccessChain contains parameters to configure iptables
type AccessChain struct {
	// Unique chain name,
	// must be unique across the system
	Name string `json:"name"`
	// PriviousChainName is the iptables chain
	// where rules entry begins
	ContainerID string `json:"containerID"`
	// Address is the ip of the container
	Address net.IPNet `json:"address"`
	// Gateway is the ip of the bridge
	Gateway net.IP `json:"gateway"`
	// OutRules are user specified parameters to configure
	// outcoming connections
	OutRules []AccessRule `json:"outRules"`
	// InputPortsUDP passed to iptables --destination-ports
	// for udp protocol, up to 15 ports can be specified
	InputPortsUDP []string `json:"inputPortsUDP"`
	// InputPortsTCP passed to iptables --destination-ports
	// for tcp protocol, up to 15 ports can be specified
	InputPortsTCP []string `json:"inputPortsTCP"`
	// HasInternetConnection specifies if container has outgoing permissions the network
	HasInternetConnection bool `json:"hasInternetConnection"`
}

// AccessRule contains parameters to configure one rule for a single container
type AccessRule struct {
	// system-wide unique container identifier
	DestContainerID string `json:"destContainerID"`
	// Comma separated list of ports or port ranges
	Ports string `json:"ports"`
	// Protocol, tcp or udp, default is tcp
	Protocol string `json:"protocol"`
}

// Firewall handles user defined chains
type Firewall struct {
	runtimeConfig *fileConfig
	chainMap      map[string]*AccessChain
	iptables      *iptables.IPTables
}

type iptableAction int

type iptablesRequest struct {
	action   iptableAction
	chain    string
	src      string
	dest     string
	sPorts   string
	dPorts   string
	protocol string
	jump     string
	state    string
}

/*******************************************************************************
 * Public
 ******************************************************************************/

// NewAccessChain returns *AccessChain, accepts minimal parameters to configure AccessChain
// name: unique chain name for a container
// containerID: unique identifier of the container
// address: ip address allocated to the container
// gateway: ip of the bridge container can be accessed with
// hasInternetConnection: specifies if container has access to network
func NewAccessChain(name string, containerID string, address net.IPNet, gateway net.IP, hasInternetConnection bool) (chain *AccessChain) {
	return &AccessChain{name, containerID, address, gateway,
		[]AccessRule{}, []string{}, []string{}, hasInternetConnection}
}

// AddInRule adds configuration to the chain for incoming connections,
// port can be a single port port=5000, a list or comma separeted ports
// port=5000,5005 or a range ports=5000:5005
// protocol=tcp or udp, default is tcp.
func (c *AccessChain) AddInRule(ports, protocol string) (err error) {
	if ports == "" {
		return fmt.Errorf("no ports were provided")
	}

	if protocol == udpProtocol {
		c.InputPortsUDP = append(c.InputPortsUDP, strings.Split(ports, ",")...)
	} else if protocol == tcpProtocol || protocol == "" {
		c.InputPortsTCP = append(c.InputPortsTCP, strings.Split(ports, ",")...)
	} else {
		return fmt.Errorf("protocol %s is not supported", protocol)
	}

	if len(c.InputPortsUDP) > maxPortsNumber || len(c.InputPortsTCP) > maxPortsNumber {
		return fmt.Errorf("number of ports exceeds iptables limitations")
	}

	return nil
}

// AddOutRule adds configuration to the chain for outgoing connections,
// containerId is system-wide unique container identifier
// port can be a single port port=5000, a list or comma separeted ports
// port=5000,5005 or a range ports=5000:5005
// protocol=tcp or udp, default is tcp
func (c *AccessChain) AddOutRule(containerID string, ports string, protocol string) (err error) {
	if containerID == "" {
		return fmt.Errorf("no container id was specified")
	}
	if protocol == "" {
		protocol = tcpProtocol
	}
	c.OutRules = append(c.OutRules, AccessRule{containerID, ports, protocol})

	return nil
}

// New returns Firewall instance
// configPath: the path where runtime state of the plugin is stored
func New(configPath string) (f *Firewall, err error) {
	f = &Firewall{chainMap: make(map[string]*AccessChain)}

	f.runtimeConfig, err = newFileConfig(configPath)
	if err != nil {
		return nil, err
	}

	f.iptables, err = iptables.New()
	if err != nil {
		return nil, err
	}

	return f, nil
}

// Add adds user defined chain to the firewall
func (f *Firewall) Add(c *AccessChain) (err error) {
	if err = f.runtimeConfig.Lock(); err != nil {
		return err
	}

	defer f.runtimeConfig.Unlock()

	if err = f.runtimeConfig.Load(&f.chainMap); err != nil {
		return err
	}

	f.chainMap[c.ContainerID] = c
	if err = f.ensureChains(c); err != nil {
		return err
	}

	for _, dchain := range f.chainMap {
		for _, outrule := range dchain.OutRules {
			if chain, ok := f.chainMap[outrule.DestContainerID]; ok {
				if err = f.update(chain); err != nil {
					return err
				}
			}
		}
	}

	if err = f.update(c); err != nil {
		return err
	}

	if err = f.runtimeConfig.Save(f.chainMap); err != nil {
		return err
	}

	return nil
}

// Del deletes user defined chain to the firewall
func (f *Firewall) Del(containerID string) (err error) {
	if err = f.runtimeConfig.Lock(); err != nil {
		return err
	}
	defer f.runtimeConfig.Unlock()

	if err = f.runtimeConfig.Load(&f.chainMap); err != nil {
		return err
	}

	c, ok := f.chainMap[containerID]
	if !ok {
		return nil
	}

	for _, dchain := range f.chainMap {
		for _, outrule := range dchain.OutRules {
			if outrule.DestContainerID == containerID {
				if err = f.update(dchain); err != nil {
					return err
				}
			}
		}
	}

	if err := f.iptables.ClearChain("filter", c.Name); err != nil {
		return err
	}

	f.execute(&iptablesRequest{
		action: tableDelete, chain: forwardChainName, dest: c.Address.IP.String(), state: "NEW", jump: c.Name})
	f.execute(&iptablesRequest{
		action: tableDelete, chain: outputChainName, src: c.Address.IP.String(), state: "NEW", jump: "DROP"})
	f.execute(&iptablesRequest{
		action: tableDelete, chain: outputChainName, src: c.Address.IP.String(), protocol: "icmp", jump: "DROP"})

	f.iptables.DeleteChain("filter", c.Name)

	delete(f.chainMap, containerID)

	if err = f.runtimeConfig.Save(f.chainMap); err != nil {
		return err
	}

	return err
}

// Check verifies that user defined chain is applied
func (f *Firewall) Check(c *AccessChain) (err error) {
	if err = f.runtimeConfig.Lock(); err != nil {
		return err
	}

	defer f.runtimeConfig.Unlock()

	if err = f.runtimeConfig.Load(&f.chainMap); err != nil {
		return err
	}

	if _, ok := f.chainMap[c.ContainerID]; !ok {
		return nil
	}

	if err = f.hasApplied(c); err != nil {
		return err
	}

	for _, dchain := range f.chainMap {
		for _, outrule := range dchain.OutRules {
			if outrule.DestContainerID == c.ContainerID {
				if err = f.hasApplied(dchain); err != nil {
					return err
				}
			}
		}
	}

	if err = f.runtimeConfig.Save(f.chainMap); err != nil {
		return err
	}

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (f *Firewall) hasApplied(c *AccessChain) (err error) {
	for _, request := range f.formatIptablesRequest(c) {
		parameters, err := request.formatRequest()
		if err != nil {
			return fmt.Errorf("failed formant rule to chain %s", err)
		}

		applied, err := f.iptables.Exists("filter", request.chain, parameters...)
		if !applied {
			return fmt.Errorf("iptable rule was not applied, %s %s, %s",
				c.Name, strings.Join(parameters, " "), err)
		}
	}

	return nil
}

func (f *Firewall) update(c *AccessChain) (err error) {
	chainRequests := f.formatIptablesRequest(c)

	if err = f.iptables.ClearChain("filter", c.Name); err != nil {
		return fmt.Errorf("failed to clean old chain %s", err)
	}
	if len(chainRequests) <= 1 {
		return nil
	}

	currChains, err := f.iptables.List("filter", c.Name)
	if err != nil {
		return fmt.Errorf("failed to backup backup chains %s", err)
	}

	defer func() {
		if err != nil {
			if err := f.iptables.ClearChain("filter", c.Name); err != nil {
				return
			}
			for i, chain := range currChains {
				if i == 0 {
					continue
				}
				params := strings.Split(chain, " ")
				if err = f.iptables.Append("filter", c.Name, params[2:]...); err != nil {
					break
				}
			}
		}
	}()

	for _, request := range chainRequests {
		if err = f.execute(&request); err != nil {
			return err
		}
	}

	return nil
}

func isMultiport(ports string) bool {
	return strings.Contains(ports, ":") || strings.Contains(ports, ",")
}

func (f *Firewall) formatIptablesRequest(chain *AccessChain) (chainFilters []iptablesRequest) {
	maskClass, _ := chain.Address.Mask.Size()
	mask := strconv.Itoa(maskClass)

	adminParams := []iptablesRequest{
		// Configure admin chains
		{action: tableInsert, chain: "FORWARD", jump: forwardChainName},
		{chain: "FORWARD", jump: outputChainName},
		{chain: forwardChainName, dest: chain.Address.IP.String(), state: "NEW", jump: chain.Name},
		{chain: outputChainName, src: chain.Address.IP.String(), protocol: "icmp", jump: "DROP"},
	}

	if !chain.HasInternetConnection {
		adminParams = append(adminParams, iptablesRequest{
			chain: outputChainName, src: chain.Address.IP.String(), state: "NEW", jump: "DROP"})
	}

	acceptParams := []iptablesRequest{
		// Accept all incoming connections within sub-network
		{chain: chain.Name, src: chain.Gateway.String() + "/" + mask, protocol: "tcp", jump: "ACCEPT"},
		{chain: chain.Name, src: chain.Gateway.String() + "/" + mask, protocol: "udp", jump: "ACCEPT"},
		// Accept all user specified incoming traffic
	}

	var outputParams []iptablesRequest
	for _, dchain := range f.chainMap {
		for _, rule := range dchain.OutRules {
			if rule.DestContainerID == chain.ContainerID {
				if dchain.Address.IP != nil {
					// Accept user specified output connections
					outputParams = append(outputParams, iptablesRequest{
						chain:    chain.Name,
						src:      dchain.Address.IP.String(),
						protocol: rule.Protocol,
						dPorts:   rule.Ports,
						jump:     "ACCEPT"})
				}
			}
		}
	}

	inputParams := []iptablesRequest{
		// Return from current chain if input is withing allowed port range
		{chain: chain.Name, src: "0.0.0.0" + "/" + mask,
			dPorts: strings.Join(chain.InputPortsTCP, ","), protocol: "tcp", jump: "RETURN"},
		{chain: chain.Name, src: "0.0.0.0" + "/" + mask,
			dPorts: strings.Join(chain.InputPortsUDP, ","), protocol: "udp", jump: "RETURN"},
	}

	dropParams := []iptablesRequest{
		// Drop all
		{chain: chain.Name, protocol: "tcp", jump: "DROP"},
		{chain: chain.Name, protocol: "udp", jump: "DROP"},
	}

	return append(append(append(append(adminParams, acceptParams...), outputParams...), inputParams...), dropParams...)
}

func (i *iptablesRequest) formatRequest() (request []string, err error) {
	if i.src != "" {
		request = append(request, "-s", i.src)
	}

	if i.dest != "" {
		request = append(request, "-d", i.dest)
	}

	if i.protocol == tcpProtocol {
		request = append(request, "-p", "tcp", "-m", "tcp", "--syn")
	} else if i.protocol == udpProtocol {
		request = append(request, "-p", "udp", "-m", "udp")
	} else if i.protocol == icmpProtocol {
		request = append(request, "-p", "icmp")
	}

	if i.sPorts != "" {
		if isMultiport(i.sPorts) {
			request = append(request, "-m", "multiport", "--sports", i.sPorts)
		} else {
			request = append(request, "--sport", i.sPorts)
		}
	}

	if i.dPorts != "" {
		if isMultiport(i.dPorts) {
			request = append(request, "-m", "multiport", "--dports", i.dPorts)
		} else {
			request = append(request, "--dport", i.dPorts)
		}
	}
	if i.state != "" {
		request = append(request, "-m", "conntrack", "--ctstate", i.state)
	}

	return append(request, "-j", i.jump), nil
}

func (f *Firewall) ensureChains(c *AccessChain) (err error) {
	// Ensure private chains exist
	if err := utils.EnsureChain(f.iptables, "filter", forwardChainName); err != nil {
		return err
	}

	if err := utils.EnsureChain(f.iptables, "filter", outputChainName); err != nil {
		return err
	}

	if err := utils.EnsureChain(f.iptables, "filter", c.Name); err != nil {
		return err
	}

	return nil
}

func (f *Firewall) execute(r *iptablesRequest) (err error) {
	params, err := r.formatRequest()
	if err != nil {
		return fmt.Errorf("failed formant rule for chain %s", err)
	}

	if r.action == tableAppend {
		if err = f.iptables.AppendUnique("filter", r.chain, params...); err != nil {
			return fmt.Errorf("failed to append rule to chain %s", err)
		}
	} else if r.action == tableDelete {
		if err = f.iptables.Delete("filter", r.chain, params...); err != nil {
			return fmt.Errorf("failed to delete rule from chain %s", err)
		}
	} else if r.action == tableInsert {
		exists, err := f.iptables.Exists("filter", r.chain, params...)
		if !exists && err == nil {
			err = f.iptables.Insert("filter", r.chain, 1, params...)
		}
	}

	return nil
}
