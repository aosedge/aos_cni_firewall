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

package firewall

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/coreos/go-iptables/iptables"
	"github.com/jackpal/gateway"
)

const (
	icmpProtocol         = "icmp"
	tcpProtocol          = "tcp"
	udpProtocol          = "udp"
	forwardChainName     = "AOS-FORWARD"
	forwardPortChainName = "AOS-FORWARD-PORT"
	outputChainName      = "AOS-OUTPUT"
	maxPortsNumber       = 15
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
	// ContainerID id of the container
	ContainerID string `json:"containerID"`
	// Address is the ip of the container
	Address net.IPNet `json:"address"`
	// Gateway is the ip of the bridge
	Gateway net.IP `json:"gateway"`
	// GatewayPrefixLen is gateway prefix len
	GatewayPrefixLen string `json:"gatewayPrefixLen"`
	// PublicInterface net interface for internet access
	PublicInterface string `json:"publicInterface"`
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
	// DstIP is the ip of the destination
	DstIP string `json:"dstIp"`
	// DstPort is the port of the destination
	DstPort string `json:"dstPort"`
	// Proto is the protocol of the destination
	Proto string `json:"proto"`
	// SrcIP is the ip of the source
	SrcIP string `json:"srcIp"`
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
	input    string
	output   string
	sPorts   string
	dPorts   string
	protocol string
	jump     string
	state    string
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

// interfaceInfoByIP used to mock in test functionality get interface name and prefix len
var interfaceInfoByIP = getInterfaceInfoByIP

/*******************************************************************************
 * Public
 ******************************************************************************/

// NewAccessChain returns *AccessChain, accepts minimal parameters to configure AccessChain
// name: unique chain name for a container
// containerID: unique identifier of the container
// address: ip address allocated to the container
// gateway: ip of the bridge container can be accessed with
// hasInternetConnection: specifies if container has access to network
func NewAccessChain(
	name string, containerID string, address net.IPNet, gateway net.IP, hasInternetConnection bool,
) (chain *AccessChain) {
	return &AccessChain{
		Name:                  utils.FormatChainName(name, containerID),
		ContainerID:           containerID,
		Address:               address,
		Gateway:               gateway,
		HasInternetConnection: hasInternetConnection,
	}
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
	defer f.runtimeConfig.Unlock() //nolint:errcheck

	if err = f.runtimeConfig.Load(&f.chainMap); err != nil {
		return err
	}

	f.chainMap[c.ContainerID] = c

	if err = f.ensureChains(c); err != nil {
		return err
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
func (f *Firewall) Del(containerID string) (errDel error) {
	if errDel = f.runtimeConfig.Lock(); errDel != nil {
		return errDel
	}
	defer f.runtimeConfig.Unlock() //nolint:errcheck

	if errDel = f.runtimeConfig.Load(&f.chainMap); errDel != nil {
		return errDel
	}

	c, ok := f.chainMap[containerID]
	if !ok {
		return nil
	}

	if err := f.deleteOutRules(c); err != nil && errDel == nil {
		errDel = err
	}

	if err := f.deleteAccessChain(c); err != nil && errDel == nil {
		errDel = err
	}

	if err := f.runtimeConfig.Save(f.chainMap); err != nil && errDel == nil {
		errDel = err
	}

	delete(f.chainMap, containerID)

	return errDel
}

// Check verifies that user defined chain is applied
func (f *Firewall) Check(c *AccessChain) (err error) {
	if err = f.runtimeConfig.Lock(); err != nil {
		return err
	}

	defer f.runtimeConfig.Unlock() //nolint:errcheck

	if err = f.runtimeConfig.Load(&f.chainMap); err != nil {
		return err
	}

	if _, ok := f.chainMap[c.ContainerID]; !ok {
		return nil
	}

	if err = f.hasApplied(c); err != nil {
		return err
	}

	if err = f.runtimeConfig.Save(f.chainMap); err != nil {
		return err
	}

	return nil
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func (f *Firewall) deleteOutRules(c *AccessChain) (errDel error) {
	for _, outrule := range c.OutRules {
		if err := f.execute(&iptablesRequest{
			action:   tableDelete,
			chain:    forwardChainName,
			src:      outrule.SrcIP,
			dest:     outrule.DstIP,
			dPorts:   outrule.DstPort,
			protocol: outrule.Proto,
			jump:     "ACCEPT",
		}); err != nil && errDel == nil {
			errDel = err
		}

		if err := f.execute(&iptablesRequest{
			action: tableDelete,
			chain:  forwardChainName,
			src:    outrule.DstIP,
			dest:   outrule.SrcIP,
			jump:   "ACCEPT",
		}); err != nil && errDel == nil {
			errDel = err
		}
	}

	return errDel
}

func (f *Firewall) deleteAccessChain(c *AccessChain) (errDel error) {
	if err := f.iptables.ClearChain("filter", c.Name); err != nil && errDel == nil {
		errDel = err
	}

	if err := f.execute(&iptablesRequest{
		action: tableDelete, chain: forwardPortChainName, dest: c.Address.IP.String(), state: "NEW", jump: c.Name,
	}); err != nil && errDel == nil {
		errDel = err
	}

	if err := f.execute(&iptablesRequest{
		action: tableDelete, chain: outputChainName, src: c.Address.IP.String(), state: "NEW", jump: "DROP",
	}); err != nil && errDel == nil {
		errDel = err
	}

	if err := f.execute(&iptablesRequest{
		action: tableDelete, chain: outputChainName, src: c.Address.IP.String(), protocol: "icmp", jump: "DROP",
	}); err != nil && errDel == nil {
		errDel = err
	}

	if c.HasInternetConnection {
		if err := f.execute(&iptablesRequest{
			action: tableDelete,
			chain:  forwardChainName,
			src:    c.Address.IP.String(),
			output: c.PublicInterface,
			jump:   "ACCEPT",
		}); err != nil && errDel == nil {
			errDel = err
		}

		if err := f.execute(&iptablesRequest{
			action: tableDelete,
			chain:  forwardChainName,
			input:  c.PublicInterface,
			dest:   c.Address.IP.String(),
			jump:   "ACCEPT",
		}); err != nil && errDel == nil {
			errDel = err
		}
	}

	if err := f.execute(&iptablesRequest{
		action: tableDelete,
		chain:  forwardChainName,
		src:    c.Address.IP.String(),
		dest:   c.Gateway.String() + "/" + c.GatewayPrefixLen,
		jump:   "ACCEPT",
	}); err != nil && errDel == nil {
		errDel = err
	}

	if err := f.execute(&iptablesRequest{
		action: tableDelete,
		chain:  forwardChainName,
		src:    c.Gateway.String() + "/" + c.GatewayPrefixLen,
		dest:   c.Address.IP.String(),
		jump:   "ACCEPT",
	}); err != nil && errDel == nil {
		errDel = err
	}

	if err := f.iptables.DeleteChain("filter", c.Name); err != nil && errDel == nil {
		errDel = err
	}

	return errDel
}

func (f *Firewall) hasApplied(c *AccessChain) (err error) {
	chainFilter, err := f.formatIptablesRequest(c)
	if err != nil {
		return err
	}

	for _, request := range chainFilter {
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
	chainRequests, err := f.formatIptablesRequest(c)
	if err != nil {
		return err
	}

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

func (f *Firewall) formatIptablesRequest(chain *AccessChain) (chainFilters []iptablesRequest, err error) {
	// Configure admin chains
	chainFilters = append(chainFilters, f.formatAdminParams(chain)...)

	// Allow internet access if chain has it
	internetParams, err := f.formatInternetParams(chain)
	if err != nil {
		return nil, err
	}

	chainFilters = append(chainFilters, internetParams...)

	// Accept all incoming connections within sub-network
	chainFilters = append(chainFilters, f.formatAcceptParams(chain)...)

	// Add output rules
	chainFilters = append(chainFilters, f.formatOutputParams(chain)...)

	// Allow traffic forward between containers on the same subnets
	forwardParams, err := f.formatForwardParams(chain)
	if err != nil {
		return nil, err
	}

	chainFilters = append(chainFilters, forwardParams...)

	// Return from current chain if input is withing allowed port range
	chainFilters = append(chainFilters, f.formatInputParams(chain)...)

	// Drop all
	chainFilters = append(chainFilters, f.formatDropParams(chain)...)

	return chainFilters, nil
}

func (f *Firewall) formatAdminParams(chain *AccessChain) []iptablesRequest {
	return []iptablesRequest{
		{action: tableInsert, chain: "FORWARD", jump: forwardPortChainName},
		{action: tableInsert, chain: "FORWARD", jump: forwardChainName},
		{chain: "FORWARD", jump: outputChainName},
		{chain: forwardPortChainName, dest: chain.Address.IP.String(), state: "NEW", jump: chain.Name},
		{chain: outputChainName, src: chain.Address.IP.String(), protocol: "icmp", jump: "DROP"},
	}
}

func (f *Firewall) formatInternetParams(chain *AccessChain) ([]iptablesRequest, error) {
	if !chain.HasInternetConnection {
		return []iptablesRequest{
			{chain: outputChainName, src: chain.Address.IP.String(), state: "NEW", jump: "DROP"},
		}, nil
	}

	ip, err := gateway.DiscoverInterface()
	if err != nil {
		return nil, err
	}

	if chain.PublicInterface, _, err = interfaceInfoByIP(ip); err != nil {
		return nil, err
	}

	return []iptablesRequest{
		{chain: forwardChainName, src: chain.Address.IP.String(), output: chain.PublicInterface, jump: "ACCEPT"},
		{chain: forwardChainName, input: chain.PublicInterface, dest: chain.Address.IP.String(), jump: "ACCEPT"},
	}, nil
}

func (f *Firewall) formatAcceptParams(chain *AccessChain) []iptablesRequest {
	maskClass, _ := chain.Address.Mask.Size()
	mask := strconv.Itoa(maskClass)

	return []iptablesRequest{
		{chain: chain.Name, src: chain.Gateway.String() + "/" + mask, protocol: "tcp", jump: "ACCEPT"},
		{chain: chain.Name, src: chain.Gateway.String() + "/" + mask, protocol: "udp", jump: "ACCEPT"},
	}
}

func (f *Firewall) formatOutputParams(chain *AccessChain) (outputParams []iptablesRequest) {
	for _, rule := range chain.OutRules {
		outputParams = append(outputParams, iptablesRequest{
			chain:    forwardChainName,
			src:      rule.SrcIP,
			dest:     rule.DstIP,
			dPorts:   rule.DstPort,
			protocol: rule.Proto,
			jump:     "ACCEPT",
		})

		outputParams = append(outputParams, iptablesRequest{
			chain: forwardChainName,
			src:   rule.DstIP,
			dest:  rule.SrcIP,
			jump:  "ACCEPT",
		})
	}

	return outputParams
}

func (f *Firewall) formatForwardParams(chain *AccessChain) (forwardParams []iptablesRequest, err error) {
	if _, chain.GatewayPrefixLen, err = interfaceInfoByIP(chain.Gateway); err != nil {
		return nil, err
	}

	return []iptablesRequest{
		{
			chain: forwardChainName,
			src:   chain.Address.IP.String(),
			dest:  chain.Gateway.String() + "/" + chain.GatewayPrefixLen,
			jump:  "ACCEPT",
		},
		{
			chain: forwardChainName,
			src:   chain.Gateway.String() + "/" + chain.GatewayPrefixLen,
			dest:  chain.Address.IP.String(),
			jump:  "ACCEPT",
		},
	}, nil
}

func (f *Firewall) formatInputParams(chain *AccessChain) (inputParams []iptablesRequest) {
	maskClass, _ := chain.Address.Mask.Size()
	mask := strconv.Itoa(maskClass)

	if len(chain.InputPortsTCP) > 0 {
		inputParams = append(inputParams, iptablesRequest{
			chain: chain.Name, src: "0.0.0.0" + "/" + mask,
			dPorts: strings.Join(chain.InputPortsTCP, ","), protocol: "tcp", jump: "RETURN",
		})
	}

	if len(chain.InputPortsUDP) > 0 {
		inputParams = append(inputParams, iptablesRequest{
			chain: chain.Name, src: "0.0.0.0" + "/" + mask,
			dPorts: strings.Join(chain.InputPortsUDP, ","), protocol: "udp", jump: "RETURN",
		})
	}

	return inputParams
}

func (f *Firewall) formatDropParams(chain *AccessChain) []iptablesRequest {
	return []iptablesRequest{
		{chain: chain.Name, protocol: "tcp", jump: "DROP"},
		{chain: chain.Name, protocol: "udp", jump: "DROP"},
	}
}

func (i *iptablesRequest) formatRequest() (request []string, err error) {
	if i.src != "" {
		request = append(request, "-s", i.src)
	}

	if i.dest != "" {
		request = append(request, "-d", i.dest)
	}

	if i.output != "" {
		request = append(request, "-o", i.output)
	}

	if i.input != "" {
		request = append(request, "-i", i.input)
	}

	switch i.protocol {
	case tcpProtocol:
		request = append(request, "-p", "tcp", "-m", "tcp")
	case udpProtocol:
		request = append(request, "-p", "udp", "-m", "udp")
	case icmpProtocol:
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
	if err := utils.EnsureChain(f.iptables, "filter", forwardPortChainName); err != nil {
		return err
	}

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

	switch r.action {
	case tableAppend:
		if err = f.iptables.AppendUnique("filter", r.chain, params...); err != nil {
			return fmt.Errorf("failed to append rule to chain %s", err)
		}
	case tableDelete:
		if err = f.iptables.Delete("filter", r.chain, params...); err != nil {
			return fmt.Errorf("failed to delete rule from chain %s", err)
		}
	case tableInsert:
		exists, err := f.iptables.Exists("filter", r.chain, params...)
		if !exists && err == nil {
			if err = f.iptables.Insert("filter", r.chain, 1, params...); err != nil {
				return fmt.Errorf("failed to insert rule to chain %s", err)
			}
		}
	}

	return nil
}

func getInterfaceInfoByIP(ip net.IP) (name string, mask string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			iip, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			if iip.Equal(ip) {
				prefixLen, _ := ipNet.Mask.Size()

				return iface.Name, strconv.Itoa(prefixLen), nil
			}
		}
	}

	return "", "", fmt.Errorf("couldn't find an interface for the ip: %s", ip.String())
}
