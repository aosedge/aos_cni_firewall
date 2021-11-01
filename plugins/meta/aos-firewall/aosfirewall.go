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
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"

	"gitpct.epam.com/epmd-aepr/aos_cni_firewall/plugins/meta/aos-firewall/firewall"
)

/*******************************************************************************
 * Var
 ******************************************************************************/

const (
	aosFirewallPluginName   = "aos-firewall"
	defaultRuntimeStatePath = "/run/containers/cni/aos-firewall/aos_chains.conf"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// InputAccessEntry is eht rule that restricts input connections to the container
type InputAccessEntry struct {
	// Comma separated list of ports or ranges
	// passed with iptables parameters --sports 1001:1002,1005
	Port string `json:"port"`
	// tcp or udp, default is tcp
	Protocol string `json:"protocol"`
}

// OutputAccessEntry is the rule that restricts output connections from the specified container
type OutputAccessEntry struct {
	// Comma separated list of ports or ranges
	// passed with iptables parameters --dports 1001:1002,1005
	Port string `json:"port"`
	// tcp or udp, default is tcp
	Protocol string `json:"protocol"`
	// UUID is the system-wide unique container identifier to which
	// outbound connection restriction is applied
	UUID string `json:"uuid,omitempty"`
}

type pluginConf struct {
	types.NetConf
	// InputAccess is a list of rules that restricts inbound connections
	InputAccess []InputAccessEntry `json:"inputAccess"`
	// OutputAccess is a list of rules that restricts inbound connections
	OutputAccess []OutputAccessEntry `json:"outputAccess"`

	// PrevResult contains the JSON response (via stdout) from the ADD/DEL command
	// of the previous plugin in the chain
	PrevResult *current.Result `json:"-"`

	// IptablesAdminChainName is the unique to the the container iptables filter chain name
	IptablesAdminChainName string `json:"iptablesAdminChainName"`
	// UUID is a system-wide unique container identifier to which
	// inbound connection restrictions are applied
	UUID string `json:"uuid"`
	// RuntimeStatePath is the path to the config file where inter-run state of the plugin is stored
	// must be unique across system
	RuntimeStatePath string `json:"runtimeStatePath"`
	// AllowPublicConnections specifies if container has outgoing permissions the network
	// default is false
	AllowPublicConnections bool `json:"allowPublicConnections"`
}

/*******************************************************************************
 * Main
 ******************************************************************************/

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString(aosFirewallPluginName))
}

/*******************************************************************************
 * Private
 ******************************************************************************/

func cmdAdd(args *skel.CmdArgs) (err error) {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	fw, err := firewall.New(conf.RuntimeStatePath)
	if err != nil {
		return err
	}

	cn, err := getAccessChainFromConfig(conf)
	if err != nil {
		return err
	}

	if err := fw.Add(cn); err != nil {
		return err
	}

	return types.PrintResult(conf.PrevResult, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) (err error) {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	fw, err := firewall.New(conf.RuntimeStatePath)
	if err != nil {
		return err
	}

	return fw.Del(conf.UUID)
}

func cmdCheck(args *skel.CmdArgs) (err error) {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	fw, err := firewall.New(conf.RuntimeStatePath)
	if err != nil {
		return err
	}

	cn, err := getAccessChainFromConfig(conf)
	if err != nil {
		return err
	}

	return fw.Check(cn)
}

func getAccessChainFromConfig(conf *pluginConf) (cn *firewall.AccessChain, err error) {
	var containerAddresses []*current.IPConfig

	for _, ip := range conf.PrevResult.IPs {
		containerAddresses = append(containerAddresses, ip)
	}

	if len(containerAddresses) == 0 {
		return nil, fmt.Errorf("got no container IPs")
	}

	cn = firewall.NewAccessChain(conf.IptablesAdminChainName, conf.UUID, containerAddresses[0].Address,
		containerAddresses[0].Gateway, conf.AllowPublicConnections)

	for _, chain := range conf.InputAccess {
		if err = cn.AddInRule(chain.Port, chain.Protocol); err != nil {
			return nil, err
		}
	}

	for _, chain := range conf.OutputAccess {
		if err = cn.AddOutRule(chain.UUID, chain.Port, chain.Protocol); err != nil {
			return nil, err
		}
	}

	return cn, nil
}

func parseConfig(stdin []byte) (config *pluginConf, err error) {
	config = &pluginConf{}
	if err = json.Unmarshal(stdin, &config); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// RawPrevResult contains the JSON response from the ADD/DEL command
	if config.RawPrevResult != nil {
		resultBytes, err := json.Marshal(config.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %s", err)
		}
		res, err := version.NewResult(config.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %s", err)
		}
		config.RawPrevResult = nil
		config.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %s", err)
		}
	}

	if config.RuntimeStatePath == "" {
		config.RuntimeStatePath = defaultRuntimeStatePath
	}

	if config.IptablesAdminChainName == "" {
		return nil, fmt.Errorf("IptablesAdminChainName must be specified")
	}

	return config, nil
}
