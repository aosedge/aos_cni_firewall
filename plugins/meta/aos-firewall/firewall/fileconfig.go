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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/disk"
)

/*******************************************************************************
 * Types
 ******************************************************************************/

// the disk lock for inter-process guard
type fileConfig struct {
	lock *disk.FileLock
	path string
}

/*******************************************************************************
 * Public
 ******************************************************************************/

func newFileConfig(path string) (f *fileConfig, err error) {
	f = &fileConfig{path: path}

	if err = os.MkdirAll(filepath.Dir(path), 0600); err != nil {
		return nil, err
	}

	if _, err = os.Stat(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if os.IsNotExist(err) {
		if _, err = os.Create(path); err != nil {
			return nil, fmt.Errorf("failed to create file %s", err)
		}
	}

	if f.lock, err = disk.NewFileLock(path); err != nil {
		return nil, err
	}

	return f, nil
}

func (f *fileConfig) Lock() (err error) {
	return f.lock.Lock()
}

func (f *fileConfig) Unlock() (err error) {
	return f.lock.Unlock()
}

func (f *fileConfig) Load(v interface{}) (err error) {
	configJSON, err := ioutil.ReadFile(f.path)
	if err != nil {
		return err
	}
	if len(configJSON) == 0 {
		return nil
	}

	return json.Unmarshal(configJSON, &v)
}

func (f *fileConfig) Save(v interface{}) (err error) {
	conf, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return fmt.Errorf("failed to serialize config %s", err)
	}

	err = ioutil.WriteFile(f.path, conf, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config %s", err)
	}

	return nil
}
