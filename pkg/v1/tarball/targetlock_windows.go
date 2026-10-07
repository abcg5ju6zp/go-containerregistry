// Copyright 2026 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tarball

import (
	"os"

	"golang.org/x/sys/windows"
)

// targetLock is an exclusive byte-range lock. Windows releases it
// automatically (with the handle) if the process exits or is killed.
type targetLock struct {
	f  *os.File
	ol windows.Overlapped
}

func acquireTargetLock(p string) (*targetLock, error) {
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	l := &targetLock{f: f}
	// Lock one byte at offset 0 for the lifetime of the export; the call
	// blocks until the region is available.
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &l.ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	return l, nil
}

func (l *targetLock) Unlock() {
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &l.ol)
	_ = l.f.Close()
}
