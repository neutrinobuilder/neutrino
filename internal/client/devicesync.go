// Copyright (C) 2026 Neutrino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"neutrino/internal/shared"
)

// PostDeviceSync sends envelope (a shared.KnockEnvelope, as built by
// shared.EncryptKnockWithTag) to another device of this identity at
// netAddr, through the device-sync endpoint: its tag travels in the
// header so the receiver accepts a body as large as an address book.
// Returns an error unless the receiver accepted it.
func PostDeviceSync(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), netAddr, envelope string, timeout time.Duration) error {
	var env shared.KnockEnvelope
	if err := json.Unmarshal([]byte(envelope), &env); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+netAddr+shared.DeviceSyncPath, strings.NewReader(envelope))
	if err != nil {
		return err
	}
	req.Header.Set(shared.DeviceSyncTagHeader, base64.StdEncoding.EncodeToString(env.Tag))
	httpCli := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: timeout}
	resp, err := httpCli.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
