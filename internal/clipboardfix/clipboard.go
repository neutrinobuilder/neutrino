// Copyright 2013 @atotto. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package clipboard is a drop-in replacement for github.com/atotto/clipboard
// (same import path, wired via a `replace` directive in the main module's
// go.mod), swapped in only to avoid a syscall that crashes on Android/Termux
// see lookpath.go for the actual reason. Public API identical to upstream.
package clipboard

// ReadAll read string from clipboard
func ReadAll() (string, error) {
	return readAll()
}

// WriteAll write string to clipboard
func WriteAll(text string) error {
	return writeAll(text)
}

// Unsupported might be set true during clipboard init, to help callers decide
// whether or not to offer clipboard options.
var Unsupported bool
