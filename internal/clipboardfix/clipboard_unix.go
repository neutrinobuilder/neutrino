// Copyright 2013 @atotto. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build freebsd || linux || netbsd || openbsd || solaris || dragonfly

package clipboard

import (
	"errors"
	"os"
	"os/exec"
)

const (
	xsel               = "xsel"
	xclip              = "xclip"
	powershellExe      = "powershell.exe"
	clipExe            = "clip.exe"
	wlcopy             = "wl-copy"
	wlpaste            = "wl-paste"
	termuxClipboardGet = "termux-clipboard-get"
	termuxClipboardSet = "termux-clipboard-set"
)

var (
	Primary bool
	trimDos bool

	pasteCmdArgs []string
	copyCmdArgs  []string

	xselPasteArgs = []string{xsel, "--output", "--clipboard"}
	xselCopyArgs  = []string{xsel, "--input", "--clipboard"}

	xclipPasteArgs = []string{xclip, "-out", "-selection", "clipboard"}
	xclipCopyArgs  = []string{xclip, "-in", "-selection", "clipboard"}

	powershellExePasteArgs = []string{powershellExe, "Get-Clipboard"}
	clipExeCopyArgs        = []string{clipExe}

	wlpasteArgs = []string{wlpaste, "--no-newline"}
	wlcopyArgs  = []string{wlcopy}

	termuxPasteArgs = []string{termuxClipboardGet}
	termuxCopyArgs  = []string{termuxClipboardSet}

	missingCommands = errors.New("No clipboard utilities available. Please install xsel, xclip, wl-clipboard or Termux:API add-on for termux-clipboard-get/set.")
)

// init picks the available clipboard helper and resolves its absolute
// path once with lookPathSafe, saving it into pasteCmdArgs[0] /
// copyCmdArgs[0]. Required: getPasteCommand/getCopyCommand pass that
// element to exec.Command, which, if it contains a bare name (no path
// separator), redoes a real exec.LookPath on its own — the very
// Faccessat2 call lookPathSafe exists to avoid. The constant slices
// (xclipPasteArgs etc.) are copied, not aliased, before writing to
// element [0].
func init() {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		pc, cc := append([]string(nil), wlpasteArgs...), append([]string(nil), wlcopyArgs...)
		if copyPath, err := lookPathSafe(wlcopy); err == nil {
			if pastePath, err := lookPathSafe(wlpaste); err == nil {
				cc[0], pc[0] = copyPath, pastePath
				pasteCmdArgs, copyCmdArgs = pc, cc
				return
			}
		}
	}

	pc, cc := append([]string(nil), xclipPasteArgs...), append([]string(nil), xclipCopyArgs...)
	if path, err := lookPathSafe(xclip); err == nil {
		pc[0], cc[0] = path, path
		pasteCmdArgs, copyCmdArgs = pc, cc
		return
	}

	pc, cc = append([]string(nil), xselPasteArgs...), append([]string(nil), xselCopyArgs...)
	if path, err := lookPathSafe(xsel); err == nil {
		pc[0], cc[0] = path, path
		pasteCmdArgs, copyCmdArgs = pc, cc
		return
	}

	pc, cc = append([]string(nil), termuxPasteArgs...), append([]string(nil), termuxCopyArgs...)
	if copyPath, err := lookPathSafe(termuxClipboardSet); err == nil {
		if pastePath, err := lookPathSafe(termuxClipboardGet); err == nil {
			cc[0], pc[0] = copyPath, pastePath
			pasteCmdArgs, copyCmdArgs = pc, cc
			return
		}
	}

	pc, cc = append([]string(nil), powershellExePasteArgs...), append([]string(nil), clipExeCopyArgs...)
	trimDos = true
	if copyPath, err := lookPathSafe(clipExe); err == nil {
		if pastePath, err := lookPathSafe(powershellExe); err == nil {
			cc[0], pc[0] = copyPath, pastePath
			pasteCmdArgs, copyCmdArgs = pc, cc
			return
		}
	}

	Unsupported = true
}

func getPasteCommand() *exec.Cmd {
	if Primary {
		pasteCmdArgs = pasteCmdArgs[:1]
	}
	return exec.Command(pasteCmdArgs[0], pasteCmdArgs[1:]...)
}

func getCopyCommand() *exec.Cmd {
	if Primary {
		copyCmdArgs = copyCmdArgs[:1]
	}
	return exec.Command(copyCmdArgs[0], copyCmdArgs[1:]...)
}

func readAll() (string, error) {
	if Unsupported {
		return "", missingCommands
	}
	pasteCmd := getPasteCommand()
	out, err := pasteCmd.Output()
	if err != nil {
		return "", err
	}
	result := string(out)
	if trimDos && len(result) > 1 {
		result = result[:len(result)-2]
	}
	return result, nil
}

func writeAll(text string) error {
	if Unsupported {
		return missingCommands
	}
	copyCmd := getCopyCommand()
	in, err := copyCmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := copyCmd.Start(); err != nil {
		return err
	}
	if _, err := in.Write([]byte(text)); err != nil {
		return err
	}
	if err := in.Close(); err != nil {
		return err
	}
	return copyCmd.Wait()
}
