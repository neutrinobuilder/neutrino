module neutrino

go 1.26.2

require (
	filippo.io/edwards25519 v1.2.0
	fyne.io/fyne/v2 v2.8.0
	github.com/atotto/clipboard v0.1.4
	github.com/awnumar/memguard v0.23.0
	github.com/blackjack/webcam v0.6.1
	github.com/charmbracelet/bubbles v1.0.0
	github.com/charmbracelet/bubbletea v1.3.10
	github.com/charmbracelet/lipgloss v1.1.0
	github.com/charmbracelet/x/ansi v0.11.6
	github.com/cloudflare/circl v1.6.4
	github.com/coder/websocket v1.8.14
	github.com/cretz/bine v0.2.0
	github.com/go-pdf/fpdf v0.9.0
	github.com/godbus/dbus/v5 v5.2.2
	github.com/google/uuid v1.6.0
	github.com/makiuchi-d/gozxing v0.1.1
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/tyler-smith/go-bip39 v1.1.0
	github.com/ulikunitz/xz v0.5.16
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird v0.0.0-20260312101154-fc105a03c0e0
	golang.org/x/crypto v0.54.0
	golang.org/x/image v0.24.0
	golang.org/x/net v0.56.0
	golang.org/x/term v0.45.0
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/awnumar/memcall v0.4.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/charmbracelet/colorprofile v0.4.1 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.9.0 // indirect
	github.com/clipperhouse/stringish v0.1.1 // indirect
	github.com/clipperhouse/uax29/v2 v2.5.0 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/refraction-networking/utls v1.6.7 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	gitlab.com/yawning/edwards25519-extra v0.0.0-20231005122941-2149dcafc266 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel v0.0.3 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
)

// atotto/clipboard's init() calls exec.LookPath unconditionally at process
// startup (transitive dependency of charmbracelet/bubbles, for Ctrl+V paste)
// — on Android/Termux this crashes the whole binary with SIGSYS "bad system
// call" (golang/go#57393, #60125: LookPath hits internal/syscall/unix.Eaccess
// → Faccessat2, a syscall blocked by Android's seccomp filter). Local
// replacement with the same public API, avoiding that syscall — see
// internal/clipboardfix and MANUALE_TERMUX_it.md.
replace github.com/atotto/clipboard => ./internal/clipboardfix
