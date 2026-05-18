package ui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	cryptopkg "chat/internal/crypto"
	netpkg "chat/internal/net"
	"chat/internal/protocol"
	"chat/internal/trust"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type incomingMessage struct {
	body string
}

type incomingFile struct {
	name string
	path string
	size int64
}

type sessionError struct {
	err error
}

type panicWipeComplete struct {
	err error
}

type typingIndicator struct{}

type clearTypingTick struct{ at time.Time }

type chatLine struct {
	timestamp time.Time
	speaker   string
	body      string
	self      bool
}

type banner struct {
	body  string
	error bool
}

type chatModel struct {
	runtimeOptions   RuntimeOptions
	session          *netpkg.SecureSession
	peer             netpkg.PeerIdentity
	input            textinput.Model
	viewport         viewport.Model
	lines            []chatLine
	banners          []banner
	events           chan tea.Msg
	width            int
	height           int
	quitting         bool
	disconnected     bool
	remoteAddress    string
	localFingerprint string
	peerFingerprint  string
	receiveDir       string
	exitErr          error
	peerTyping       bool
	peerTypingAt     time.Time
	lastTypingSentAt time.Time
	localName        string
	peerName         string
}

type RuntimeOptions struct {
	MemoryOnly     bool
	IdentityPath   string
	KnownPeersPath string
	LocalName      string
	PeerName       string
}

var (
	appStyle = lipgloss.NewStyle().
			Padding(1, 2)

	headerTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("230"))

	headerMetaStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("248"))

	selfPrefixStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86"))

	peerPrefixStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("223"))

	selfBodyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("121"))

	peerBodyStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("254"))

	bannerStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("69")).
			Foreground(lipgloss.Color("230")).
			Padding(0, 1)

	errorBannerStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("203")).
				Foreground(lipgloss.Color("224")).
				Padding(0, 1)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)

	transcriptPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("67")).
				Padding(0, 1)

	inputPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("66")).
			Padding(0, 1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	typingStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243")).
			Italic(true).
			Padding(0, 1)
)

func RunChat(stdin io.Reader, stdout io.Writer, session *netpkg.SecureSession, peer netpkg.PeerIdentity, runtimeOptions RuntimeOptions) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	ti := textinput.New()
	ti.Placeholder = "Type a message and press Enter"
	ti.Prompt = "> "
	ti.Focus()
	ti.CharLimit = 4096

	vp := viewport.New(0, 0)
	vp.KeyMap = viewport.DefaultKeyMap()
	vp.MouseWheelEnabled = true

	events := make(chan tea.Msg, 16)
	model := &chatModel{
		runtimeOptions:   runtimeOptions,
		session:          session,
		peer:             peer,
		input:            ti,
		viewport:         vp,
		events:           events,
		remoteAddress:    session.RemoteAddress(),
		localFingerprint: session.LocalFingerprint(),
		peerFingerprint:  peer.Fingerprint,
		receiveDir:       filepath.Join(cwd, "received"),
		banners:          initialBanners(runtimeOptions),
		localName:        runtimeOptions.LocalName,
		peerName:         runtimeOptions.PeerName,
	}

	go readLoop(session, events, model.receiveDir, runtimeOptions)

	program := tea.NewProgram(
		model,
		tea.WithInput(stdin),
		tea.WithOutput(stdout),
		tea.WithAltScreen(),
	)

	if _, err := program.Run(); err != nil {
		return err
	}

	return model.exitErr
}

func readLoop(session *netpkg.SecureSession, events chan<- tea.Msg, receiveDir string, runtimeOptions RuntimeOptions) {
	for {
		message, err := session.ReceiveMessage()
		if err != nil {
			events <- sessionError{err: err}
			return
		}

		switch message.Type {
		case protocol.MessageTypeChat:
			events <- incomingMessage{body: message.Text}
		case protocol.MessageTypeTyping:
			events <- typingIndicator{}
		case protocol.MessageTypeFileStart:
			if runtimeOptions.MemoryOnly {
				_ = session.Close()
				events <- sessionError{err: errors.New("peer attempted file transfer while memory-only mode is active")}
				return
			}
			path, size, err := session.SaveIncomingFile(message.FileID, message.Name, message.Size, receiveDir)
			if err != nil {
				events <- sessionError{err: err}
				return
			}
			events <- incomingFile{name: message.Name, path: path, size: size}
		default:
			events <- sessionError{err: fmt.Errorf("unexpected message type %q", message.Type)}
			return
		}
	}
}

func waitForEvent(events <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		return <-events
	}
}

func (m *chatModel) Init() tea.Cmd {
	return waitForEvent(m.events)
}

func (m *chatModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.reflow()
		return m, nil
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.quitting = true
			_ = m.session.Close()
			return m, tea.Quit
		case tea.KeyCtrlW:
			m.quitting = true
			return m, panicWipeCmd(m.runtimeOptions, m.session)
		case tea.KeyEnter:
			body := strings.TrimSpace(m.input.Value())
			if body == "" {
				return m, nil
			}
			if body == "/quit" {
				m.quitting = true
				_ = m.session.Close()
				return m, tea.Quit
			}
			if m.disconnected {
				m.appendBanner("session is closed; panic wipe or restart a new session", true)
				m.reflow()
				return m, nil
			}
			if strings.HasPrefix(body, "/send ") {
				if m.runtimeOptions.MemoryOnly {
					m.appendBanner("file transfer is disabled in memory-only mode", true)
					m.reflow()
					return m, nil
				}
				path := strings.TrimSpace(strings.TrimPrefix(body, "/send "))
				if path == "" {
					m.appendBanner("usage: /send <path-to-file>", true)
					m.reflow()
					return m, nil
				}
				fileID, name, size, err := m.session.SendFile(path)
				if err != nil {
					m.appendBanner(fmt.Sprintf("file transfer failed: %v", err), true)
					m.reflow()
					return m, nil
				}
				m.lines = append(m.lines, chatLine{
					timestamp: time.Now(),
					speaker:   "you",
					body:      fmt.Sprintf("sent file %s (%d bytes, id %s)", name, size, fileID),
					self:      true,
				})
				m.appendBanner(fmt.Sprintf("file sent: %s (%d bytes)", name, size), false)
				m.input.SetValue("")
				m.reflow()
				return m, nil
			}
			if err := m.session.SendChat(body); err != nil {
				m.appendBanner(fmt.Sprintf("send failed: %v", err), true)
				m.reflow()
				return m, nil
			}
			m.lines = append(m.lines, chatLine{
				timestamp: time.Now(),
				speaker:   "you",
				body:      body,
				self:      true,
			})
			m.input.SetValue("")
			m.refreshTranscript(true)
			return m, nil
		}
	case typingIndicator:
		m.peerTyping = true
		m.peerTypingAt = time.Now()
		m.reflow()
		return m, tea.Batch(waitForEvent(m.events), clearTypingAfter(m.peerTypingAt))
	case clearTypingTick:
		if msg.at.Equal(m.peerTypingAt) {
			m.peerTyping = false
			m.reflow()
		}
		return m, nil
	case incomingMessage:
		m.peerTyping = false
		m.lines = append(m.lines, chatLine{
			timestamp: time.Now(),
			speaker:   "peer",
			body:      msg.body,
		})
		m.refreshTranscript(true)
		return m, waitForEvent(m.events)
	case incomingFile:
		m.lines = append(m.lines, chatLine{
			timestamp: time.Now(),
			speaker:   "peer",
			body:      fmt.Sprintf("sent file %s (%d bytes) -> %s", msg.name, msg.size, msg.path),
		})
		m.appendBanner(fmt.Sprintf("received file: %s", msg.path), false)
		m.reflow()
		return m, waitForEvent(m.events)
	case sessionError:
		m.disconnected = true
		m.exitErr = &SessionClosedError{Cause: msg.err}
		if !m.quitting {
			return m, tea.Quit
		}
		return m, nil
	case panicWipeComplete:
		m.bestEffortClear()
		if msg.err != nil {
			m.exitErr = msg.err
		}
		return m, tea.Quit
	}

	var cmds []tea.Cmd
	var cmd tea.Cmd

	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.Type == tea.KeyRunes {
		if !m.disconnected && !m.quitting && time.Since(m.lastTypingSentAt) > 2*time.Second {
			m.lastTypingSentAt = time.Now()
			cmds = append(cmds, sendTypingCmd(m.session))
		}
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *chatModel) View() string {
	if m.width == 0 {
		return "Loading chat..."
	}

	contentWidth := max(32, m.width-6)
	header := m.renderHeader(contentWidth)
	banners := m.renderBanners(contentWidth)
	transcript := m.renderTranscript(contentWidth)
	input := m.renderInput(contentWidth)
	status := m.renderStatusBar(contentWidth)

	sections := []string{header}
	if banners != "" {
		sections = append(sections, banners)
	}
	sections = append(sections, transcript)
	if typing := m.renderTypingIndicator(contentWidth); typing != "" {
		sections = append(sections, typing)
	}
	sections = append(sections, input, status)

	return appStyle.Width(m.width).Height(m.height).Render(
		lipgloss.JoinVertical(lipgloss.Left, sections...),
	)
}

func (m *chatModel) renderHeader(width int) string {
	title := headerTitleStyle.Render("Encrypted Terminal Chat")
	peerDisplay := m.peerName
	if peerDisplay == "" {
		peerDisplay = m.remoteAddress
	} else {
		peerDisplay = fmt.Sprintf("%s (%s)", m.peerName, m.remoteAddress)
	}
	meta := headerMetaStyle.Render(
		fmt.Sprintf(
			"mode  %s\npeer  %s\nlocal %s\ntheir key %s",
			m.modeLabel(),
			peerDisplay,
			m.localFingerprint,
			m.peerFingerprint,
		),
	)
	return panelStyle.Width(width).Render(lipgloss.JoinVertical(lipgloss.Left, title, meta))
}

func (m *chatModel) renderBanners(width int) string {
	if len(m.banners) == 0 {
		return ""
	}

	maxBanners := 2
	if len(m.banners) < maxBanners {
		maxBanners = len(m.banners)
	}

	rendered := make([]string, 0, maxBanners)
	for _, item := range m.banners[len(m.banners)-maxBanners:] {
		style := bannerStyle
		if item.error {
			style = errorBannerStyle
		}
		rendered = append(rendered, style.Width(width).Render(item.body))
	}

	return lipgloss.JoinVertical(lipgloss.Left, rendered...)
}

func (m *chatModel) renderTranscript(width int) string {
	return transcriptPanelStyle.Width(width).Height(m.viewport.Height + 2).Render(m.viewport.View())
}

func (m *chatModel) renderInput(width int) string {
	m.input.Width = max(12, width-6)
	return inputPanelStyle.Width(width).Render(m.input.View())
}

func (m *chatModel) renderStatusBar(width int) string {
	scrollState := "tail"
	if m.viewport.AtTop() {
		scrollState = "top"
	} else if !m.viewport.AtBottom() {
		scrollState = "scroll"
	}

	status := fmt.Sprintf(
		"%s  %s  lines:%d  scroll:%s  state:%s",
		m.remoteAddress,
		m.scrollHint(),
		len(m.lines),
		scrollState,
		m.connectionState(),
	)

	return statusBarStyle.Width(width).Render(status)
}

func (m *chatModel) reflow() {
	if m.width == 0 || m.height == 0 {
		return
	}

	contentWidth := max(32, m.width-6)
	transcriptInnerWidth := max(20, contentWidth-4)
	headerHeight := lipgloss.Height(m.renderHeader(contentWidth))
	bannersHeight := lipgloss.Height(m.renderBanners(contentWidth))
	inputHeight := lipgloss.Height(m.renderInput(contentWidth))
	statusHeight := lipgloss.Height(m.renderStatusBar(contentWidth))

	var typingHeight int
	if m.peerTyping {
		typingHeight = lipgloss.Height(m.renderTypingIndicator(contentWidth))
	}
	transcriptHeight := m.height - 2 - headerHeight - bannersHeight - typingHeight - inputHeight - statusHeight - 1
	if transcriptHeight < 8 {
		transcriptHeight = 8
	}

	m.viewport.Width = transcriptInnerWidth
	m.viewport.Height = transcriptHeight - 2
	if m.viewport.Height < 3 {
		m.viewport.Height = 3
	}

	m.refreshTranscript(true)
}

func (m *chatModel) refreshTranscript(scrollToBottom bool) {
	if m.viewport.Width == 0 {
		return
	}

	content := m.renderTranscriptContent(m.viewport.Width)
	m.viewport.SetContent(content)
	if scrollToBottom {
		m.viewport.GotoBottom()
	}
}

func (m *chatModel) renderTranscriptContent(width int) string {
	if len(m.lines) == 0 {
		return headerMetaStyle.Width(width).Render("No messages yet.")
	}

	rendered := make([]string, 0, len(m.lines))
	for _, line := range m.lines {
		rendered = append(rendered, m.renderChatLine(line, width))
	}

	return strings.Join(rendered, "\n\n")
}

func (m *chatModel) renderChatLine(line chatLine, width int) string {
	stamp := line.timestamp.Format("15:04:05")
	speaker := line.speaker
	if line.self && m.localName != "" {
		speaker = m.localName
	} else if !line.self && m.peerName != "" {
		speaker = m.peerName
	}
	prefix := fmt.Sprintf("%s  %s", stamp, speaker)

	prefixStyle := peerPrefixStyle
	bodyStyle := peerBodyStyle
	if line.self {
		prefixStyle = selfPrefixStyle
		bodyStyle = selfBodyStyle
	}

	prefixRendered := prefixStyle.Render(prefix)
	bodyRendered := bodyStyle.Width(width - 2).Render(line.body)
	bodyRendered = indentBlock(bodyRendered, "  ")

	return lipgloss.JoinVertical(lipgloss.Left, prefixRendered, bodyRendered)
}

func (m *chatModel) appendBanner(body string, isError bool) {
	m.banners = append(m.banners, banner{
		body:  body,
		error: isError,
	})
	if len(m.banners) > 8 {
		m.banners = m.banners[len(m.banners)-8:]
	}
}

func (m *chatModel) modeLabel() string {
	if m.runtimeOptions.MemoryOnly {
		return "memory-only"
	}
	return "normal"
}

func (m *chatModel) scrollHint() string {
	return "PgUp/PgDn scroll"
}

func (m *chatModel) connectionState() string {
	if m.disconnected {
		return "closed"
	}
	return "live"
}

func (m *chatModel) bestEffortClear() {
	for idx := range m.lines {
		m.lines[idx].body = ""
		m.lines[idx].speaker = ""
	}
	m.lines = nil
	for idx := range m.banners {
		m.banners[idx].body = ""
	}
	m.banners = nil
	m.input.SetValue("")
	m.remoteAddress = ""
	m.localFingerprint = ""
	m.peerFingerprint = ""
	m.localName = ""
	m.peerName = ""
}

func initialBanners(runtimeOptions RuntimeOptions) []banner {
	banners := []banner{{body: SecureSessionReady}}
	if runtimeOptions.MemoryOnly {
		banners = append(banners, banner{body: "Memory-only mode is active. File transfer is disabled. Press Ctrl+W for panic wipe."})
	} else {
		banners = append(banners, banner{body: "Use /send <path> to transfer a file. Press Ctrl+W for panic wipe."})
	}
	banners = append(banners, banner{body: "Use PgUp/PgDn or arrow keys to scroll. Press Esc, Ctrl+C, or /quit to exit."})
	return banners
}

func panicWipeCmd(runtimeOptions RuntimeOptions, session *netpkg.SecureSession) tea.Cmd {
	return func() tea.Msg {
		_ = session.Close()

		var errs []error
		if runtimeOptions.IdentityPath != "" {
			if err := cryptopkg.DeleteIdentity(runtimeOptions.IdentityPath); err != nil {
				errs = append(errs, err)
			}
		}
		if runtimeOptions.KnownPeersPath != "" {
			if err := trust.DeleteStore(runtimeOptions.KnownPeersPath); err != nil {
				errs = append(errs, err)
			}
		}

		return panicWipeComplete{err: errors.Join(errs...)}
	}
}

type SessionClosedError struct {
	Cause error
}

func (e *SessionClosedError) Error() string {
	if e == nil || e.Cause == nil {
		return "chat session ended"
	}
	return fmt.Sprintf("chat session ended: %v", e.Cause)
}

func (e *SessionClosedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (m *chatModel) renderTypingIndicator(width int) string {
	if !m.peerTyping {
		return ""
	}
	name := m.peerName
	if name == "" {
		name = "peer"
	}
	return typingStyle.Width(width).Render(name + " is typing...")
}

func clearTypingAfter(at time.Time) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(3 * time.Second)
		return clearTypingTick{at: at}
	}
}

func sendTypingCmd(session *netpkg.SecureSession) tea.Cmd {
	return func() tea.Msg {
		_ = session.SendTyping()
		return nil
	}
}

func indentBlock(value, prefix string) string {
	parts := strings.Split(value, "\n")
	for idx := range parts {
		parts[idx] = prefix + parts[idx]
	}
	return strings.Join(parts, "\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
