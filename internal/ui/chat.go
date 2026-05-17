package ui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	netpkg "chat/internal/net"
	"chat/internal/protocol"

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
	remoteAddress    string
	localFingerprint string
	peerFingerprint  string
	receiveDir       string
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
)

func RunChat(stdin io.Reader, stdout io.Writer, session *netpkg.SecureSession, peer netpkg.PeerIdentity) error {
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
		session:          session,
		peer:             peer,
		input:            ti,
		viewport:         vp,
		events:           events,
		remoteAddress:    session.RemoteAddress(),
		localFingerprint: session.LocalFingerprint(),
		peerFingerprint:  peer.Fingerprint,
		receiveDir:       filepath.Join(cwd, "received"),
		banners: []banner{
			{body: SecureSessionReady},
			{body: "Use /send <path> to transfer a file. Use PgUp/PgDn or arrow keys to scroll. Press Esc, Ctrl+C, or /quit to exit."},
		},
	}

	go readLoop(session, events, model.receiveDir)

	program := tea.NewProgram(
		model,
		tea.WithInput(stdin),
		tea.WithOutput(stdout),
		tea.WithAltScreen(),
	)

	if _, err := program.Run(); err != nil {
		return err
	}

	return nil
}

func readLoop(session *netpkg.SecureSession, events chan<- tea.Msg, receiveDir string) {
	for {
		message, err := session.ReceiveMessage()
		if err != nil {
			events <- sessionError{err: err}
			return
		}

		switch message.Type {
		case protocol.MessageTypeChat:
			events <- incomingMessage{body: message.Text}
		case protocol.MessageTypeFileStart:
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
			if strings.HasPrefix(body, "/send ") {
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
	case incomingMessage:
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
		if !m.quitting {
			m.appendBanner(fmt.Sprintf("session ended: %v", msg.err), true)
			m.reflow()
		}
		return m, nil
	}

	var cmds []tea.Cmd
	var cmd tea.Cmd

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
	sections = append(sections, transcript, input, status)

	return appStyle.Width(m.width).Height(m.height).Render(
		lipgloss.JoinVertical(lipgloss.Left, sections...),
	)
}

func (m *chatModel) renderHeader(width int) string {
	title := headerTitleStyle.Render("Encrypted Terminal Chat")
	meta := headerMetaStyle.Render(
		fmt.Sprintf(
			"remote %s\nlocal %s\npeer  %s",
			m.remoteAddress,
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
		"%s  %s  lines:%d  scroll:%s",
		m.remoteAddress,
		"PgUp/PgDn scroll",
		len(m.lines),
		scrollState,
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

	transcriptHeight := m.height - 2 - headerHeight - bannersHeight - inputHeight - statusHeight - 1
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
	prefix := fmt.Sprintf("%s  %s", stamp, line.speaker)

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
