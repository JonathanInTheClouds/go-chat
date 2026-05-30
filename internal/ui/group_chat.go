package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	grouppkg "github.com/JonathanInTheClouds/go-chat/internal/group"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type groupClearTypingTick struct {
	memberID string
	at       time.Time
}

type groupChatModel struct {
	room             grouppkg.Transport
	input            textinput.Model
	viewport         viewport.Model
	width            int
	height           int
	lines            []chatLine
	banners          []banner
	members          map[string]grouppkg.Member
	typing           map[string]time.Time
	quitting         bool
	disconnected     bool
	exitErr          error
	lastTypingSentAt time.Time
}

func RunGroupChat(stdin io.Reader, stdout io.Writer, room grouppkg.Transport) error {
	ti := textinput.New()
	ti.Placeholder = "Type a group message and press Enter"
	ti.Prompt = "> "
	ti.Focus()
	ti.CharLimit = 4096

	vp := viewport.New(0, 0)
	vp.KeyMap = viewport.DefaultKeyMap()
	vp.MouseWheelEnabled = true

	members := map[string]grouppkg.Member{}
	for _, member := range room.Members() {
		members[member.ID] = member
	}
	local := room.LocalMember()
	members[local.ID] = local

	model := &groupChatModel{
		room:     room,
		input:    ti,
		viewport: vp,
		banners:  initialGroupBanners(room),
		members:  members,
		typing:   map[string]time.Time{},
	}

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

func waitForGroupEvent(events <-chan grouppkg.Event) tea.Cmd {
	return func() tea.Msg {
		return <-events
	}
}

func (m *groupChatModel) Init() tea.Cmd {
	return waitForGroupEvent(m.room.Events())
}

func (m *groupChatModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			_ = m.room.Close()
			return m, tea.Quit
		case tea.KeyTab:
			if strings.HasPrefix("/quit", m.input.Value()) {
				m.input.SetValue("/quit")
				m.input.CursorEnd()
			}
			return m, nil
		case tea.KeyEnter:
			body := strings.TrimSpace(m.input.Value())
			if body == "" {
				return m, nil
			}
			if body == "/quit" {
				m.quitting = true
				_ = m.room.Close()
				return m, tea.Quit
			}
			if strings.HasPrefix(body, "/send ") {
				m.appendBanner("file transfer is not available in group rooms yet", true)
				m.reflow()
				return m, nil
			}
			if m.disconnected {
				m.appendBanner("room is closed; restart a new room to continue", true)
				m.reflow()
				return m, nil
			}
			if err := m.room.SendChat(body); err != nil {
				m.appendBanner(fmt.Sprintf("send failed: %v", err), true)
				m.reflow()
				return m, nil
			}
			m.input.SetValue("")
			return m, nil
		}
	case grouppkg.Event:
		return m.handleGroupEvent(msg)
	case groupClearTypingTick:
		if at, ok := m.typing[msg.memberID]; ok && at.Equal(msg.at) {
			delete(m.typing, msg.memberID)
			m.reflow()
		}
		return m, nil
	}

	var cmds []tea.Cmd
	var cmd tea.Cmd
	if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.Type == tea.KeyRunes {
		if !m.disconnected && !m.quitting && time.Since(m.lastTypingSentAt) > 2*time.Second {
			m.lastTypingSentAt = time.Now()
			cmds = append(cmds, sendGroupTypingCmd(m.room))
		}
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)
	m.input, cmd = m.input.Update(msg)
	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m *groupChatModel) handleGroupEvent(event grouppkg.Event) (tea.Model, tea.Cmd) {
	switch event.Type {
	case grouppkg.EventMemberList:
		m.replaceMembers(event.Members)
		m.appendBanner(fmt.Sprintf("joined room with %d members", len(event.Members)), false)
		m.reflow()
		return m, waitForGroupEvent(m.room.Events())
	case grouppkg.EventMemberJoined:
		m.members[event.Member.ID] = event.Member
		m.appendBanner(fmt.Sprintf("%s joined", displayMember(event.Member)), false)
		m.reflow()
		return m, waitForGroupEvent(m.room.Events())
	case grouppkg.EventMemberLeft:
		delete(m.members, event.Member.ID)
		delete(m.typing, event.Member.ID)
		m.appendBanner(fmt.Sprintf("%s left", displayMember(event.Member)), false)
		m.reflow()
		return m, waitForGroupEvent(m.room.Events())
	case grouppkg.EventMessage:
		delete(m.typing, event.Member.ID)
		m.lines = append(m.lines, chatLine{
			timestamp: time.Now(),
			speaker:   displayMember(event.Member),
			body:      event.Text,
			self:      event.Member.ID == m.room.LocalMember().ID,
		})
		m.refreshTranscript(true)
		return m, waitForGroupEvent(m.room.Events())
	case grouppkg.EventTyping:
		if event.Member.ID != m.room.LocalMember().ID {
			now := time.Now()
			m.typing[event.Member.ID] = now
			m.reflow()
			return m, tea.Batch(waitForGroupEvent(m.room.Events()), clearGroupTypingAfter(event.Member.ID, now))
		}
		return m, waitForGroupEvent(m.room.Events())
	case grouppkg.EventClosed:
		m.disconnected = true
		if event.Err != nil {
			m.exitErr = &SessionClosedError{Cause: event.Err}
		}
		if !m.quitting {
			return m, tea.Quit
		}
		return m, nil
	case grouppkg.EventError:
		m.appendBanner(fmt.Sprintf("room warning: %v", event.Err), true)
		m.reflow()
		return m, waitForGroupEvent(m.room.Events())
	default:
		return m, waitForGroupEvent(m.room.Events())
	}
}

func (m *groupChatModel) View() string {
	if m.width == 0 {
		return "Loading group chat..."
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

func (m *groupChatModel) renderHeader(width int) string {
	title := headerTitleStyle.Render("Encrypted Group Chat")
	lines := []string{
		fmt.Sprintf("room  %s", m.room.RoomName()),
		fmt.Sprintf("id    %s", m.groupIDLabel()),
		fmt.Sprintf("local %s", m.room.LocalMember().Fingerprint),
		fmt.Sprintf("members %s", strings.Join(m.memberNames(), ", ")),
	}
	if m.room.InviteAddress() != "" {
		lines = append(lines, fmt.Sprintf("invite chat room join -n <name> -u %s %s", m.room.InviteAddress(), m.room.RoomName()))
	}
	meta := headerMetaStyle.Render(
		strings.Join(lines, "\n"),
	)
	return panelStyle.Width(width).Render(lipgloss.JoinVertical(lipgloss.Left, title, meta))
}

func (m *groupChatModel) renderBanners(width int) string {
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

func (m *groupChatModel) renderTranscript(width int) string {
	return transcriptPanelStyle.Width(width).Height(m.viewport.Height + 2).Render(m.viewport.View())
}

func (m *groupChatModel) renderInput(width int) string {
	m.input.Width = max(12, width-6)
	return inputPanelStyle.Width(width).Render(m.input.View())
}

func (m *groupChatModel) renderStatusBar(width int) string {
	status := fmt.Sprintf(
		"%s  members:%d  lines:%d  state:%s",
		m.room.RoomName(),
		len(m.members),
		len(m.lines),
		m.connectionState(),
	)
	return statusBarStyle.Width(width).Render(status)
}

func (m *groupChatModel) reflow() {
	if m.width == 0 || m.height == 0 {
		return
	}

	contentWidth := max(32, m.width-6)
	transcriptInnerWidth := max(20, contentWidth-4)
	headerHeight := lipgloss.Height(m.renderHeader(contentWidth))
	bannersHeight := lipgloss.Height(m.renderBanners(contentWidth))
	inputHeight := lipgloss.Height(m.renderInput(contentWidth))
	statusHeight := lipgloss.Height(m.renderStatusBar(contentWidth))
	typingHeight := lipgloss.Height(m.renderTypingIndicator(contentWidth))

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

func (m *groupChatModel) refreshTranscript(scrollToBottom bool) {
	if m.viewport.Width == 0 {
		return
	}
	content := m.renderTranscriptContent(m.viewport.Width)
	m.viewport.SetContent(content)
	if scrollToBottom {
		m.viewport.GotoBottom()
	}
}

func (m *groupChatModel) renderTranscriptContent(width int) string {
	if len(m.lines) == 0 {
		return headerMetaStyle.Width(width).Render("No group messages yet.")
	}
	rendered := make([]string, 0, len(m.lines))
	for _, line := range m.lines {
		rendered = append(rendered, m.renderChatLine(line, width))
	}
	return strings.Join(rendered, "\n\n")
}

func (m *groupChatModel) renderChatLine(line chatLine, width int) string {
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

func (m *groupChatModel) renderTypingIndicator(width int) string {
	if len(m.typing) == 0 {
		return ""
	}
	names := make([]string, 0, len(m.typing))
	for memberID := range m.typing {
		names = append(names, displayMember(m.members[memberID]))
	}
	sort.Strings(names)
	return typingStyle.Width(width).Render(strings.Join(names, ", ") + " typing...")
}

func (m *groupChatModel) appendBanner(body string, isError bool) {
	m.banners = append(m.banners, banner{body: body, error: isError})
	if len(m.banners) > 8 {
		m.banners = m.banners[len(m.banners)-8:]
	}
}

func (m *groupChatModel) connectionState() string {
	if m.disconnected {
		return "closed"
	}
	return "live"
}

func (m *groupChatModel) groupIDLabel() string {
	if m.room.GroupID() == "" {
		return "pending"
	}
	return m.room.GroupID()
}

func (m *groupChatModel) replaceMembers(members []grouppkg.Member) {
	m.members = map[string]grouppkg.Member{}
	for _, member := range members {
		m.members[member.ID] = member
	}
}

func (m *groupChatModel) memberNames() []string {
	names := make([]string, 0, len(m.members))
	for _, member := range m.members {
		names = append(names, displayMember(member))
	}
	sort.Strings(names)
	return names
}

func displayMember(member grouppkg.Member) string {
	if member.Name != "" {
		return member.Name
	}
	if member.ID != "" {
		return member.ID
	}
	return "unknown"
}

func clearGroupTypingAfter(memberID string, at time.Time) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(3 * time.Second)
		return groupClearTypingTick{memberID: memberID, at: at}
	}
}

func sendGroupTypingCmd(room grouppkg.Transport) tea.Cmd {
	return func() tea.Msg {
		_ = room.SendTyping()
		return nil
	}
}

func initialGroupBanners(room grouppkg.Transport) []banner {
	banners := []banner{{body: SecureSessionReady}}
	banners = append(banners,
		banner{body: "Group text chat is active. File transfer is not available in rooms yet."},
		banner{body: "Press Esc, Ctrl+C, or /quit to exit."},
	)
	return banners
}
