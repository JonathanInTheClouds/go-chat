# Group Chat Research

This document reviews the current application and outlines how to evolve it from encrypted 1:1 chat into group chat with more than two people.

## Current Application Review

The application is currently a direct encrypted 1:1 chat tool. The implementation is coherent for that scope: one TCP connection becomes one `SecureSession`, the UI renders one remote peer, and trust/admission is checked for one peer before entering chat.

Core strengths to preserve:

- Noise XX provides an authenticated encrypted transport after both sides exchange and verify identity material.
- The Ed25519 plus X25519 identity model gives the app a stable fingerprint for TOFU.
- Trust is enforced before the UI starts, and explicit `session_accept` / `session_reject` prevents one side from entering chat alone.
- The protocol already has typed messages, which gives a natural place to add group metadata.
- The server can keep accepting sequential sessions after disconnects.

Current blockers for group chat:

- `internal/net.SecureSession` represents exactly one remote peer, one TCP connection, one send cipher, and one receive cipher.
- `internal/app.runServe` accepts one peer at a time and hands the process to `ui.RunChat`, so the listener is not available for concurrent participants during a session.
- `internal/ui.chatModel` stores one `session`, one `peer`, one `peerName`, one `peerFingerprint`, and one typing indicator.
- Incoming file transfer is synchronous inside `SaveIncomingFile`; while receiving a file, that peer's read loop cannot process other messages.
- Trust is keyed by a single peer label and fingerprint. There is no room, invitation flow, member list, membership epoch, or group transcript identity.
- `protocol.Message` has no group ID, sender ID, message ID, target membership epoch, or origin identity fields.

The main conclusion: the app should not try to "just allow multiple peers" inside the existing `SecureSession` API. It needs a small group coordination layer above pairwise secure sessions.

## Relevant Protocol Research

There are two practical approaches:

1. Pairwise encrypted fan-out.
   Keep the existing Noise 1:1 session for every member connection. When Alice sends a group message, her client sends one encrypted copy to every connected peer. This is the smallest safe step for this codebase because it reuses the current trust model and transport encryption.

2. Sender keys or MLS-style group encryption.
   Messaging Layer Security (MLS), standardized as RFC 9420, is designed specifically for group key agreement and encrypted group messaging. RFC 9420 also describes the common sender-key strategy: distribute symmetric sender keys over existing 1:1 secure channels, then let each member encrypt group messages with their own sender key. Signal's public docs describe private groups and group features, and its developer docs expose the building blocks of the Signal protocol, but adopting Signal-style group crypto would be a larger protocol project.

Sources:

- RFC 9420, Messaging Layer Security: https://www.rfc-editor.org/info/rfc9420
- Noise Protocol Framework: https://noiseprotocol.org/noise_rev34.html
- Signal developer specifications: https://signal.org/docs
- Signal group chat support overview: https://support.signal.org/hc/en-us/articles/360007319331-Group-chats

## Recommended Direction

For this application, start with pairwise encrypted fan-out and explicit group membership. It is the best first group-chat milestone because it keeps each transport E2E encrypted with the already implemented Noise session and avoids inventing new group cryptography too early.

This does not provide the same scaling or group key agreement properties as MLS. It does support small group chat safely enough for a terminal tool if membership is explicit and every member's identity is verified before joining.

Target first milestone:

- One host creates a room.
- Multiple clients connect to the host concurrently.
- The host verifies each peer through the existing trust flow.
- Every admitted client sees a member list.
- A message from any client is relayed by the host to all other admitted clients over each recipient's pairwise encrypted session.
- Clients render messages with the sender's display name and fingerprint-derived stable member ID.

## Proposed Architecture

Add a group layer above `SecureSession`:

- `GroupRoom`: owns the room ID, admitted members, membership epoch, and broadcast loop.
- `GroupMember`: wraps a `SecureSession`, peer identity, display name, outbound queue, and connection state.
- `GroupEvent`: internal event type for member joined, member left, chat message, typing, file events, and errors.
- `GroupClient`: client-side wrapper for a single connection to a room host.

Transport shape:

- Host remains the only listener for the first implementation.
- Each client still has exactly one `SecureSession`, but the host has many concurrent `SecureSession` instances.
- The host is a relay, not plaintext storage. Messages are decrypted by the host today because pairwise fan-out terminates each secure session at the host. True host-blind group E2EE requires sender keys or MLS later.

Protocol additions:

- `group_hello`: announces requested room ID, display name, and optional client capabilities.
- `group_member_list`: sends current members and membership epoch.
- `group_member_joined`: announces a new member.
- `group_member_left`: announces a departure.
- `group_chat`: carries sender member ID, message ID, body, and membership epoch.
- `group_typing`: carries sender member ID and membership epoch.
- `group_file_start`, `group_file_chunk`, `group_file_complete`: later, with sender and message metadata.

Suggested message fields:

- `GroupID string`
- `MemberID string`
- `SenderID string`
- `MessageID string`
- `Epoch uint64`
- `Members []Member`
- `Capabilities []string`

`MemberID` should be derived from the verified identity fingerprint, not from the display name. Display names can change; fingerprints are the stable trust anchor.

## Command Surface

Keep existing 1:1 commands unchanged.

Add group commands:

```text
chat room serve <room-name> [-n name] [-u] [-m] [--listen host:port] [--tunnel]
chat room join <host:port> <room-name> [-n name] [-u] [-m]
```

Later commands:

```text
chat room list
chat room trust <room-name>
chat room invite <room-name>
```

For the first implementation, room names can be local labels and room IDs can be random values generated by the host at startup.

## Trust And Admission

Every pairwise connection should still complete these steps:

1. Noise handshake.
2. Identity frame exchange and fingerprint verification.
3. Name exchange.
4. Local trust check.
5. Admission decision.
6. Group admission.

Group-specific admission should add:

- The host verifies that the peer asked for the correct room.
- The host announces the joining member to all existing members.
- Existing members receive the new member's display name and fingerprint.
- Clients display membership changes in the transcript.

Open design question: should existing members have veto power over new members, or is the host the only room admin for the first milestone? For a terminal-first implementation, host-admin admission is simpler and matches the current `serve` model.

## UI Changes

Replace the single-peer UI assumptions:

- Show room name / room ID in the header.
- Show local fingerprint and participant count.
- Keep a compact member list, preferably in the header or a side panel when width allows.
- Render each line with the sender display name.
- Track typing by member ID, allowing multiple "typing" states.
- Change status from remote address to room state.

Data model changes:

- `chatLine.speaker` should become a stable member display value plus member ID.
- Incoming messages should carry sender identity, not just body.
- The UI should depend on a small interface rather than directly on `*net.SecureSession`, so the same Bubble Tea model can run 1:1 and group sessions.

## File Transfer

Defer group file transfer until text group chat works.

When implemented, avoid blocking one reader loop for the entire file. The current `SaveIncomingFile` consumes frames synchronously until completion, which is workable for 1:1 but awkward with multiplexed group events. A better group design is:

- Track incoming transfers by `file_id`.
- Let the read loop continue dispatching each chunk as an event.
- Write chunks through a per-transfer state machine.
- Include sender ID and group epoch in all file messages.

## Security Notes

Pairwise fan-out has clear limits:

- The host can read all messages because it decrypts inbound messages and re-encrypts outbound copies.
- Offline members do not receive history unless the host stores plaintext or encrypted per-member copies.
- Membership consistency depends on the host honestly relaying join/leave events.

Those limits are acceptable for an incremental local terminal tool if documented. They are not equivalent to Signal or MLS group E2EE.

To move beyond this, the next cryptographic phase should be sender keys distributed over pairwise Noise sessions, or an MLS implementation. MLS is the stronger long-term model but would require a real library or a substantial implementation effort; it should not be hand-rolled casually.

## Incremental Implementation Plan

1. Introduce protocol metadata.
   Add group message types and metadata fields while keeping current 1:1 validation intact.

2. Decouple UI from `SecureSession`.
   Define a minimal chat transport interface with `SendChat`, `SendTyping`, `SendFile`, `Close`, and an event stream. Adapt the current 1:1 session to it.

3. Add concurrent room server.
   Create a `GroupRoom` that accepts connections in a loop, performs existing trust/admission, then starts one read goroutine and one write goroutine per member.

4. Add group client.
   Join a room over one pairwise `SecureSession`, receive member events, and send `group_chat` messages to the host.

5. Update TUI for multiple members.
   Render room metadata and member-attributed messages.

6. Add tests.
   Use `net.Pipe` or local TCP listeners to verify three identities can join, one message from each member reaches the others, trust rejection blocks admission, and disconnects generate member-left events.

7. Revisit crypto.
   Decide whether the project wants small-group host-relayed chat only, sender-key group encryption, or MLS.

## Suggested First PR Scope

The first code PR should avoid file transfer and advanced room administration. It should prove:

- Alice hosts a room.
- Bob and Carol join concurrently.
- Bob sends a message.
- Alice and Carol see "Bob: message".
- Carol sends a message.
- Alice and Bob see "Carol: message".
- A peer with failed trust is rejected and never appears in the member list.

That scope exercises the main architectural change without mixing in group files, offline delivery, or new group cryptography.
