# P2P Chat over Tor

Real-time encrypted chat using Tor hidden services. Both peers are equal - no server/client distinction.

> **Security Warning:** Arti's onion services are experimental and not as secure as C-Tor. Do not use for highly sensitive communications.

## Setup (one time)

```bash
# 1. Generate your keys (encryption + signing)
anyhide keygen -o mykeys
anyhide keygen -o mykeys --signing

# 2. Initialize your chat identity (bootstraps Tor, shows your .onion)
anyhide chat init -k mykeys -s mykeys.sign
# Output: Your .onion address: xyz123abc.onion

# 3. Add a contact (you need their .onion address and public keys)
anyhide chat add bob <bob.onion> --key bob.pub --sign-key bob.sign.pub
```

## Start Chatting

```bash
anyhide chat bob
# Enter your passphrase when prompted (input is hidden)
```

The system will:
1. Ask for your passphrase (required for encryption, input is hidden)
2. Create your hidden service
3. Try to connect to Bob's .onion address
4. If Bob isn't online, wait for him to connect to you
5. First successful connection (incoming or outgoing) establishes the session
6. Launch the TUI (Terminal User Interface)

## Pre-shared Carriers (optional)

Extra security layer - both parties must use the SAME files in the SAME order:

```bash
anyhide chat bob -c photo.jpg -c song.mp3 -c document.pdf

# The carrier files are NEVER transmitted - only a hash is verified
# This provides extra security: the files become an additional secret
# N files = N! additional security (3 files = 6 possible orders)
```

## Single-Peer TUI Interface

```
┌─ Anyhide Chat - bob ─────────────────────────────────┐
│ Connected | abc123...onion | 2↑ 1↓                   │
├──────────────────────────────────────────────────────┤
│                                                      │
│  [14:32] Connected to bob                            │
│  [14:32] Type /help for commands. Ctrl+Q to quit.    │
│  [14:33] you: Hello Bob!                             │
│  [14:33] bob: Hey Alice! How are you?                │
│                                                      │
├─ Input ──────────────────────────────────────────────┤
│ > your message here...                  11/256       │
└──────────────────────────────────────────────────────┘
```

The counter shows `current/max` characters. Turns yellow at <20 remaining, red at 0.

## Chat Management Commands

```bash
anyhide chat init -k <keys> -s <sign>   # Initialize your identity (shows .onion)
anyhide chat add <name> <onion> ...     # Add a contact
anyhide chat list                       # List contacts
anyhide chat show <name>                # Show contact details
anyhide chat show me                    # Show your own identity and .onion
anyhide chat remove <name>              # Remove a contact
anyhide chat export-qr -o me.png        # Export your identity as QR code
anyhide chat import-qr me.png -n alice  # Import contact from QR code
```

## Ephemeral Chat (no saved contact)

Chat without saving the contact - session data is lost when you quit. Useful for one-time conversations or maximum privacy.

```bash
# Option 1: Using command line arguments
anyhide chat -e --onion <peer.onion> --pubkey <hex64> --sign-key <hex64>

# Option 2: Using a QR code image
anyhide chat -e --from-qr contact_qr.png

# Example with inline keys:
anyhide chat -e \
  --onion xyz123abc.onion \
  --pubkey 0101010101010101010101010101010101010101010101010101010101010101 \
  --sign-key 0202020202020202020202020202020202020202020202020202020202020202
```

The ephemeral contact will appear as `~ephemeral` in the TUI and won't be saved to your contacts file.

## Multi-Contact Dashboard

Launch the multi-contact dashboard to manage all your chats in one interface:

```bash
# Launch dashboard (no contact specified)
anyhide chat

# With profile
anyhide chat --profile alice
```

### Dashboard Layout

```
╭──────────────────────────────────────────────────────────────────╮
│  ⠿ anyhide                                            v0.13.0   │
│ ─────────────────────────────────────────────────────────────── │
│ Contacts    │  alice   bob   ~guest                     ← Tabs  │
│─────────────├───────────────────────────────────────────────────│
│ ● alice   ▲ │ Messages                                    ▲     │
│ ○ bob     █ │ [14:32] alice: hola                         █     │
│ ◌ ~guest  █ │ [14:33] you: todo bien?                     █     │
│           │ │ [14:34] alice: si, vos?                     │     │
│           ▼ │                                             ▼     │
│─────────────├───────────────────────────────────────────────────│
│  + Add      │ Input                                    128/256  │
│  ⚡ Quick   │ Mensaje...                                        │
│─────────────┴───────────────────────────────────────────────────│
│ 🔒 Tor ● | Chat ● | abc12345...onion | ↑↓: nav | Ctrl+Q: quit  │
╰──────────────────────────────────────────────────────────────────╯
```

### Dashboard Features

- **Branding**: `⠿ anyhide` title bar with version number
- **Rounded borders**: Outer border with rounded corners, cyan theme
- **Native tabs**: Active tab highlighted (cyan background, bold), inactive in gray
- **Scrollbar**: Vertical scrollbar on messages area (appears when content overflows), with `▲`/`▼` arrows and `█` thumb
- **Context-sensitive hints**: Status bar hints change based on focused panel

### Contact Status Indicators

- `●` Online (connected)
- `○` Offline
- `◌` Ephemeral contact
- `◐` Connecting...
- `◀` Incoming request
- `▶` Pending accept

### Status Bar Indicators

- `🔒 Tor ●` / `⚠ Tor ○` / `◐ Tor...` - Tor connection status
- `Chat ●` / `Chat ◐` / `Chat ○` - Hidden service status
- Truncated `.onion` address
- `👤N` - Pending requests from known contacts
- `👻N` - Pending requests from unknown contacts
- `🔔N` - Unseen notifications

### Keyboard Shortcuts

**Global:**
- `Ctrl+Q` - Quit application
- `Ctrl+P` - Open command console (works from any panel)
- `Tab`/`Shift+Tab` - Cycle between sidebar, tabs, and input
- `Ctrl+W` - Close active tab
- `Ctrl+Left`/`Right` or `Alt+Left`/`Right` - Switch tabs
- `Alt+1-9` - Jump to tab by number
- `Esc` - Quit (from sidebar/tabs) or go back to sidebar (from input)

**Sidebar:**
- `Up`/`Down` or `j`/`k` - Navigate contacts
- `Enter`/`Right`/`l` - Open/connect to contact
- `x`/`Delete` - Reject incoming request
- `+` - Add new contact (dialog form)
- `e` - Quick ephemeral contact (dialog form)
- `r` - View known contact requests
- `z` - View unknown contact requests
- `n` - View next unseen notification
- `N` - Mark all notifications as seen
- `/` - Open command console

**Tabs:**
- `Left`/`Right` or `h`/`l` - Switch tabs
- `PageUp`/`PageDown` - Scroll messages (5 lines)
- `Ctrl+Up`/`Down` - Scroll messages (1 line)
- `/` - Open command console

**Input:**
- `Enter` - Send message
- `PageUp`/`PageDown` - Scroll messages (5 lines)
- `Ctrl+Up`/`Down` - Scroll messages (1 line)

### Command Console (doom-style overlay)

A drop-down console overlay (40% of screen) for executing commands and viewing output.

- Open with `/` (from sidebar or tabs) or `Ctrl+P` (from anywhere)
- Close with `Esc`
- Command history with `Up`/`Down` arrows
- Scroll output with `PageUp`/`PageDown`
- All console state is securely zeroized on session end

Available console commands:
- `/quit` (`q`, `exit`) - Quit the application
- `/close` (`c`) - Close active conversation tab
- `/status` (`s`) - Show session status
- `/clear` - Clear conversation messages (or console output when in console)
- `/requests` (`r`) - Show pending chat requests
- `/notifications` (`n`) - Show notification count
- `/help` (`h`, `?`) - Show available commands; `/help keys` shows all keyboard shortcuts
- `/debug` (`d`) - Show debug info (onion, contacts, sessions, Tor status)
- `/myonion` (`me`) - Show your .onion address
- `/who <name>` - Show a contact's .onion address

### Request/Accept Protocol

For privacy, incoming connections require manual acceptance:

1. Someone connects to your .onion - appears as notification
2. Known contacts show as `👤`, unknown show as `👻`
3. Select the request and press `Enter` to accept
4. Press `x` or `Delete` to reject

This prevents DDoS via chat requests - you choose who to talk to.

### Connect On-demand

Select any contact from the sidebar and press `Enter`:
1. Opens conversation tab
2. Connects to their .onion address
3. Performs handshake automatically
4. Contact status updates to online

### Add Contact and Quick Ephemeral Dialogs

From the sidebar, press `+` to add a new contact via a multi-field dialog (Name, Onion, Public Key, Sign Key), or press `e` to start a quick ephemeral chat by entering just an onion address.

## Profiles

Run multiple identities on the same machine (useful for testing):

```bash
# Terminal 1:
anyhide chat --profile alice init -k alice -s alice.sign
anyhide chat --profile alice add bob <bob.onion> --key bob.pub --sign-key bob.sign.pub
anyhide chat --profile alice bob

# Terminal 2:
anyhide chat --profile bob init -k bob -s bob.sign
anyhide chat --profile bob add alice <alice.onion> --key alice.pub --sign-key alice.sign.pub
anyhide chat --profile bob alice
```

Each profile gets separate config and Tor state directories.

## How It Works

1. Both parties initialize with `chat init` (creates their .onion identity)
2. Exchange identities out-of-band:
   - **Option A (QR):** `chat export-qr` to generate QR, scan with `chat import-qr`
   - **Option B (Manual):** Share .onion address and public keys, use `chat add`
3. Run `anyhide chat <contact>` - both peers create hidden services and race to connect
4. First successful connection wins, handshake establishes encrypted session
5. Messages encrypted with Double Ratchet protocol for forward secrecy

## Data Persistence

In ALL chat modes (normal or ephemeral), messages and session keys are NEVER written to disk. All cryptographic state is kept in RAM only and zeroized when the session ends. The only difference is whether the contact identity (onion address, public keys) is saved to `chat.toml`.
