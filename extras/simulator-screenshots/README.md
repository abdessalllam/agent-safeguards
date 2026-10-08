# Simulator screenshots (optional, Claude Code on macOS)

Safe iOS Simulator screenshots for agents. Two small files, wired up by hand because they depend on your own settings.

| File | What it does |
| --- | --- |
| `sim-shot` | Captures the booted simulator with `xcrun simctl io`, shrinks the PNG to at most 600 pixels on its longest side with `sips`, and prints the path. The agent then reads that file with the image reader. |
| `block-simulator-screenshot.py` | A Claude Code `PreToolUse` hook. It holds the simulator control tool's `screenshot` action for you to approve. Other actions (`launch`, `attach`, `tap`, and so on) are not touched. |

## Why

The `screenshot` action of the iOS Simulator control tool returns an image block the API rejects ("Input tag ... does not match any of the expected tags"). The bad block stays in the chat history, so every later message fails and the chat is lost. The hook stops an agent from calling it. An unattended session cannot answer the prompt, so the call stays blocked there. `sim-shot` is the safe way to get the same picture.

## Install

Run these from a clone of this repository. Symlinks keep the scripts next to the `lib/` and `locales/` folders they load.

```sh
mkdir -p ~/.local/bin ~/.claude/hooks
ln -s "$PWD/extras/simulator-screenshots/sim-shot" ~/.local/bin/sim-shot
ln -s "$PWD/extras/simulator-screenshots/block-simulator-screenshot.py" ~/.claude/hooks/block-simulator-screenshot.py
```

Then add this to `~/.claude/settings.json`, merging it with what is already there:

```json
{
  "permissions": {
    "allow": ["Bash(sim-shot:*)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__Claude_Code_iOS_Simulator__control",
        "hooks": [
          { "type": "command", "command": "python3 -I $HOME/.claude/hooks/block-simulator-screenshot.py" }
        ]
      }
    ]
  }
}
```

Start a new session and check that `/hooks` lists the entry.

## Using sim-shot

```sh
sim-shot                          # saves a new file in the temp folder and prints the path
sim-shot /path/to/new-shot.png    # saves where you say
sim-shot --device "iPhone 17 Pro" --max-side 800
```

- It only creates new `.png` files. It refuses to overwrite an existing file or to write any other extension, so the allow rule above is safe to grant.
- The result stays within 1568 pixels (default 600) and 1 MB. A heavier capture is shrunk further until it fits. These limits are shared with the [website screenshot extras](../web-screenshots/README.md).
- It captures into the temp folder first, because `simctl` is refused ("Operation not permitted") when it writes straight into `~/Documents` and similar protected folders. Only `sips` writes the final file, so any folder works as the output.
- It does not boot a simulator. If none is running it fails with a message, and the agent should skip the screenshot.

## Limits

- The iOS Simulator exists only on macOS.
- The hook matches the tool name `mcp__Claude_Code_iOS_Simulator__control`. If your host names that tool differently, change the `matcher`.
- Messages come from `locales/en.json` (`sim_shot.*` and `simulator_hook.*`).
