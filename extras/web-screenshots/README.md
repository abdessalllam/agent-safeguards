# Website screenshots (optional, Claude Code)

Website screenshots that stay inside fixed limits: PNG only, at most 1568 pixels on the longest side, at most 1 MB. Two small files, wired up by hand because they depend on your own settings.

| File | What it does |
| --- | --- |
| `web-shot` | Takes a screenshot of an `http` or `https` page with headless Chrome (or Chromium, Edge, Brave), keeps it within the limits, saves it as a new PNG, and prints the path. The agent then reads that file with the image reader. |
| `limit-browser-screenshot.py` | A Claude Code `PreToolUse` hook for the in-app browser and the Claude in Chrome extension. It denies a `screenshot` or `zoom` that does not ask for `scale` 0.5 or lower, and tells the agent how to retry. Clicks, typing and every other action are not touched. |

## Why

Every screenshot stays in the chat and is sent again with each new message. The API rejects an oversized image that a browser or computer-use tool returns instead of shrinking it, and a request with more than 20 images caps every image at 2000 pixels. The documented limits are on the [vision page](https://platform.claude.com/docs/en/build-with-claude/vision). Small images also cost fewer tokens, and text stays readable at 1280 pixels.

## Limits

| Limit | Value |
| --- | --- |
| Format | PNG |
| Default viewport | 1280 by 800 |
| Longest side | 1568 pixels at most (`--width` and `--height` accept 100 to 1568) |
| File size | 1 MB at most. A heavier capture is shrunk in 20% steps until it fits, and refused if it cannot get under 1 MB above 320 pixels. |
| Browser tool scale | 0.5 or lower |

These values come from `lib/agent_safeguards/screenshot.py` and the hook, and the simulator extras share them.

## Install

Run these from a clone of this repository. Symlinks keep the scripts next to the `lib/` and `locales/` folders they load.

```sh
mkdir -p ~/.local/bin ~/.claude/hooks
ln -s "$PWD/extras/web-screenshots/web-shot" ~/.local/bin/web-shot
ln -s "$PWD/extras/web-screenshots/limit-browser-screenshot.py" ~/.claude/hooks/limit-browser-screenshot.py
```

Then add this to `~/.claude/settings.json`, merging it with what is already there:

```json
{
  "permissions": {
    "allow": ["Bash(web-shot:*)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__Claude_Browser__(computer|browser_batch)|mcp__claude-in-chrome__(computer|browser_batch)",
        "hooks": [
          { "type": "command", "command": "python3 -I $HOME/.claude/hooks/limit-browser-screenshot.py" }
        ]
      }
    ]
  }
}
```

Start a new session and check that `/hooks` lists the entry.

## Using web-shot

```sh
web-shot https://example.com                      # saves a new file in the temp folder and prints the path
web-shot http://localhost:3000 shot.png           # saves where you say
web-shot https://example.com --width 1024 --height 768
```

- Only `http` and `https` addresses are accepted. `file:`, `javascript:`, `data:` and similar schemes are refused, because a screenshot of a local file would put its content in front of the model, and an address with a username or password is refused so credentials never reach a log.
- It only creates new `.png` files. It refuses to overwrite an existing file or to write any other extension, and a page that answers with a file to download is kept inside the throwaway browser profile, which is deleted. It still makes web requests to the address it is given, as `curl` does, so granting the allow rule gives an agent the same reach as an allowed `curl`. Link-local addresses, which cloud metadata services use, are refused.
- It starts the browser with a fresh temporary profile, waits for the finished PNG, stops the browser, and removes the profile. A termination signal also stops the browser and removes the temporary files.
- It captures the viewport, not the whole page, and waits up to 5 seconds of page time for scripts to settle. A page that needs a login or interaction is out of reach, so use a browser tool for that and keep its screenshots small.

## The browser hook

The in-app browser and the Claude in Chrome extension return the image straight into the chat, so a hook cannot see or change what comes back. It limits the request instead: a `screenshot` or `zoom` must carry `scale` 0.5 or lower, including inside a `browser_batch` call. The tools already cap an unscaled image to a token budget, and this keeps it well below that.

- Older versions of the Claude in Chrome extension ignore `scale` and return a full-size image.
- If your host names these tools differently, change the `matcher`.
- Messages come from `locales/en.json` (`web_shot.*`, `screenshot.*` and `browser_hook.*`).
