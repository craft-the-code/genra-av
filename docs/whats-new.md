# Writing "Có gì mới" (what users read about a new version)

Every version ships short notes for users, one file per language, beside the technical CHANGELOG.md:

- `whats-new/<version>.vi.md` (Vietnamese, written first; most users read this one), required
- `whats-new/<version>.en.md` (English, same content), required
- `whats-new/<version>.<lang>.md` for any other language the app gains: picked up automatically
  (add its heading to `TITLES` in `scripts/whats-new.py`)

They appear in the app's update dialog ("Genra AV Updater", in the user's language) and at the top of
the GitHub release. Work in progress goes in `whats-new/unreleased.<lang>.md`; the release PR renames
them to the version. The release fails when either file is missing or breaks the rules below
(`scripts/whats-new.py --check <version>` runs the same check locally).

## Shape

```
One-sentence summary of what is better for the user.

- What changed, in the user's words.
- At most six bullets, each under 160 characters.
```

## Rules

1. **Write for an office worker, not a developer.** Say what they can now do or what got better for
   them: "Quét được toàn bộ máy", not "Added full-drive scan scope".
2. **No technical detail.** No file names, paths, links, code, rule ids, library or OS internals,
   and no developer words such as API, hash, VBA, PowerShell or refactor. Those belong in CHANGELOG.md.
   The checker refuses the common ones.
3. **Name things as the app names them**: the button and page names in quotes ("Dọn sạch giúp tôi",
   "Máy của bạn"), so users can find them.
4. **Only what users notice.** Leave out internal fixes unless users saw the problem; then say what
   now works ("Tab Máy của bạn không còn để trống khi đang tải").
5. **Say it if the user must do something** (rare): one clear step.
6. **Calm and plain.** No fear words, no blame, no marketing ("mạnh mẽ", "tuyệt vời"). The voice is
   "Genra", not "chúng tôi".
7. **Same meaning in every language.** Translate the meaning, not word for word; keep the same bullets
   in the same order.
