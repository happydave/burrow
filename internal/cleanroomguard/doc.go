// Package cleanroomguard tests the repository's Claude Code PreToolUse hook,
// .claude/hooks/cleanroom-guard, which refuses tool calls naming copyleft
// implementations of the protocol. The hook is Python; this package holds
// only its test, so the Go gate covers it.
package cleanroomguard
