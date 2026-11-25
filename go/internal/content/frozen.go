package content

// FrozenVersion is the content release the frozen answers were recorded at (PRO-428): every record of
// migration/fixtures/cases.json and of the golden files pins it as content.version. The pack and release history
// of that release are kept unchanged in frozen/ (FrozenPackFile, FrozenHistoryFile) after later releases are
// added, so the frozen answers keep being replayed against the content they were recorded with, not against the
// current pack with only its version string changed.
const FrozenVersion = "2026.11.9"

// FrozenPackFile and FrozenHistoryFile are the frozen copies, relative to this package's directory.
const (
	FrozenPackFile    = "frozen/pack-2026.11.9.json"
	FrozenHistoryFile = "frozen/history-2026.11.9.json"
)
