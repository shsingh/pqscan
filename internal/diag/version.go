package diag

// mainVersion is injected via ldflags -X diag.mainVersion at release
// builds; keep it in sync with cmd/pqscan's version const by build flags
// (single source = the build system; CI passes both).
var mainVersion = "0.0.1"
