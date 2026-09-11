package web

import "embed"

// Dist contains the production Vue build. Docker copies frontend/dist here
// before compiling the single executable.
//
//go:embed dist/*
var Dist embed.FS
