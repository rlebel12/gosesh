package internal

import "flag"

const (
	dirDefault = "./identity"
	dirUsage   = "directory to store identity data"
)

func DirFlag(dir *string) {
	flag.StringVar(dir, "directory", dirDefault, dirUsage)
	flag.StringVar(dir, "d", dirDefault, dirUsage+" (shorthand)")
}
