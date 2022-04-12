package env

type Env int

const (
	LocalEnv   Env = -1
	ReleaseEnv Env = 0
)

var (
	curEnv = LocalEnv
)

func IsLocal() bool {
	return curEnv == LocalEnv
}
func Set(setEnv Env) {
	curEnv = setEnv
}
