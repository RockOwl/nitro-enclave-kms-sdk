package crypto

import (
	"math/rand"
	"sync"
	"time"
)

var (
	charset = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var rander *rand.Rand
var randerMutex sync.Mutex

func init() {
	rander = rand.New(rand.NewSource(time.Now().UnixNano()))
}

// RandomString 随机
func RandomString(n int) string {
	randerMutex.Lock()
	defer randerMutex.Unlock()

	b := make([]byte, n)
	for index := 0; index < n; index++ {
		b[index] = charset[rander.Intn(len(charset))]
	}
	return string(b)
}
