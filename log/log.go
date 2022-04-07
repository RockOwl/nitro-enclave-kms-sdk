package log

import "fmt"

const (
	TraceLevel Level = 0
	DebugLevel Level = 10
	InfoLevel  Level = 20
	WarnLevel  Level = 30
	ErrorLevel Level = 40
	FatalLevel Level = 50
	OffLevel   Level = 60
)

var (
	CurLevel = DebugLevel
)

type Level = int

func SetLevel(level Level) {
	CurLevel = level
}

func Debug(a ...interface{}) {
	if CurLevel <= DebugLevel {
		fmt.Println(a...)
	}
}
func Debugf(format string, a ...interface{}) {
	if CurLevel <= DebugLevel {
		fmt.Printf(format, a...)
	}
}
func Info(a ...interface{}) {
	if CurLevel <= InfoLevel {
		fmt.Println(a...)
	}
}
func Infof(format string, a ...interface{}) {
	if CurLevel <= InfoLevel {
		fmt.Printf(format, a...)
	}
}
func Warn(a ...interface{}) {
	if CurLevel <= WarnLevel {
		fmt.Println(a...)
	}
}
func Warnf(format string, a ...interface{}) {
	if CurLevel <= WarnLevel {
		fmt.Printf(format, a...)
	}
}
func Error(a ...interface{}) {
	if CurLevel <= ErrorLevel {
		fmt.Println(a...)
	}
}
func Errorf(format string, a ...interface{}) {
	if CurLevel <= ErrorLevel {
		fmt.Printf(format, a...)
	}
}
