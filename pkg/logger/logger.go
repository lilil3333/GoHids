package logger

import (
	"log"
	"os"
)

// Logger is a simple wrapper around standard log, but can be replaced with zap/logrus later
type Logger interface {
	Info(v ...interface{})
	Infof(format string, v ...interface{})
	Error(v ...interface{})
	Errorf(format string, v ...interface{})
	Fatal(v ...interface{})
	Fatalf(format string, v ...interface{})
}

type stdLogger struct {
	logger *log.Logger
}

func New() Logger {
	return &stdLogger{
		logger: log.New(os.Stdout, "[GoHIDS] ", log.LstdFlags|log.Lshortfile),
	}
}

func (l *stdLogger) Info(v ...interface{}) {
	l.logger.Println(append([]interface{}{"[INFO] "}, v...)...)
}

func (l *stdLogger) Infof(format string, v ...interface{}) {
	l.logger.Printf("[INFO] "+format, v...)
}

func (l *stdLogger) Error(v ...interface{}) {
	l.logger.Println(append([]interface{}{"[ERROR] "}, v...)...)
}

func (l *stdLogger) Errorf(format string, v ...interface{}) {
	l.logger.Printf("[ERROR] "+format, v...)
}

func (l *stdLogger) Fatal(v ...interface{}) {
	l.logger.Fatal(append([]interface{}{"[FATAL] "}, v...)...)
}

func (l *stdLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Fatalf("[FATAL] "+format, v...)
}

var Global Logger = New()

func Info(v ...interface{}) {
	Global.Info(v...)
}

func Infof(format string, v ...interface{}) {
	Global.Infof(format, v...)
}

func Error(v ...interface{}) {
	Global.Error(v...)
}

func Errorf(format string, v ...interface{}) {
	Global.Errorf(format, v...)
}

func Fatal(v ...interface{}) {
	Global.Fatal(v...)
}

func Fatalf(format string, v ...interface{}) {
	Global.Fatalf(format, v...)
}
