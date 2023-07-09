package logger

import "github.com/getamis/sirius/log"

var logger = log.Discard()

func Logger() log.Logger {
	return logger
}

func SetLogger(log log.Logger) {
	logger = log
}
