package utils

import (
	"strings"
	timex "time"
)

func GetMoment() (string, int64) {
	TR_TIME_OFFSET := 3

	t := timex.UnixMilli(timex.Now().UTC().UnixMilli())
	t = t.Add(timex.Duration(TR_TIME_OFFSET) * timex.Hour)
	timestamp := t.UTC().Format(timex.RFC3339Nano)
	timestamp = strings.ReplaceAll(timestamp, "T", " ")
	timestamp = strings.TrimSuffix(timestamp, "Z")
	return timestamp, t.UnixMilli()
}

func AddMinute(time int64, minutes int) (string, int64) {

	n := minutes
	afterTime := timex.UnixMilli(time)
	afterTime = afterTime.Add(timex.Duration(n) * timex.Minute)
	afterTimeMilli := afterTime.UTC().UnixMilli()
	afterTimestamp := afterTime.UTC().Format(timex.RFC3339Nano)
	afterTimestamp = strings.ReplaceAll(afterTimestamp, "T", " ")
	afterTimestamp = strings.TrimSuffix(afterTimestamp, "Z")

	return afterTimestamp, afterTimeMilli
}
