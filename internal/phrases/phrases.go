// Package phrases holds the jokes and the lessons. Contributors edit the .txt files.
package phrases

import (
	_ "embed"
	"hash/fnv"
	"strings"
)

//go:embed titles.txt
var titlesRaw string

//go:embed why.txt
var whyRaw string

// Haiku is the haiku.
const Haiku = "It's not DNS.\nThere's no way it's DNS.\nIt was DNS."

// Lesson is one real DNS failure mode.
type Lesson struct{ Title, Text string }

// Titles returns every case title.
func Titles() []string { return lines(titlesRaw) }

// Lessons returns every entry for the why command.
func Lessons() []Lesson {
	var out []Lesson
	for _, l := range lines(whyRaw) {
		t, x, ok := strings.Cut(l, "|")
		if ok {
			out = append(out, Lesson{strings.TrimSpace(t), strings.TrimSpace(x)})
		}
	}
	return out
}

// Hash turns a seed into a stable number.
func Hash(seed string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(seed))
	return h.Sum32()
}

// Pick chooses an item from list by seed.
func Pick(list []string, seed uint32) string {
	if len(list) == 0 {
		return ""
	}
	return list[int(seed%uint32(len(list)))]
}

func lines(raw string) []string {
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}
