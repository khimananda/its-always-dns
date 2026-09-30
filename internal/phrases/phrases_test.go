package phrases

import (
	"strings"
	"testing"
)

func TestTitles(t *testing.T) {
	ts := Titles()
	if len(ts) < 8 {
		t.Fatalf("only %d titles", len(ts))
	}
	for _, x := range ts {
		if len(x) > 32 || !strings.HasPrefix(x, "The ") {
			t.Errorf("titles start with The and fit in 32 characters: %q", x)
		}
	}
}

func TestLessons(t *testing.T) {
	ls := Lessons()
	if len(ls) < 8 {
		t.Fatalf("only %d lessons; check the title | text format", len(ls))
	}
	for _, l := range ls {
		if l.Title == "" || len(l.Text) < 40 || strings.Count(l.Text, ". ") > 2 {
			t.Errorf("lesson needs a title and one or two real sentences: %+v", l)
		}
	}
}

func TestHaikuSyllablesAreAJoke(t *testing.T) {
	if len(strings.Split(Haiku, "\n")) != 3 {
		t.Error("a haiku has three lines")
	}
}
