package main

import "testing"

func Test_convertPictureKeywordToFilename(t *testing.T) {
	// array of from-to pairs
	casePairs := [...]string{
		// No converssion
		"", "",
		"Test5", "Test5",
		"русский-язык7", "русский-язык7",
		"norskBokstaver-øåæØÅÆ", "norskBokstaver-øåæØÅÆ",
		"良い一日を", "良い一日を",

		// Converssion
		"\t\n\r ", "____",
		"*$test.#привет-/", "__test__привет-_",
	}
	for i := 0; i < len(casePairs); i += 2 {
		from := casePairs[i]
		expected := casePairs[i + 1]
		to := convertPictureKeywordToFilename(from)
		if expected != to {
			t.Errorf("Expected %s, got %s while converting %s", expected, to, from)
		}
	}

	
}
