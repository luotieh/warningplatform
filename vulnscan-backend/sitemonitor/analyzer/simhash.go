package analyzer

import (
	"crypto/md5"
	"encoding/binary"
	"strings"
	"unicode"
)

const simhashBits = 64

// Simhash computes a 64-bit simhash fingerprint for the given text.
// Similar texts produce fingerprints with small Hamming distance.
func Simhash(text string) uint64 {
	tokens := tokenize(text)
	if len(tokens) == 0 {
		return 0
	}

	var v [simhashBits]int
	for _, token := range tokens {
		h := hashToken(token)
		for i := 0; i < simhashBits; i++ {
			if (h>>uint(i))&1 == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}

	var fingerprint uint64
	for i := 0; i < simhashBits; i++ {
		if v[i] > 0 {
			fingerprint |= 1 << uint(i)
		}
	}
	return fingerprint
}

// SimhashDistance returns the Hamming distance between two simhash fingerprints.
func SimhashDistance(a, b uint64) int {
	x := a ^ b
	count := 0
	for x != 0 {
		count++
		x &= x - 1
	}
	return count
}

// SimhashSimilarity returns a 0-1 similarity score (1 = identical).
func SimhashSimilarity(a, b uint64) float64 {
	if a == 0 && b == 0 {
		return 1.0
	}
	dist := SimhashDistance(a, b)
	return 1.0 - float64(dist)/float64(simhashBits)
}

func tokenize(text string) []string {
	text = strings.ToLower(text)
	var tokens []string
	var current strings.Builder

	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	if len(tokens) < 3 {
		return tokens
	}
	ngrams := make([]string, 0, len(tokens)-2)
	for i := 0; i <= len(tokens)-3; i++ {
		ngrams = append(ngrams, tokens[i]+" "+tokens[i+1]+" "+tokens[i+2])
	}
	return append(tokens, ngrams...)
}

func hashToken(token string) uint64 {
	h := md5.Sum([]byte(token))
	return binary.LittleEndian.Uint64(h[:8])
}
