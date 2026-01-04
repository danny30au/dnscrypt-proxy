package main

import (
"fmt"
"log/slog"
"path"
"strings"

"github.com/k-sone/critbitgo"
)

// PatternType defines the category of the match rule.
type PatternType int

const (
PatternTypeNone PatternType = iota
PatternTypePrefix
PatternTypeSuffix
PatternTypeSubstring
PatternTypePattern
PatternTypeExact
)

// PatternMatcher uses Generics [V any] to allow storing any data type
// without interface boxing overhead.
type PatternMatcher[V any] struct {
prefixes     *critbitgo.Trie
suffixes     *critbitgo.Trie
substrings   []string
patterns     []string
exact        map[string]V
indirectVals map[string]V
}

// NewPatternMatcher creates a typed matcher instance.
func NewPatternMatcher[V any]() *PatternMatcher[V] {
return &PatternMatcher[V]{
prefixes:     critbitgo.NewTrie(),
suffixes:     critbitgo.NewTrie(),
exact:        make(map[string]V),
indirectVals: make(map[string]V),
}
}

// isGlobCandidate checks for shell pattern characters.
func isGlobCandidate(str string) bool {
return strings.ContainsAny(str, "?[*")
}

// Add registers a pattern with a value.
func (pm *PatternMatcher[V]) Add(pattern string, val V, position int) error {
var (
leadingStar  = strings.HasPrefix(pattern, "*")
trailingStar = strings.HasSuffix(pattern, "*")
isExact      = strings.HasPrefix(pattern, "=")
patternType  = PatternTypeNone
cleanPattern string
)

// Determine pattern type and strip indicators using modern string helpers
switch {
case isGlobCandidate(pattern):
patternType = PatternTypePattern
// Use path.Match for consistency across OS (avoids Windows '' issues)
if _, err := path.Match(pattern, "example.com"); err != nil || len(pattern) < 2 {
return fmt.Errorf("syntax error in rule file at line %d: invalid glob", position)
}
cleanPattern = pattern

case leadingStar && trailingStar:
// Substring match (*contains*)
patternType = PatternTypeSubstring
if len(pattern) < 3 {
return fmt.Errorf("syntax error in rule file at line %d: pattern too short", position)
}
cleanPattern = pattern[1 : len(pattern)-1]

case trailingStar:
// Prefix match (starts*)
patternType = PatternTypePrefix
if len(pattern) < 2 {
return fmt.Errorf("syntax error in rule file at line %d: pattern too short", position)
}
cleanPattern = strings.TrimSuffix(pattern, "*")

case isExact:
// Exact match (=example.com)
patternType = PatternTypeExact
if len(pattern) < 2 {
return fmt.Errorf("syntax error in rule file at line %d: pattern too short", position)
}
cleanPattern = strings.TrimPrefix(pattern, "=")

default:
// Default: suffix match (*ends or .ends)
patternType = PatternTypeSuffix
cleanPattern = strings.TrimPrefix(pattern, "*")
cleanPattern = strings.TrimPrefix(cleanPattern, ".")
}

if len(cleanPattern) == 0 {
slog.Error("Syntax error: empty pattern after parsing", "line", position)
return fmt.Errorf("empty pattern at line %d", position)
}

cleanPattern = strings.ToLower(cleanPattern)

switch patternType {
case PatternTypeSubstring:
pm.substrings = append(pm.substrings, cleanPattern)
pm.indirectVals[cleanPattern] = val
case PatternTypePattern:
pm.patterns = append(pm.patterns, cleanPattern)
pm.indirectVals[cleanPattern] = val
case PatternTypePrefix:
// critbitgo only accepts interface{}, but we enforce type safety at the API boundary
pm.prefixes.Insert([]byte(cleanPattern), val)
case PatternTypeSuffix:
pm.suffixes.Insert([]byte(reverseString(cleanPattern)), val)
case PatternTypeExact:
pm.exact[cleanPattern] = val
default:
slog.Error("Unexpected rule pattern type", "type", patternType)
}
return nil
}

// Eval checks if a query name matches any registered pattern.
func (pm *PatternMatcher[V]) Eval(qName string) (reject bool, reason string, val V) {
if len(qName) < 2 {
var zero V
return false, "", zero
}

// 1. Exact Match (O(1) map lookup)
if xval, ok := pm.exact[qName]; ok {
return true, qName, xval
}

// 2. Suffix Match (Longest Prefix on reversed string)
revQname := reverseString(qName)
if match, xval, found := pm.suffixes.LongestPrefix([]byte(revQname)); found {
matchStr := string(match)
// Check boundaries: exact match or dot separator
if len(matchStr) == len(revQname) || revQname[len(matchStr)] == '.' {
return true, "*." + reverseString(matchStr), xval.(V)
}

// Handle specific sub-domain logic
// If the longest match isn't a perfect suffix, try stripping one label
if i := strings.LastIndex(revQname, "."); i > 0 {
pName := revQname[:i]
if match, _, found := pm.suffixes.LongestPrefix([]byte(pName)); found {
matchStr := string(match)
if len(matchStr) == len(pName) || pName[len(matchStr)] == '.' {
return true, "*." + reverseString(matchStr), xval.(V)
}
}
}
}

// 3. Prefix Match
if match, xval, found := pm.prefixes.LongestPrefix([]byte(qName)); found {
return true, string(match) + "*", xval.(V)
}

// 4. Substring Match (Linear Scan)
// Note: For large lists, Aho-Corasick would be preferred, but linear is fine for small rulesets.
for _, substring := range pm.substrings {
if strings.Contains(qName, substring) {
return true, "*" + substring + "*", pm.indirectVals[substring]
}
}

// 5. Glob Pattern Match
for _, pattern := range pm.patterns {
if found, _ := path.Match(pattern, qName); found {
return true, pattern, pm.indirectVals[pattern]
}
}

var zero V
return false, "", zero
}

// reverseString reverses a string by runes.
// Optimized for ASCII domains but handles UTF-8 correctly.
func reverseString(s string) string {
// Fast path for ASCII (common in domains)
isASCII := true
for i := 0; i < len(s); i++ {
if s[i] > 127 {
isASCII = false
break
}
}

if isASCII {
b := []byte(s)
for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
b[i], b[j] = b[j], b[i]
}
return string(b)
}

// UTF-8 path
r := []rune(s)
for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
r[i], r[j] = r[j], r[i]
}
return string(r)
}