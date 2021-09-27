package fqtest

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/internal/deepequal"
	"github.com/wader/fq/internal/shquote"
	"github.com/wader/fq/pkg/bitio"
	"github.com/wader/fq/pkg/interp"
)

var writeActual = os.Getenv("WRITE_ACTUAL") != ""

type testCaseReadline struct {
	expr           string
	env            []string
	input          string
	expectedPrompt string
	expectedStdout string
}

type testCaseRunInput struct {
	interp.FileReader
	isTerminal bool
	width      int
	height     int
}

func (i testCaseRunInput) Size() (int, int) { return i.width, i.height }
func (i testCaseRunInput) IsTerminal() bool { return i.isTerminal }

type testCaseRunOutput struct {
	io.Writer
	isTerminal bool
	width      int
	height     int
}

func (o testCaseRunOutput) Size() (int, int) { return o.width, o.height }
func (o testCaseRunOutput) IsTerminal() bool { return o.isTerminal }

type testCaseRun struct {
	lineNr           int
	testCase         *testCase
	command          string
	env              []string
	args             []string
	stdin            string
	expectedStdout   string
	expectedStderr   string
	expectedExitCode int
	actualStdoutBuf  *bytes.Buffer
	actualStderrBuf  *bytes.Buffer
	actualExitCode   int
	readlines        []testCaseReadline
	readlinesPos     int
	readlineEnv      []string
}

func (tcr *testCaseRun) Line() int { return tcr.lineNr }

func (tcr *testCaseRun) getEnv(name string) string {
	for _, kv := range tcr.Environ() {
		if strings.HasPrefix(kv, name+"=") {
			return kv[len(name)+1:]
		}
	}
	return ""
}

func (tcr *testCaseRun) getEnvInt(name string) int {
	n, _ := strconv.Atoi(tcr.getEnv(name))
	return n
}

func (tcr *testCaseRun) Stdin() interp.Input {
	return testCaseRunInput{
		FileReader: interp.FileReader{
			R: bytes.NewBufferString(tcr.stdin),
		},
		isTerminal: tcr.stdin == "",
		width:      tcr.getEnvInt("_STDIN_WIDTH"),
		height:     tcr.getEnvInt("_STDIN_HEIGHT"),
	}
}

func (tcr *testCaseRun) Stdout() interp.Output {
	return testCaseRunOutput{
		Writer:     tcr.actualStdoutBuf,
		isTerminal: tcr.getEnvInt("_STDOUT_ISTERMINAL") != 0,
		width:      tcr.getEnvInt("_STDOUT_WIDTH"),
		height:     tcr.getEnvInt("_STDOUT_HEIGHT"),
	}
}

func (tcr *testCaseRun) Stderr() interp.Output {
	return testCaseRunOutput{Writer: tcr.actualStderrBuf}
}

func (tcr *testCaseRun) Interrupt() chan struct{} { return nil }

func (tcr *testCaseRun) Environ() []string {
	env := []string{
		"_STDIN_WIDTH=135",
		"_STDIN_HEIGHT=25",
		"_STDOUT_WIDTH=135",
		"_STDOUT_HEIGHT=25",
		"_STDOUT_ISTERMINAL=1",
		"NO_COLOR=1",
		"NO_DECODE_PROGRESS=1",
	}
	env = append(env, tcr.env...)
	env = append(env, tcr.readlineEnv...)

	envm := make(map[string]string)
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			envm[kv[:i]] = kv[i+1:]
		}
	}

	env = []string{}
	for k, v := range envm {
		env = append(env, k+"="+v)
	}

	return env
}

func (tcr *testCaseRun) Args() []string { return tcr.args }

func (tcr *testCaseRun) ConfigDir() (string, error) { return "/config", nil }

func (tcr *testCaseRun) FS() fs.FS { return tcr.testCase }

func (tcr *testCaseRun) Readline(prompt string, complete func(line string, pos int) (newLine []string, shared int)) (string, error) {
	tcr.actualStdoutBuf.WriteString(prompt)
	if tcr.readlinesPos >= len(tcr.readlines) {
		return "", io.EOF
	}

	expr := tcr.readlines[tcr.readlinesPos].expr
	lineRaw := tcr.readlines[tcr.readlinesPos].input
	line := Unescape(lineRaw)
	tcr.readlineEnv = tcr.readlines[tcr.readlinesPos].env
	tcr.readlinesPos++

	if strings.HasSuffix(line, "\t") {
		tcr.actualStdoutBuf.WriteString(lineRaw + "\n")

		l := len(line) - 1
		newLine, shared := complete(line[0:l], l)
		// TODO: shared
		_ = shared
		for _, nl := range newLine {
			tcr.actualStdoutBuf.WriteString(nl + "\n")
		}

		return "", nil
	}

	tcr.actualStdoutBuf.WriteString(expr + "\n")

	if line == "^D" {
		return "", io.EOF
	}

	return line, nil
}
func (tcr *testCaseRun) History() ([]string, error) { return nil, nil }

func (tcr *testCaseRun) ToExpectedStdout() string {
	sb := &strings.Builder{}

	if len(tcr.readlines) == 0 {
		fmt.Fprint(sb, tcr.expectedStdout)
	} else {
		for _, rl := range tcr.readlines {
			fmt.Fprintf(sb, "%s%s\n", rl.expectedPrompt, rl.expr)
			if rl.expectedStdout != "" {
				fmt.Fprint(sb, rl.expectedStdout)
			}
		}
	}

	return sb.String()
}

func (tcr *testCaseRun) ToExpectedStderr() string {
	return tcr.expectedStderr
}

type part interface {
	Line() int
}

type testCaseFile struct {
	lineNr int
	name   string
	data   []byte
}

func (tcf *testCaseFile) Line() int { return tcf.lineNr }

type testCaseComment struct {
	lineNr  int
	comment string
}

func (tcr *testCaseComment) Line() int { return tcr.lineNr }

type testCase struct {
	path      string
	parts     []part
	wasTested bool
}

func (tc *testCase) ToActual() string {
	var partsLineSorted []part
	partsLineSorted = append(partsLineSorted, tc.parts...)
	sort.Slice(partsLineSorted, func(i, j int) bool {
		return partsLineSorted[i].Line() < partsLineSorted[j].Line()
	})

	sb := &strings.Builder{}
	for _, p := range partsLineSorted {
		switch p := p.(type) {
		case *testCaseComment:
			fmt.Fprintf(sb, "#%s\n", p.comment)
		case *testCaseRun:
			fmt.Fprintf(sb, "$%s\n", p.command)
			s := p.actualStdoutBuf.String()
			if s != "" {
				fmt.Fprint(sb, s)
				if !strings.HasSuffix(s, "\n") {
					fmt.Fprint(sb, "\\\n")
				}
			}
			if p.actualExitCode != 0 {
				fmt.Fprintf(sb, "exitcode: %d\n", p.actualExitCode)
			}
			if p.stdin != "" {
				fmt.Fprint(sb, "stdin:\n")
				fmt.Fprint(sb, p.stdin)
			}
			if p.actualStderrBuf.Len() > 0 {
				fmt.Fprint(sb, "stderr:\n")
				fmt.Fprint(sb, p.actualStderrBuf.String())
			}
		case *testCaseFile:
			fmt.Fprintf(sb, "%s:\n", p.name)
			sb.Write(p.data)
		default:
			panic("unreachable")
		}
	}

	return sb.String()
}

func (tc *testCase) Open(name string) (fs.File, error) {
	for _, p := range tc.parts {
		f, ok := p.(*testCaseFile)
		if ok && f.name == name {
			// if no data assume it's a real file
			if len(f.data) == 0 {
				return os.Open(filepath.Join(filepath.Dir(tc.path), name))
			}
			return interp.FileReader{
				R: io.NewSectionReader(bytes.NewReader(f.data), 0, int64(len(f.data))),
				FileInfo: interp.FixedFileInfo{
					FName: filepath.Base(name),
					FSize: int64(len(f.data)),
				},
			}, nil
		}
	}
	return nil, fmt.Errorf("%s: file not found", name)
}

type Section struct {
	LineNr int
	Name   string
	Value  string
}

var unescapeRe = regexp.MustCompile(`\\(?:t|b|n|r|0(?:b[01]{8}|x[0-f]{2}))`)

func Unescape(s string) string {
	return unescapeRe.ReplaceAllStringFunc(s, func(r string) string {
		switch {
		case r == `\n`:
			return "\n"
		case r == `\r`:
			return "\r"
		case r == `\t`:
			return "\t"
		case r == `\b`:
			return "\b"
		case strings.HasPrefix(r, `\0b`):
			b, _ := bitio.BytesFromBitString(r[3:])
			return string(b)
		case strings.HasPrefix(r, `\0x`):
			b, _ := hex.DecodeString(r[3:])
			return string(b)
		default:
			return r
		}
	})
}

func SectionParser(re *regexp.Regexp, s string) []Section {
	var sections []Section

	firstMatch := func(ss []string, fn func(s string) bool) string {
		for _, s := range ss {
			if fn(s) {
				return s
			}
		}
		return ""
	}

	const lineDelim = "\n"
	var cs *Section
	lineNr := 0
	lines := strings.Split(s, lineDelim)
	// skip last if empty because of how split works "a\n" -> ["a", ""]
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for _, l := range lines {
		lineNr++

		sm := re.FindStringSubmatch(l)
		if cs == nil || len(sm) > 0 {
			sections = append(sections, Section{})
			cs = &sections[len(sections)-1]

			cs.LineNr = lineNr
			cs.Name = firstMatch(sm, func(s string) bool { return len(s) != 0 })
		} else {
			// TODO: use builder somehow if performance is needed
			cs.Value += l + lineDelim
		}
	}

	return sections
}

var kvRe = regexp.MustCompile(`^[A-Z_]+=`)

func parseCommand(s string) (env []string, args []string) {
	parts := shquote.Split(s)
	for i, p := range parts {
		if kvRe.MatchString(p) {
			env = append(env, p)
			continue
		}
		args = parts[i:]
		break
	}

	return env, args
}

func parseInput(s string) (env []string, input string) {
	tokens := shquote.Parse(s)
	l := 0
	for _, t := range tokens {
		if t.Separator {
			continue
		}
		if kvRe.MatchString(t.Str) {
			env = append(env, t.Str)
			l = t.End
			continue
		}
		break
	}
	return env, s[l:]
}

func parseTestCases(s string) *testCase {
	te := &testCase{}
	te.parts = []part{}
	var currentTestRun *testCaseRun
	const promptEnd = ">"
	replDepth := 0

	// TODO: better section splitter, too much heuristics now
	for _, section := range SectionParser(regexp.MustCompile(
		`^\$ .*$|^stdin:$|^stderr:$|^exitcode:.*$|^#.*$|^/.*:|^[^<:|]+>.*$`,
	), s) {
		n, v := section.Name, section.Value

		switch {
		case strings.HasPrefix(n, "#"):
			comment := n[1:]
			te.parts = append(te.parts, &testCaseComment{lineNr: section.LineNr, comment: comment})
		case strings.HasPrefix(n, "/"):
			name := n[0 : len(n)-1]
			te.parts = append(te.parts, &testCaseFile{lineNr: section.LineNr, name: name, data: []byte(v)})
		case strings.HasPrefix(n, "$"):
			replDepth++

			if currentTestRun != nil {
				te.parts = append(te.parts, currentTestRun)
			}

			// escaped newline
			v = strings.TrimSuffix(v, "\\\n")
			command := strings.TrimPrefix(n, "$")
			env, args := parseCommand(command)

			currentTestRun = &testCaseRun{
				lineNr:          section.LineNr,
				testCase:        te,
				command:         command,
				env:             env,
				args:            args,
				expectedStdout:  v,
				actualStdoutBuf: &bytes.Buffer{},
				actualStderrBuf: &bytes.Buffer{},
			}
		case strings.HasPrefix(n, "exitcode:"):
			currentTestRun.expectedExitCode, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(n, "exitcode:")))
		case strings.HasPrefix(n, "stdin"):
			currentTestRun.stdin = v
		case strings.HasPrefix(n, "stderr"):
			currentTestRun.expectedStderr = v
		case strings.Contains(n, promptEnd): // TODO: better
			i := strings.LastIndex(n, promptEnd)

			prompt := n[0:i] + promptEnd + " "
			expr := strings.TrimSpace(n[i+1:])
			env, input := parseInput(expr)

			currentTestRun.readlines = append(currentTestRun.readlines, testCaseReadline{
				expr:           expr,
				env:            env,
				input:          input,
				expectedPrompt: prompt,
				expectedStdout: v,
			})

			// TODO: hack
			if strings.Contains(expr, "| repl") {
				replDepth++
			}
			if expr == "^D" {
				replDepth--
			}

		default:
			panic(fmt.Sprintf("%d: unexpected section %q %q", section.LineNr, n, v))
		}
	}

	if currentTestRun != nil {
		te.parts = append(te.parts, currentTestRun)
	}

	return te
}

func testDecodedTestCaseRun(t *testing.T, registry *registry.Registry, tcr *testCaseRun) {
	q, err := interp.New(tcr, registry)
	if err != nil {
		t.Fatal(err)
	}

	err = q.Main(context.Background(), tcr.Stdout(), "dev")
	if err != nil {
		if ex, ok := err.(interp.Exiter); ok { //nolint:errorlint
			tcr.actualExitCode = ex.ExitCode()
		}
	}

	if writeActual {
		return
	}

	deepequal.Error(t, "exitcode", tcr.expectedExitCode, tcr.actualExitCode)
	deepequal.Error(t, "stdout", tcr.ToExpectedStdout(), tcr.actualStdoutBuf.String())
	deepequal.Error(t, "stderr", tcr.ToExpectedStderr(), tcr.actualStderrBuf.String())
}

func TestPath(t *testing.T, registry *registry.Registry) {
	tcs := []*testCase{}

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) != ".fqtest" {
			return nil
		}

		t.Run(path, func(t *testing.T) {
			b, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tc := parseTestCases(string(b))

			tcs = append(tcs, tc)
			tc.path = path

			for _, p := range tc.parts {
				tcr, ok := p.(*testCaseRun)
				if !ok {
					continue
				}

				t.Run(strconv.Itoa(tcr.lineNr)+":"+tcr.command, func(t *testing.T) {
					testDecodedTestCaseRun(t, registry, tcr)
					tc.wasTested = true
				})
			}
		})

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if writeActual {
		for _, tc := range tcs {
			if !tc.wasTested {
				continue
			}
			if err := ioutil.WriteFile(tc.path, []byte(tc.ToActual()), 0644); err != nil { //nolint:gosec
				t.Error(err)
			}
		}
	}
}
