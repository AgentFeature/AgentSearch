package report

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

type OutputError struct{ Err error }

func (e *OutputError) Error() string {
	if errors.Is(e.Err, ErrLimit) {
		return "report output failed: resource limit exceeded"
	}
	var failure *renderFailure
	if errors.As(e.Err, &failure) {
		return "report output failed: " + failure.Error()
	}
	return "report output failed (invalid input or destination; inspect configuration)"
}

type renderFailure struct {
	format string
	err    error
}

func (e *renderFailure) Error() string { return fmt.Sprintf("%s rendering: %v", e.format, e.err) }
func (e *renderFailure) Unwrap() error { return e.err }
func (e *OutputError) Unwrap() error   { return e.Err }

// SafeBase preserves ordinary historical filenames. Unsafe, reserved or long
// labels get a bounded slug plus hash, preventing traversal and sanitization collisions.
func SafeBase(target string) string {
	target = security.Redact(target)
	safe := target != "" && len(target) <= 120 && !strings.HasPrefix(target, ".") && !strings.HasSuffix(target, ".") && !strings.HasSuffix(target, " ")
	upper := strings.ToUpper(strings.Split(target, ".")[0])
	if upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL" || len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9' {
		safe = false
	}
	for _, c := range target {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && !strings.ContainsRune("-_.@+[]", c) {
			safe = false
		}
	}
	if safe {
		return target
	}
	var slug strings.Builder
	for _, c := range target {
		if slug.Len() > 60 {
			break
		}
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			slug.WriteRune(c)
		} else {
			slug.WriteByte('_')
		}
	}
	return "target-" + slug.String() + "-" + digest([]byte(target))[:16]
}
func writeFile(dir, name string, raw []byte) (path string, err error) {
	if len(raw) > MaxOutputBytes {
		return "", ErrLimit
	}
	if name == "" || len(name) > 160 || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return "", errors.New("invalid report filename")
	}
	if len(dir) > 4096 {
		return "", errors.New("invalid output directory")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if len(strings.FieldsFunc(dir, func(c rune) bool { return c == '/' || c == '\\' })) > 32 {
		return "", errors.New("output path depth exceeds limit")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("output directory must not be a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if info, e := root.Lstat(name); e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return "", errors.New("refusing nonregular report destination")
	} else if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	// Open relative to the held directory, including during concurrent renames.
	temporary := ".report-" + rand.Text() + ".tmp"
	temp, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}

	defer root.Remove(temporary)
	if _, err = temp.Write(raw); err == nil {
		err = temp.Sync()
	}
	err = errors.Join(err, temp.Close())
	if err != nil {
		return "", err
	}
	if err = publish(root, temporary, name); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}
func WriteReport(dir, base, format string, r *Report) (string, error) {
	if !ValidFormat(format) {
		return "", errors.New("unsupported output format")
	}
	raw, err := Render(r, format)
	if err != nil {
		return "", err
	}
	return writeFile(dir, SafeBase(base)+"."+format, raw)
}

// WriteOutputs is the single one-shot output path. The -rf bridge preserves the
// documented historical cwd/output location; -of always respects the supplied dir.
func WriteOutputs(dir string, formats, reportFormats []string, r *Report) error {
	if err := r.validate(); err != nil {
		return &OutputError{err}
	}
	for _, f := range formats {
		if !ValidFormat(f) {
			return &OutputError{errors.New("unsupported output format")}
		}
	}
	for _, f := range reportFormats {
		if f != "cli" && !ValidFormat(f) {
			return &OutputError{errors.New("unsupported report format")}
		}
	}
	var failures []error
	seen := map[string]bool{}
	put := func(directory, name, format string, legacy bool) {
		key := directory + "\x00" + name + "\x00" + format
		if seen[key] {
			return
		}
		seen[key] = true
		var raw []byte
		var err error
		if legacy {
			raw, err = RenderLegacy(r, format)
		} else {
			raw, err = Render(r, format)
		}
		if err == nil {
			_, err = writeFile(directory, name+"."+format, raw)
		} else {
			err = &renderFailure{format, err}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s output: %w", format, err))
		}
	}
	base := SafeBase(r.Target())
	for _, f := range formats {
		if f == "json" || f == "csv" {
			put(dir, base, f, true)
			put(dir, base+"_report", f, false)
		} else {
			put(dir, base, f, false)
		}
	}
	for _, f := range reportFormats {
		if f == "cli" {
			put("output", base+"_report", "txt", false)
			raw, err := Render(r, "txt")
			if err == nil {
				_, err = os.Stdout.Write(raw)
			}
			if err != nil {
				failures = append(failures, err)
			}
		} else {
			put("output", base+"_report", f, false)
		}
	}
	if len(reportFormats) > 0 {
		summary := BuildSummary(r.Target(), r.results(), time.Duration(r.data.DurationNS))
		raw := summaryJSON(summary)
		if _, err := writeFile(dir, base+"_summary.json", raw); err != nil {
			failures = append(failures, err)
		}
	}
	if err := errors.Join(failures...); err != nil {
		return &OutputError{err}
	}
	return nil
}
func legacyReport(target string, results []models.Result, duration time.Duration) (*Report, error) {
	kind := models.TargetUsername
	if len(results) > 0 && results[0].TargetType != "" {
		kind = results[0].TargetType
	} else {
		t, _ := models.LegacyTarget(target)
		kind = t.Type()
	}
	for _, row := range results {
		if row.TargetType.Sensitive() {
			kind = row.TargetType
			break
		}
	}
	return New(kind, target, results, Options{CreatedAt: time.Now(), Duration: duration})
}
func generateLegacy(format, target string, results []models.Result, duration time.Duration) (string, error) {
	r, err := legacyReport(target, results, duration)
	if err != nil {
		return "", err
	}
	raw, err := Render(r, format)
	if err != nil {
		return "", err
	}
	if format == "txt" {
		if _, err = os.Stdout.Write(raw); err != nil {
			return "", err
		}
	}
	return writeFile("output", SafeBase(r.Target())+"_report."+format, raw)
}

// PrepareDirectory detects invalid destinations before an investigation starts.
func PrepareDirectory(dir string) error {
	if dir == "" || len(dir) > 4096 {
		return errors.New("invalid output directory")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if len(strings.FieldsFunc(absolute, func(c rune) bool { return c == '/' || c == '\\' })) > 32 {
		return errors.New("output path depth exceeds limit")
	}
	if err = os.MkdirAll(absolute, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid output directory")
	}
	return nil
}
