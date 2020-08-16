//go:generate go install github.com/golangci/golangci-lint/cmd/golangci-lint

// Package nfpm provides ways to package programs in some linux packaging
// formats.
package nfpm

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/Masterminds/semver/v3"
	"github.com/goreleaser/chglog"
	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

// nolint: gochecknoglobals
var (
	packagers = map[string]Packager{}
	lock      sync.Mutex
)

// Register a new packager for the given format.
func Register(format string, p Packager) {
	lock.Lock()
	packagers[format] = p
	lock.Unlock()
}

// ErrNoPackager happens when no packager is registered for the given format.
type ErrNoPackager struct {
	format string
}

func (e ErrNoPackager) Error() string {
	return fmt.Sprintf("no packager registered for the format %s", e.format)
}

// Get a packager for the given format.
func Get(format string) (Packager, error) {
	p, ok := packagers[format]
	if !ok {
		return nil, ErrNoPackager{format}
	}
	return p, nil
}

// Parse decodes YAML data from an io.Reader into a configuration struct.
func Parse(in io.Reader) (config Config, err error) {
	dec := yaml.NewDecoder(in)
	dec.SetStrict(true)
	if err = dec.Decode(&config); err != nil {
		return
	}

	config.Info.Release = os.ExpandEnv(config.Info.Release)
	config.Info.Version = os.ExpandEnv(config.Info.Version)

	config.Info.PrivateKeyBase64 = os.ExpandEnv(config.Info.PrivateKeyBase64)
	config.Info.PrivateKeyFile = os.ExpandEnv(config.Info.PrivateKeyFile)

	return config, config.Validate()
}

// ParseFile decodes YAML data from a file path into a configuration struct.
func ParseFile(path string) (config Config, err error) {
	var file *os.File
	file, err = os.Open(path) //nolint:gosec
	if err != nil {
		return
	}
	defer file.Close() // nolint: errcheck,gosec
	return Parse(file)
}

// Packager represents any packager implementation.
type Packager interface {
	Package(info *Info, w io.Writer) error
	ConventionalFileName(info *Info) string
}

// Config contains the top level configuration for packages.
type Config struct {
	Info      `yaml:",inline"`
	Overrides map[string]Overridables `yaml:"overrides,omitempty"`
}

// Get returns the Info struct for the given packager format. Overrides
// for the given format are merged into the final struct.
func (c *Config) Get(format string) (info *Info, err error) {
	info = &Info{}
	// make a deep copy of info
	if err = mergo.Merge(info, c.Info); err != nil {
		return nil, errors.Wrap(err, "failed to merge config into info")
	}
	override, ok := c.Overrides[format]
	if !ok {
		// no overrides
		return info, nil
	}
	if err = mergo.Merge(&info.Overridables, override, mergo.WithOverride); err != nil {
		return nil, errors.Wrap(err, "failed to merge overrides into info")
	}
	return info, nil
}

// Validate ensures that the config is well typed.
func (c *Config) Validate() error {
	for format := range c.Overrides {
		if _, err := Get(format); err != nil {
			return err
		}
	}
	return nil
}

// Info contains information about a single package.
type Info struct {
	Overridables `yaml:",inline"`
	Name         string `yaml:"name,omitempty"`
	Arch         string `yaml:"arch,omitempty"`
	Platform     string `yaml:"platform,omitempty"`
	Epoch        string `yaml:"epoch,omitempty"`
	Version      string `yaml:"version,omitempty"`
	Release      string `yaml:"release,omitempty"`
	Prerelease   string `yaml:"prerelease,omitempty"`
	Section      string `yaml:"section,omitempty"`
	Priority     string `yaml:"priority,omitempty"`
	Maintainer   string `yaml:"maintainer,omitempty"`
	Description  string `yaml:"description,omitempty"`
	Vendor       string `yaml:"vendor,omitempty"`
	Homepage     string `yaml:"homepage,omitempty"`
	License      string `yaml:"license,omitempty"`
	Bindir       string `yaml:"bindir,omitempty"` // Deprecated: this does nothing. TODO: remove.
	Changelog    string `yaml:"changelog,omitempty"`
	Target       string `yaml:"-"`
}

// Overridables contain the field which are overridable in a package.
type Overridables struct {
	Replaces     []string          `yaml:"replaces,omitempty"`
	Provides     []string          `yaml:"provides,omitempty"`
	Depends      []string          `yaml:"depends,omitempty"`
	Recommends   []string          `yaml:"recommends,omitempty"`
	Suggests     []string          `yaml:"suggests,omitempty"`
	Conflicts    []string          `yaml:"conflicts,omitempty"`
	Files        map[string]string `yaml:"files,omitempty"`
	ConfigFiles  map[string]string `yaml:"config_files,omitempty"`
	Symlinks     map[string]string `yaml:"symlinks,omitempty"`
	EmptyFolders []string          `yaml:"empty_folders,omitempty"`
	Scripts      Scripts           `yaml:"scripts,omitempty"`
	RPM          RPM               `yaml:"rpm,omitempty"`
	Deb          Deb               `yaml:"deb,omitempty"`
}

// RPM is custom configs that are only available on RPM packages.
type RPM struct {
	Group       string `yaml:"group,omitempty"`
	Compression string `yaml:"compression,omitempty"`
	// https://www.cl.cam.ac.uk/~jw35/docs/rpm_config.html
	ConfigNoReplaceFiles map[string]string `yaml:"config_noreplace_files,omitempty"`
}

// Deb is custom configs that are only available on deb packages.
type Deb struct {
	Scripts         DebScripts  `yaml:"scripts,omitempty"`
	Triggers        DebTriggers `yaml:"triggers,omitempty"`
	VersionMetadata string      `yaml:"metadata,omitempty"`
}

// DebTriggers contains triggers only available for deb packages.
// https://wiki.debian.org/DpkgTriggers
// https://man7.org/linux/man-pages/man5/deb-triggers.5.html
type DebTriggers struct {
	Interest        []string `yaml:"interest,omitempty"`
	InterestAwait   []string `yaml:"interest_await,omitempty"`
	InterestNoAwait []string `yaml:"interest_noawait,omitempty"`
	Activate        []string `yaml:"activate,omitempty"`
	ActivateAwait   []string `yaml:"activate_await,omitempty"`
	ActivateNoAwait []string `yaml:"activate_noawait,omitempty"`
}

// DebScripts is scripts only available on deb packages.
type DebScripts struct {
	Rules string `yaml:"rules,omitempty"`
}

// Scripts contains information about maintainer scripts for packages.
type Scripts struct {
	PreInstall  string `yaml:"preinstall,omitempty"`
	PostInstall string `yaml:"postinstall,omitempty"`
	PreRemove   string `yaml:"preremove,omitempty"`
	PostRemove  string `yaml:"postremove,omitempty"`
}

// ErrFieldEmpty happens when some required field is empty.
type ErrFieldEmpty struct {
	field string
}

func (e ErrFieldEmpty) Error() string {
	return fmt.Sprintf("package %s must be provided", e.field)
}

// Validate the given Info and returns an error if it is invalid.
func Validate(info *Info) error {
	if info.Name == "" {
		return ErrFieldEmpty{"name"}
	}
	if info.Arch == "" {
		return ErrFieldEmpty{"arch"}
	}
	if info.Version == "" {
		return ErrFieldEmpty{"version"}
	}
	return nil
}

// WithDefaults set some sane defaults into the given Info.
func WithDefaults(info *Info) *Info {
	if info.Platform == "" {
		info.Platform = "linux"
	}
	if info.Description == "" {
		info.Description = "no description given"
	}

	// parse the version as a semver so we can properly split the parts
	// and support proper ordering for both rpm and deb
	if v, err := semver.NewVersion(info.Version); err == nil {
		info.Version = fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Patch())
		if info.Release == "" && isInt(v.Prerelease()) {
			info.Release = v.Prerelease()
		}
		if info.Prerelease == "" && !isInt(v.Prerelease()) {
			info.Prerelease = v.Prerelease()
		}
	}

	return info
}

// GetChangeLog parses the provided changelog file.
func (info *Info) GetChangeLog() (log *chglog.PackageChangeLog, err error) {
	// if the file does not exist chglog.Parse will just silently
	// create an empty changelog but we should notify the user instead
	if _, err = os.Stat(info.Changelog); os.IsNotExist(err) {
		return nil, err
	}

	entries, err := chglog.Parse(info.Changelog)
	if err != nil {
		return nil, err
	}

	return &chglog.PackageChangeLog{
		Name:    info.Name,
		Entries: entries,
	}, nil
}

func isInt(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
