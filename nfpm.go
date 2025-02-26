// Package nfpm provides ways to package programs in some linux packaging
// formats.
package nfpm

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dario.cat/mergo"
	"github.com/AlekSi/pointer"
	"github.com/Masterminds/semver/v3"
	"github.com/goreleaser/chglog"
	"github.com/goreleaser/nfpm/v2/files"
	"github.com/goreleaser/nfpm/v2/internal/modtime"
	"gopkg.in/yaml.v3"
)

// nolint: gochecknoglobals
var (
	packagers = map[string]Packager{}
	lock      sync.Mutex
)

// RegisterPackager a new packager for the given format.
func RegisterPackager(format string, p Packager) {
	lock.Lock()
	defer lock.Unlock()
	packagers[format] = p
}

// ClearPackagers clear all registered packagers, used for testing.
func ClearPackagers() {
	lock.Lock()
	defer lock.Unlock()
	packagers = map[string]Packager{}
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

// Enumerate lists the available packagers
func Enumerate() []string {
	lock.Lock()
	defer lock.Unlock()

	list := make([]string, 0, len(packagers))
	for key := range packagers {
		if key != "" {
			list = append(list, key)
		}
	}

	sort.Strings(list)
	return list
}

// Parse decodes YAML data from an io.Reader into a configuration struct.
func Parse(in io.Reader) (config Config, err error) {
	return ParseWithEnvMapping(in, os.Getenv)
}

// ParseWithEnvMapping decodes YAML data from an io.Reader into a configuration struct.
func ParseWithEnvMapping(in io.Reader, mapping func(string) string) (config Config, err error) {
	dec := yaml.NewDecoder(in)
	dec.KnownFields(true)
	if err = dec.Decode(&config); err != nil {
		return
	}
	config.envMappingFunc = mapping
	if config.envMappingFunc == nil {
		config.envMappingFunc = func(s string) string { return s }
	}

	config.expandEnvVars()
	WithDefaults(&config.Info)
	return config, nil
}

// ParseFile decodes YAML data from a file path into a configuration struct.
func ParseFile(path string) (config Config, err error) {
	if path == "-" {
		return ParseWithEnvMapping(os.Stdin, os.Getenv)
	}
	return ParseFileWithEnvMapping(path, os.Getenv)
}

// ParseFileWithEnvMapping decodes YAML data from a file path into a configuration struct.
func ParseFileWithEnvMapping(path string, mapping func(string) string) (config Config, err error) {
	var file *os.File
	file, err = os.Open(path) //nolint:gosec
	if err != nil {
		return
	}
	defer file.Close() // nolint: errcheck,gosec
	return ParseWithEnvMapping(file, mapping)
}

// Packager represents any packager implementation.
type Packager interface {
	Package(info *Info, w io.Writer) error
	ConventionalFileName(info *Info) string
}

type PackagerWithExtension interface {
	Packager
	ConventionalExtension() string
}

type PackagerWithMetadata interface {
	PackageMetadata(info *MetaInfo, w io.Writer) error
	ConventionalMetadataFileName(info *Info) string
}

// Config contains the top level configuration for packages.
type Config struct {
	Info           `yaml:",inline" json:",inline"`
	Overrides      map[string]*Overridables `yaml:"overrides,omitempty" json:"overrides,omitempty" jsonschema:"title=overrides,description=override some fields when packaging with a specific packager,enum=apk,enum=deb,enum=rpm"`
	envMappingFunc func(string) string
}

// Get returns the Info struct for the given packager format. Overrides
// for the given format are merged into the final struct.
func (c *Config) Get(format string) (info *Info, err error) {
	info = &Info{}
	// make a deep copy of info
	if err = mergo.Merge(info, c.Info, mergo.WithOverride); err != nil {
		return nil, fmt.Errorf("failed to merge config into info: %w", err)
	}
	override, ok := c.Overrides[format]
	if !ok {
		// no overrides
		return info, nil
	}
	if err = mergo.Merge(&info.Overridables, override, mergo.WithOverride); err != nil {
		return nil, fmt.Errorf("failed to merge overrides into info: %w", err)
	}

	var contents []*files.Content
	for _, f := range info.Contents {
		if f.Packager == format || f.Packager == "" {
			contents = append(contents, f)
		}
	}
	info.Contents = contents
	return info, nil
}

// Validate ensures that the config is well typed.
func (c *Config) Validate() error {
	if err := Validate(&c.Info); err != nil {
		return err
	}
	for format := range c.Overrides {
		if _, err := Get(format); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) expandEnvVarsStringSlice(items []string) []string {
	for i, dep := range items {
		val := strings.TrimSpace(os.Expand(dep, c.envMappingFunc))
		items[i] = val
	}
	for i := 0; i < len(items); i++ {
		if items[i] == "" {
			items = append(items[:i], items[i+1:]...)
			i-- // Since we just deleted items[i], we must redo that index
		}
	}

	return items
}

func (c *Config) expandEnvVarsContents(contents files.Contents) files.Contents {
	for i := range contents {
		f := contents[i]
		if !f.Expand {
			continue
		}
		f.Destination = strings.TrimSpace(os.Expand(f.Destination, c.envMappingFunc))
		f.Source = strings.TrimSpace(os.Expand(f.Source, c.envMappingFunc))
	}
	return contents
}

func (c *Config) expandEnvVars() {
	// Version related fields
	c.Info.Release = os.Expand(c.Info.Release, c.envMappingFunc)
	c.Info.Version = os.Expand(c.Info.Version, c.envMappingFunc)
	c.Info.Prerelease = os.Expand(c.Info.Prerelease, c.envMappingFunc)
	c.Info.Platform = os.Expand(c.Info.Platform, c.envMappingFunc)
	c.Info.Arch = os.Expand(c.Info.Arch, c.envMappingFunc)
	for or := range c.Overrides {
		c.Overrides[or].Conflicts = c.expandEnvVarsStringSlice(c.Overrides[or].Conflicts)
		c.Overrides[or].Depends = c.expandEnvVarsStringSlice(c.Overrides[or].Depends)
		c.Overrides[or].Replaces = c.expandEnvVarsStringSlice(c.Overrides[or].Replaces)
		c.Overrides[or].Recommends = c.expandEnvVarsStringSlice(c.Overrides[or].Recommends)
		c.Overrides[or].Provides = c.expandEnvVarsStringSlice(c.Overrides[or].Provides)
		c.Overrides[or].Suggests = c.expandEnvVarsStringSlice(c.Overrides[or].Suggests)
		c.Overrides[or].Contents = c.expandEnvVarsContents(c.Overrides[or].Contents)
	}
	c.Info.Conflicts = c.expandEnvVarsStringSlice(c.Info.Conflicts)
	c.Info.Depends = c.expandEnvVarsStringSlice(c.Info.Depends)
	c.Info.Replaces = c.expandEnvVarsStringSlice(c.Info.Replaces)
	c.Info.Recommends = c.expandEnvVarsStringSlice(c.Info.Recommends)
	c.Info.Provides = c.expandEnvVarsStringSlice(c.Info.Provides)
	c.Info.Suggests = c.expandEnvVarsStringSlice(c.Info.Suggests)
	c.Info.Contents = c.expandEnvVarsContents(c.Info.Contents)

	// Basic metadata fields
	c.Info.Name = os.Expand(c.Info.Name, c.envMappingFunc)
	c.Info.Homepage = os.Expand(c.Info.Homepage, c.envMappingFunc)
	c.Info.Maintainer = os.Expand(c.Info.Maintainer, c.envMappingFunc)
	c.Info.Vendor = os.Expand(c.Info.Vendor, c.envMappingFunc)
	c.Info.Description = os.Expand(c.Info.Description, c.envMappingFunc)

	// Package signing related fields
	c.Info.Deb.Signature.KeyFile = os.Expand(c.Deb.Signature.KeyFile, c.envMappingFunc)
	c.Info.RPM.Signature.KeyFile = os.Expand(c.RPM.Signature.KeyFile, c.envMappingFunc)
	c.Info.APK.Signature.KeyFile = os.Expand(c.APK.Signature.KeyFile, c.envMappingFunc)
	c.Info.Deb.Signature.KeyID = pointer.ToString(os.Expand(pointer.GetString(c.Deb.Signature.KeyID), c.envMappingFunc))
	c.Info.RPM.Signature.KeyID = pointer.ToString(os.Expand(pointer.GetString(c.RPM.Signature.KeyID), c.envMappingFunc))
	c.Info.APK.Signature.KeyID = pointer.ToString(os.Expand(pointer.GetString(c.APK.Signature.KeyID), c.envMappingFunc))

	// Package signing passphrase
	generalPassphrase := os.Expand("$NFPM_PASSPHRASE", c.envMappingFunc)
	c.Info.Deb.Signature.KeyPassphrase = generalPassphrase
	c.Info.RPM.Signature.KeyPassphrase = generalPassphrase
	c.Info.APK.Signature.KeyPassphrase = generalPassphrase

	debPassphrase := os.Expand("$NFPM_DEB_PASSPHRASE", c.envMappingFunc)
	if debPassphrase != "" {
		c.Info.Deb.Signature.KeyPassphrase = debPassphrase
	}

	rpmPassphrase := os.Expand("$NFPM_RPM_PASSPHRASE", c.envMappingFunc)
	if rpmPassphrase != "" {
		c.Info.RPM.Signature.KeyPassphrase = rpmPassphrase
	}

	apkPassphrase := os.Expand("$NFPM_APK_PASSPHRASE", c.envMappingFunc)
	if apkPassphrase != "" {
		c.Info.APK.Signature.KeyPassphrase = apkPassphrase
	}

	// RPM specific
	c.Info.RPM.Packager = os.Expand(c.RPM.Packager, c.envMappingFunc)

	// Deb specific
	for k, v := range c.Info.Deb.Fields {
		c.Info.Deb.Fields[k] = os.Expand(v, c.envMappingFunc)
	}
	c.Info.Deb.Predepends = c.expandEnvVarsStringSlice(c.Info.Deb.Predepends)

	// IPK specific
	for k, v := range c.Info.IPK.Fields {
		c.Info.IPK.Fields[k] = os.Expand(v, c.envMappingFunc)
	}
	c.Info.IPK.Predepends = c.expandEnvVarsStringSlice(c.Info.IPK.Predepends)

	// RPM specific
	c.Info.RPM.Packager = os.Expand(c.RPM.Packager, c.envMappingFunc)
}

// Info contains information about a single package.
type Info struct {
	Overridables    `yaml:",inline" json:",inline"`
	Name            string    `yaml:"name" json:"name" jsonschema:"title=package name"`
	Arch            string    `yaml:"arch" json:"arch" jsonschema:"title=target architecture,example=amd64"`
	Platform        string    `yaml:"platform,omitempty" json:"platform,omitempty" jsonschema:"title=target platform,example=linux,default=linux"`
	Epoch           string    `yaml:"epoch,omitempty" json:"epoch,omitempty" jsonschema:"title=version epoch,example=2,default=extracted from version"`
	Version         string    `yaml:"version" json:"version" jsonschema:"title=version,example=v1.0.2,example=2.0.1"`
	VersionSchema   string    `yaml:"version_schema,omitempty" json:"version_schema,omitempty" jsonschema:"title=version schema,enum=semver,enum=none,default=semver"`
	Release         string    `yaml:"release,omitempty" json:"release,omitempty" jsonschema:"title=version release,example=1"`
	Prerelease      string    `yaml:"prerelease,omitempty" json:"prerelease,omitempty" jsonschema:"title=version prerelease,default=extracted from version"`
	VersionMetadata string    `yaml:"version_metadata,omitempty" json:"version_metadata,omitempty" jsonschema:"title=version metadata,example=git"`
	Section         string    `yaml:"section,omitempty" json:"section,omitempty" jsonschema:"title=package section,example=default"`
	Priority        string    `yaml:"priority,omitempty" json:"priority,omitempty" jsonschema:"title=package priority,example=extra"`
	Maintainer      string    `yaml:"maintainer,omitempty" json:"maintainer,omitempty" jsonschema:"title=package maintainer,example=me@example.com"`
	Description     string    `yaml:"description,omitempty" json:"description,omitempty" jsonschema:"title=package description"`
	Vendor          string    `yaml:"vendor,omitempty" json:"vendor,omitempty" jsonschema:"title=package vendor,example=MyCorp"`
	Homepage        string    `yaml:"homepage,omitempty" json:"homepage,omitempty" jsonschema:"title=package homepage,example=https://example.com"`
	License         string    `yaml:"license,omitempty" json:"license,omitempty" jsonschema:"title=package license,example=MIT"`
	Changelog       string    `yaml:"changelog,omitempty" json:"changelog,omitempty" jsonschema:"title=package changelog,example=changelog.yaml,description=see https://github.com/goreleaser/chglog for more details"`
	DisableGlobbing bool      `yaml:"disable_globbing,omitempty" json:"disable_globbing,omitempty" jsonschema:"title=whether to disable file globbing,default=false"`
	MTime           time.Time `yaml:"mtime,omitempty" json:"mtime,omitempty" jsonschema:"title=time to set into the files generated by nFPM"`
	Target          string    `yaml:"-" json:"-"`
	EnableMetadata  bool      `yaml:"enable_metadata,omitempty" json:"enable_metadata,omitempty" jsonschema:"title=enable_metadata"`
}

// MetaInfo is a wrapper around information about single package and generated package data
type MetaInfo struct {
	Info    *Info
	Package io.ReadSeeker
}

func (i *Info) Validate() error {
	return Validate(i)
}

// GetChangeLog parses the provided changelog file.
func (i *Info) GetChangeLog() (log *chglog.PackageChangeLog, err error) {
	// if the file does not exist chglog.Parse will just silently
	// create an empty changelog but we should notify the user instead
	if _, err = os.Stat(i.Changelog); errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	entries, err := chglog.Parse(i.Changelog)
	if err != nil {
		return nil, err
	}

	return &chglog.PackageChangeLog{
		Name:    i.Name,
		Entries: entries,
	}, nil
}

func (i *Info) parseSemver() {
	// parse the version as a semver so we can properly split the parts
	// and support proper ordering for both rpm and deb
	if v, err := semver.NewVersion(i.Version); err == nil {
		i.Version = fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Patch())
		if i.Prerelease == "" {
			i.Prerelease = v.Prerelease()
		}

		if i.VersionMetadata == "" {
			i.VersionMetadata = v.Metadata()
		}
	}
}

// Overridables contain the field which are overridable in a package.
type Overridables struct {
	Replaces   []string       `yaml:"replaces,omitempty" json:"replaces,omitempty" jsonschema:"title=replaces directive,example=nfpm"`
	Provides   []string       `yaml:"provides,omitempty" json:"provides,omitempty" jsonschema:"title=provides directive,example=nfpm"`
	Depends    []string       `yaml:"depends,omitempty" json:"depends,omitempty" jsonschema:"title=depends directive,example=nfpm"`
	Recommends []string       `yaml:"recommends,omitempty" json:"recommends,omitempty" jsonschema:"title=recommends directive,example=nfpm"`
	Suggests   []string       `yaml:"suggests,omitempty" json:"suggests,omitempty" jsonschema:"title=suggests directive,example=nfpm"`
	Conflicts  []string       `yaml:"conflicts,omitempty" json:"conflicts,omitempty" jsonschema:"title=conflicts directive,example=nfpm"`
	Contents   files.Contents `yaml:"contents,omitempty" json:"contents,omitempty" jsonschema:"title=files to add to the package"`
	Umask      os.FileMode    `yaml:"umask,omitempty" json:"umask,omitempty" jsonschema:"title=umask for file contents,example=112"`
	Scripts    Scripts        `yaml:"scripts,omitempty" json:"scripts,omitempty" jsonschema:"title=scripts to execute"`
	RPM        RPM            `yaml:"rpm,omitempty" json:"rpm,omitempty" jsonschema:"title=rpm-specific settings"`
	Deb        Deb            `yaml:"deb,omitempty" json:"deb,omitempty" jsonschema:"title=deb-specific settings"`
	APK        APK            `yaml:"apk,omitempty" json:"apk,omitempty" jsonschema:"title=apk-specific settings"`
	ArchLinux  ArchLinux      `yaml:"archlinux,omitempty" json:"archlinux,omitempty" jsonschema:"title=archlinux-specific settings"`
	IPK        IPK            `yaml:"ipk,omitempty" json:"ipk,omitempty" jsonschema:"title=ipk-specific settings"`
}

type ArchLinux struct {
	Pkgbase  string           `yaml:"pkgbase,omitempty" json:"pkgbase,omitempty" jsonschema:"title=explicitly specify the name used to refer to a split package, defaults to name"`
	Arch     string           `yaml:"arch,omitempty" json:"arch,omitempty" jsonschema:"title=architecture in archlinux nomenclature"`
	Packager string           `yaml:"packager,omitempty" json:"packager,omitempty" jsonschema:"title=organization that packaged the software"`
	Scripts  ArchLinuxScripts `yaml:"scripts,omitempty" json:"scripts,omitempty" jsonschema:"title=archlinux-specific scripts"`
}

type ArchLinuxScripts struct {
	PreUpgrade  string `yaml:"preupgrade,omitempty" json:"preupgrade,omitempty" jsonschema:"title=preupgrade script"`
	PostUpgrade string `yaml:"postupgrade,omitempty" json:"postupgrade,omitempty" jsonschema:"title=postupgrade script"`
}

// RPM is custom configs that are only available on RPM packages.
type RPM struct {
	Arch        string       `yaml:"arch,omitempty" json:"arch,omitempty" jsonschema:"title=architecture in rpm nomenclature"`
	Scripts     RPMScripts   `yaml:"scripts,omitempty" json:"scripts,omitempty" jsonschema:"title=rpm-specific scripts"`
	Group       string       `yaml:"group,omitempty" json:"group,omitempty" jsonschema:"title=package group,example=Unspecified"`
	Summary     string       `yaml:"summary,omitempty" json:"summary,omitempty" jsonschema:"title=package summary"`
	Compression string       `yaml:"compression,omitempty" json:"compression,omitempty" jsonschema:"title=compression algorithm to be used,enum=gzip,enum=lzma,enum=xz,default=gzip:-1"`
	Signature   RPMSignature `yaml:"signature,omitempty" json:"signature,omitempty" jsonschema:"title=rpm signature"`
	Packager    string       `yaml:"packager,omitempty" json:"packager,omitempty" jsonschema:"title=organization that actually packaged the software"`
	Prefixes    []string     `yaml:"prefixes,omitempty" json:"prefixes,omitempty" jsonschema:"title=Prefixes for relocatable packages"`
}

// RPMScripts represents scripts only available on RPM packages.
type RPMScripts struct {
	PreTrans  string `yaml:"pretrans,omitempty" json:"pretrans,omitempty" jsonschema:"title=pretrans script"`
	PostTrans string `yaml:"posttrans,omitempty" json:"posttrans,omitempty" jsonschema:"title=posttrans script"`
	Verify    string `yaml:"verify,omitempty" json:"verify,omitempty" jsonschema:"title=verify script"`
}

type PackageSignature struct {
	// PGP secret key, can be ASCII-armored
	KeyFile       string  `yaml:"key_file,omitempty" json:"key_file,omitempty" jsonschema:"title=key file,example=key.gpg"`
	KeyID         *string `yaml:"key_id,omitempty" json:"key_id,omitempty" jsonschema:"title=key id,example=bc8acdd415bd80b3"`
	KeyPassphrase string  `yaml:"-" json:"-"` // populated from environment variable
	// SignFn, if set, will be called with the package-specific data to sign.
	// For deb and rpm packages, data is the full package content.
	// For apk packages, data is the SHA1 digest of control tgz.
	//
	// This allows for signing implementations other than using a local file
	// (for example using a remote signer like KMS).
	SignFn func(data io.Reader) ([]byte, error) `yaml:"-" json:"-"` // populated when used as a library
}

type RPMSignature struct {
	PackageSignature `yaml:",inline" json:",inline"`
}

type APK struct {
	Arch      string       `yaml:"arch,omitempty" json:"arch,omitempty" jsonschema:"title=architecture in apk nomenclature"`
	Signature APKSignature `yaml:"signature,omitempty" json:"signature,omitempty" jsonschema:"title=apk signature"`
	Scripts   APKScripts   `yaml:"scripts,omitempty" json:"scripts,omitempty" jsonschema:"title=apk scripts"`
}

type APKSignature struct {
	PackageSignature `yaml:",inline" json:",inline"`
	// defaults to <maintainer email>.rsa.pub
	KeyName string `yaml:"key_name,omitempty" json:"key_name,omitempty" jsonschema:"title=key name,example=origin,default=maintainer_email.rsa.pub"`
}

type APKScripts struct {
	PreUpgrade  string `yaml:"preupgrade,omitempty" json:"preupgrade,omitempty" jsonschema:"title=pre upgrade script"`
	PostUpgrade string `yaml:"postupgrade,omitempty" json:"postupgrade,omitempty" jsonschema:"title=post upgrade script"`
}

// Deb is custom configs that are only available on deb packages.
type Deb struct {
	Arch         string            `yaml:"arch,omitempty" json:"arch,omitempty" jsonschema:"title=architecture in deb nomenclature"`
	Scripts      DebScripts        `yaml:"scripts,omitempty" json:"scripts,omitempty" jsonschema:"title=scripts"`
	Triggers     DebTriggers       `yaml:"triggers,omitempty" json:"triggers,omitempty" jsonschema:"title=triggers"`
	Breaks       []string          `yaml:"breaks,omitempty" json:"breaks,omitempty" jsonschema:"title=breaks"`
	Signature    DebSignature      `yaml:"signature,omitempty" json:"signature,omitempty" jsonschema:"title=signature"`
	Compression  string            `yaml:"compression,omitempty" json:"compression,omitempty" jsonschema:"title=compression algorithm to be used,enum=gzip,enum=xz,enum=none,default=gzip"`
	Fields       map[string]string `yaml:"fields,omitempty" json:"fields,omitempty" jsonschema:"title=fields"`
	Predepends   []string          `yaml:"predepends,omitempty" json:"predepends,omitempty" jsonschema:"title=predepends directive,example=nfpm"`
	Distribution string            `yaml:"distribution" json:"distribution" jsonschema:"title=distribution"`
	Urgency      string            `yaml:"urgency" json:"urgency" jsonschema:"title=urgency"`
	Metadata     DebMetadata       `yaml:"metadata,omitempty" json:"metadata,omitempty" jsonschema:"title=metadata"`
}

// DebMetadata is custom configs for generating .changes file that are only available on deb packages.
type DebMetadata struct {
	Binary       string            `yaml:"binary" json:"binary" jsonschema:"title=binary"`
	Distribution string            `yaml:"distribution" json:"distribution" jsonschema:"title=distribution"`
	Urgency      string            `yaml:"urgency" json:"urgency" jsonschema:"title=urgency"`
	ChangedBy    string            `yaml:"changed_by" json:"changed_by" jsonschema:"title=changed_by"`
	Fields       map[string]string `yaml:"fields,omitempty" json:"fields,omitempty" jsonschema:"title=fields"`
}

type DebSignature struct {
	PackageSignature `yaml:",inline" json:",inline"`
	// Only debsign still supported
	Method string `yaml:"method,omitempty" json:"method,omitempty" jsonschema:"title=method role,enum=debsign,default=debsign"`
	// origin, maint or archive (defaults to origin)
	Type   string `yaml:"type,omitempty" json:"type,omitempty" jsonschema:"title=signer role,enum=origin,enum=maint,enum=archive,default=origin"`
	Signer string `yaml:"signer,omitempty" json:"signer,omitempty" jsonschema:"title=signer"`
}

// DebTriggers contains triggers only available for deb packages.
// https://wiki.debian.org/DpkgTriggers
// https://man7.org/linux/man-pages/man5/deb-triggers.5.html
type DebTriggers struct {
	Interest        []string `yaml:"interest,omitempty" json:"interest,omitempty" jsonschema:"title=interest"`
	InterestAwait   []string `yaml:"interest_await,omitempty" json:"interest_await,omitempty" jsonschema:"title=interest await"`
	InterestNoAwait []string `yaml:"interest_noawait,omitempty" json:"interest_noawait,omitempty" jsonschema:"title=interest noawait"`
	Activate        []string `yaml:"activate,omitempty" json:"activate,omitempty" jsonschema:"title=activate"`
	ActivateAwait   []string `yaml:"activate_await,omitempty" json:"activate_await,omitempty" jsonschema:"title=activate await"`
	ActivateNoAwait []string `yaml:"activate_noawait,omitempty" json:"activate_noawait,omitempty" jsonschema:"title=activate noawait"`
}

// DebScripts is scripts only available on deb packages.
type DebScripts struct {
	Rules     string `yaml:"rules,omitempty" json:"rules,omitempty" jsonschema:"title=rules"`
	Templates string `yaml:"templates,omitempty" json:"templates,omitempty" jsonschema:"title=templates"`
	Config    string `yaml:"config,omitempty" json:"config,omitempty" jsonschema:"title=config"`
}

// IPK is custom configs that are only available on deb packages.
type IPK struct {
	ABIVersion    string            `yaml:"abi_version,omitempty" json:"abi_version,omitempty" jsonschema:"title=abi version"`
	Alternatives  []IPKAlternative  `yaml:"alternatives,omitempty" json:"alternatives,omitempty" jsonschema:"title=alternatives"`
	Arch          string            `yaml:"arch,omitempty" json:"arch,omitempty" jsonschema:"title=architecture in deb nomenclature"`
	AutoInstalled bool              `yaml:"auto_installed,omitempty" json:"auto_installed,omitempty" jsonschema:"title=auto installed,default=false"`
	Essential     bool              `yaml:"essential,omitempty" json:"essential,omitempty" jsonschema:"title=whether package is essential,default=false"`
	Fields        map[string]string `yaml:"fields,omitempty" json:"fields,omitempty" jsonschema:"title=fields"`
	Predepends    []string          `yaml:"predepends,omitempty" json:"predepends,omitempty" jsonschema:"title=predepends directive,example=nfpm"`
	Tags          []string          `yaml:"tags,omitempty" json:"tags,omitempty" jsonschema:"title=tags"`
}

// IPKAlternative represents an alternative for an IPK package.
type IPKAlternative struct {
	Priority int    `yaml:"priority,omitempty" json:"priority,omitempty" jsonschema:"title=priority"`
	Target   string `yaml:"target,omitempty" json:"target,omitempty" jsonschema:"title=target"`
	LinkName string `yaml:"link_name,omitempty" json:"link_name,omitempty" jsonschema:"title=link name"`
}

// Scripts contains information about maintainer scripts for packages.
type Scripts struct {
	PreInstall  string `yaml:"preinstall,omitempty" json:"preinstall,omitempty" jsonschema:"title=pre install"`
	PostInstall string `yaml:"postinstall,omitempty" json:"postinstall,omitempty" jsonschema:"title=post install"`
	PreRemove   string `yaml:"preremove,omitempty" json:"preremove,omitempty" jsonschema:"title=pre remove"`
	PostRemove  string `yaml:"postremove,omitempty" json:"postremove,omitempty" jsonschema:"title=post remove"`
}

// ErrFieldEmpty happens when some required field is empty.
type ErrFieldEmpty struct {
	field string
}

func (e ErrFieldEmpty) Error() string {
	return fmt.Sprintf("package %s must be provided", e.field)
}

// PrepareForPackager validates the configuration for the given packager and
// prepares the contents for said packager.
func PrepareForPackager(info *Info, packager string) (err error) {
	if info.Name == "" {
		return ErrFieldEmpty{"name"}
	}

	if info.Arch == "" &&
		((packager == "deb" && info.Deb.Arch == "") ||
			(packager == "rpm" && info.RPM.Arch == "") ||
			(packager == "apk" && info.APK.Arch == "")) {
		return ErrFieldEmpty{"arch"}
	}
	if info.Version == "" {
		return ErrFieldEmpty{"version"}
	}

	info.Contents, err = files.PrepareForPackager(
		info.Contents,
		info.Umask,
		packager,
		info.DisableGlobbing,
		info.MTime,
	)

	return err
}

// Validate the given Info and returns an error if it is invalid. Validate will
// no change the info's contents.
func Validate(info *Info) (err error) {
	if info.Name == "" {
		return ErrFieldEmpty{"name"}
	}
	if info.Arch == "" && (info.Deb.Arch == "" || info.RPM.Arch == "" || info.APK.Arch == "") {
		return ErrFieldEmpty{"arch"}
	}
	if info.Version == "" {
		return ErrFieldEmpty{"version"}
	}

	for packager := range packagers {
		_, err := files.PrepareForPackager(
			info.Contents,
			info.Umask,
			packager,
			info.DisableGlobbing,
			info.MTime,
		)
		if err != nil {
			return err
		}
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
	if info.Arch == "" {
		info.Arch = "amd64"
	}
	if strings.HasPrefix(info.Arch, "mips") {
		info.Arch = strings.NewReplacer(
			"softfloat", "",
			"hardfloat", "",
		).Replace(info.Arch)
	}
	if info.Version == "" {
		info.Version = "v0.0.0-rc0"
	}
	if info.Umask == 0 {
		info.Umask = 0o02
	}
	if info.MTime.IsZero() {
		info.MTime = modtime.FromEnv()
	}
	switch info.VersionSchema {
	case "none":
		// No change to the version or prerelease info set in the YAML file
		break
	case "semver":
		fallthrough
	default:
		info.parseSemver()
	}

	return info
}

// ErrSigningFailure is returned whenever something went wrong during
// the package signing process. The underlying error can be unwrapped
// and could be crypto-related or something that occurred while adding
// the signature to the package.
type ErrSigningFailure struct {
	Err error
}

func (s *ErrSigningFailure) Error() string {
	return fmt.Sprintf("signing error: %v", s.Err)
}

func (s *ErrSigningFailure) Unwarp() error {
	return s.Err
}
