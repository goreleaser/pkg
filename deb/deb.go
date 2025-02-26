// Package deb implements nfpm.Packager providing .deb bindings.
package deb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5" // nolint:gas
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/blakesmith/ar"
	"github.com/goreleaser/chglog"
	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/deprecation"
	"github.com/goreleaser/nfpm/v2/files"
	"github.com/goreleaser/nfpm/v2/internal/maps"
	"github.com/goreleaser/nfpm/v2/internal/modtime"
	"github.com/goreleaser/nfpm/v2/internal/sign"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const packagerName = "deb"

// nolint: gochecknoinits
func init() {
	nfpm.RegisterPackager(packagerName, Default)
}

// nolint: gochecknoglobals
var archToDebian = map[string]string{
	"386":      "i386",
	"arm64":    "arm64",
	"arm5":     "armel",
	"arm6":     "armhf",
	"arm7":     "armhf",
	"mips64le": "mips64el",
	"mipsle":   "mipsel",
	"ppc64le":  "ppc64el",
	"s390":     "s390x",
}

func ensureValidArch(info *nfpm.Info) *nfpm.Info {
	if info.Deb.Arch != "" {
		info.Arch = info.Deb.Arch
	} else if arch, ok := archToDebian[info.Arch]; ok {
		info.Arch = arch
	}

	return info
}

// Default deb packager.
// nolint: gochecknoglobals
var Default = &Deb{}

// Deb is a deb packager implementation.
type Deb struct{}

// ConventionalFileName returns a file name according
// to the conventions for debian packages. See:
// https://manpages.debian.org/buster/dpkg-dev/dpkg-name.1.en.html
func (*Deb) ConventionalFileName(info *nfpm.Info) string {
	info = ensureValidArch(info)

	version := info.Version
	if info.Prerelease != "" {
		version += "~" + info.Prerelease
	}

	if info.VersionMetadata != "" {
		version += "+" + info.VersionMetadata
	}

	if info.Release != "" {
		version += "-" + info.Release
	}

	// package_version_architecture.package-type
	return fmt.Sprintf("%s_%s_%s.deb", info.Name, version, info.Arch)
}

// ConventionalExtension returns the file name conventionally used for Deb packages
func (*Deb) ConventionalExtension() string {
	return ".deb"
}

// ErrInvalidSignatureType happens if the signature type of a deb is not one of
// origin, maint or archive.
var ErrInvalidSignatureType = errors.New("invalid signature type")

// Package writes a new deb package to the given writer using the given info.
func (d *Deb) Package(info *nfpm.Info, deb io.Writer) (err error) { // nolint: funlen
	info = ensureValidArch(info)

	err = nfpm.PrepareForPackager(withChangelogIfRequested(info), packagerName)
	if err != nil {
		return err
	}

	// Set up some deb specific defaults
	d.SetPackagerDefaults(info)

	dataTarball, md5sums, instSize, dataTarballName, err := createDataTarball(info)
	if err != nil {
		return err
	}

	controlTarGz, err := createControl(instSize, md5sums, info)
	if err != nil {
		return err
	}

	debianBinary := []byte("2.0\n")

	w := ar.NewWriter(deb)
	if err := w.WriteGlobalHeader(); err != nil {
		return fmt.Errorf("cannot write ar header to deb file: %w", err)
	}

	mtime := modtime.Get(info.MTime)

	if err := addArFile(w, "debian-binary", debianBinary, mtime); err != nil {
		return fmt.Errorf("cannot pack debian-binary: %w", err)
	}

	if err := addArFile(w, "control.tar.gz", controlTarGz, mtime); err != nil {
		return fmt.Errorf("cannot add control.tar.gz to deb: %w", err)
	}

	if err := addArFile(w, dataTarballName, dataTarball, mtime); err != nil {
		return fmt.Errorf("cannot add data.tar.gz to deb: %w", err)
	}

	if info.Deb.Signature.KeyFile != "" || info.Deb.Signature.SignFn != nil {
		sig, sigType, err := doSign(info, debianBinary, controlTarGz, dataTarball)
		if err != nil {
			return err
		}

		if err := addArFile(w, "_gpg"+sigType, sig, mtime); err != nil {
			return &nfpm.ErrSigningFailure{
				Err: fmt.Errorf("add signature to ar file: %w", err),
			}
		}
	}

	return nil
}

func doSign(info *nfpm.Info, debianBinary, controlTarGz, dataTarball []byte) ([]byte, string, error) {
	switch info.Deb.Signature.Method {
	case "dpkg-sig":
		return dpkgSign(info, debianBinary, controlTarGz, dataTarball)
	default:
		return debSign(info, debianBinary, controlTarGz, dataTarball)
	}
}

func dpkgSign(info *nfpm.Info, debianBinary, controlTarGz, dataTarball []byte) ([]byte, string, error) {
	sigType := "builder"
	if info.Deb.Signature.Type != "" {
		sigType = info.Deb.Signature.Type
	}

	data, err := readDpkgSigData(info, debianBinary, controlTarGz, dataTarball)
	if err != nil {
		return nil, sigType, &nfpm.ErrSigningFailure{Err: err}
	}

	var sig []byte
	if signFn := info.Deb.Signature.SignFn; signFn != nil {
		sig, err = signFn(data)
	} else {
		sig, err = sign.PGPClearSignWithKeyID(data, info.Deb.Signature.KeyFile, info.Deb.Signature.KeyPassphrase, info.Deb.Signature.KeyID)
	}
	if err != nil {
		return nil, sigType, &nfpm.ErrSigningFailure{Err: err}
	}
	return sig, sigType, nil
}

func debSign(info *nfpm.Info, debianBinary, controlTarGz, dataTarball []byte) ([]byte, string, error) {
	data := readDebsignData(debianBinary, controlTarGz, dataTarball)

	sigType := "origin"
	if info.Deb.Signature.Type != "" {
		sigType = info.Deb.Signature.Type
	}

	if sigType != "origin" && sigType != "maint" && sigType != "archive" {
		return nil, sigType, &nfpm.ErrSigningFailure{
			Err: ErrInvalidSignatureType,
		}
	}

	var sig []byte
	var err error
	if signFn := info.Deb.Signature.SignFn; signFn != nil {
		sig, err = signFn(data)
	} else {
		sig, err = sign.PGPArmoredDetachSignWithKeyID(data, info.Deb.Signature.KeyFile, info.Deb.Signature.KeyPassphrase, info.Deb.Signature.KeyID)
	}
	if err != nil {
		return nil, sigType, &nfpm.ErrSigningFailure{Err: err}
	}
	return sig, sigType, nil
}

func readDebsignData(debianBinary, controlTarGz, dataTarball []byte) io.Reader {
	return io.MultiReader(bytes.NewReader(debianBinary), bytes.NewReader(controlTarGz),
		bytes.NewReader(dataTarball))
}

// reference: https://manpages.debian.org/jessie/dpkg-sig/dpkg-sig.1.en.html
const dpkgSigTemplate = `
Hash: SHA1

Version: 4
Signer: {{ .Signer }}
Date: {{ .Date }}
Role: {{ .Role }}
Files:
{{range .Files -}}
{{"\t"}}{{ hex .Md5Sum }} {{ hex .Sha1Sum }} {{ .Size }} {{ .Name }}
{{end -}}
`

type dpkgSigData struct {
	Signer string
	Date   time.Time
	Role   string
	Files  []dpkgSigFileLine
	Info   *nfpm.Info
}
type dpkgSigFileLine struct {
	Md5Sum  []byte
	Sha1Sum []byte
	Size    int
	Name    string
}

func newDpkgSigFileLine(name string, fileContent []byte) dpkgSigFileLine {
	md5Sum, sha1Sum := md5.Sum(fileContent), sha1.Sum(fileContent)
	return dpkgSigFileLine{
		Name:    name,
		Md5Sum:  md5Sum[:],
		Sha1Sum: sha1Sum[:],
		Size:    len(fileContent),
	}
}

func readDpkgSigData(info *nfpm.Info, debianBinary, controlTarGz, dataTarball []byte) (io.Reader, error) {
	data := dpkgSigData{
		Signer: info.Deb.Signature.Signer,
		Date:   modtime.Get(info.MTime),
		Role:   info.Deb.Signature.Type,
		Files: []dpkgSigFileLine{
			newDpkgSigFileLine("debian-binary", debianBinary),
			newDpkgSigFileLine("control.tar.gz", controlTarGz),
			newDpkgSigFileLine("data.tar.gz", dataTarball),
		},
	}
	temp, _ := template.New("dpkg-sig").Funcs(template.FuncMap{
		"hex": hex.EncodeToString,
	}).Parse(dpkgSigTemplate)
	buf := &bytes.Buffer{}
	err := temp.Execute(buf, data)
	if err != nil {
		return nil, fmt.Errorf("dpkg-sig template error: %w", err)
	}
	return buf, nil
}

func (*Deb) SetPackagerDefaults(info *nfpm.Info) {
	// Priority should be set on all packages per:
	//   https://www.debian.org/doc/debian-policy/ch-archive.html#priorities
	// "optional" seems to be the safe/sane default here
	if info.Priority == "" {
		info.Priority = "optional"
	}

	// The safe thing here feels like defaulting to something like below.
	// That will prevent existing configs from breaking anyway...  Wondering
	// if in the long run we should be more strict about this and error when
	// not set?
	if info.Maintainer == "" {
		deprecation.Println("Leaving the 'maintainer' field unset will not be allowed in a future version")
		info.Maintainer = "Unset Maintainer <unset@localhost>"
	}
}

func addArFile(w *ar.Writer, name string, body []byte, date time.Time) error {
	header := ar.Header{
		Name:    files.ToNixPath(name),
		Size:    int64(len(body)),
		Mode:    0o644,
		ModTime: date,
	}
	if err := w.WriteHeader(&header); err != nil {
		return fmt.Errorf("cannot write file header: %w", err)
	}
	_, err := w.Write(body)
	return err
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }

func createDataTarball(info *nfpm.Info) (dataTarBall, md5sums []byte,
	instSize int64, name string, err error,
) {
	var (
		dataTarball            bytes.Buffer
		dataTarballWriteCloser io.WriteCloser
	)

	switch info.Deb.Compression {
	case "", "gzip": // the default for now
		dataTarballWriteCloser = gzip.NewWriter(&dataTarball)
		name = "data.tar.gz"
	case "xz":
		dataTarballWriteCloser, err = xz.NewWriter(&dataTarball)
		if err != nil {
			return nil, nil, 0, "", err
		}
		name = "data.tar.xz"
	case "zstd":
		dataTarballWriteCloser, err = zstd.NewWriter(&dataTarball)
		if err != nil {
			return nil, nil, 0, "", err
		}
		name = "data.tar.zst"
	case "none":
		dataTarballWriteCloser = nopCloser{Writer: &dataTarball}
		name = "data.tar"
	default:
		return nil, nil, 0, "", fmt.Errorf("unknown compression algorithm: %s", info.Deb.Compression)
	}

	// the writer is properly closed later, this is just in case that we error out
	defer dataTarballWriteCloser.Close() // nolint: errcheck

	md5sums, instSize, err = fillDataTar(info, dataTarballWriteCloser)
	if err != nil {
		return nil, nil, 0, "", err
	}

	if err := dataTarballWriteCloser.Close(); err != nil {
		return nil, nil, 0, "", fmt.Errorf("closing data tarball: %w", err)
	}

	return dataTarball.Bytes(), md5sums, instSize, name, nil
}

func fillDataTar(info *nfpm.Info, w io.Writer) (md5sums []byte, instSize int64, err error) {
	out := tar.NewWriter(w)

	// the writer is properly closed later, this is just in case that we have
	// an error in another part of the code.
	defer out.Close() // nolint: errcheck

	md5buf, instSize, err := createFilesInsideDataTar(info, out)
	if err != nil {
		return nil, 0, err
	}

	if err := out.Close(); err != nil {
		return nil, 0, fmt.Errorf("closing data.tar.gz: %w", err)
	}

	return md5buf.Bytes(), instSize, nil
}

func createFilesInsideDataTar(info *nfpm.Info, tw *tar.Writer) (md5buf bytes.Buffer, instSize int64, err error) {
	for _, file := range info.Contents {
		switch file.Type {
		case files.TypeRPMGhost:
			continue // skip ghost files in deb
		case files.TypeDir, files.TypeImplicitDir:
			header, err := tarHeader(file, info.MTime)
			if err != nil {
				return md5buf, 0, fmt.Errorf("build directory header for %q: %w",
					file.Destination, err)
			}

			err = tw.WriteHeader(header)
			if err != nil {
				return md5buf, 0, fmt.Errorf("create directory %q in data tar: %w",
					header.Name, err)
			}
		case files.TypeSymlink:
			header, err := tarHeader(file, info.MTime)
			if err != nil {
				return md5buf, 0, fmt.Errorf("build symlink header for %q: %w",
					file.Destination, err)
			}

			err = newItemInsideTar(tw, []byte{}, header)
			if err != nil {
				return md5buf, 0, fmt.Errorf("create symlink %q in data tar: %w",
					header.Linkname, err)
			}
		case files.TypeDebChangelog:
			size, err := createChangelogInsideDataTar(tw, &md5buf, info, file.Destination)
			if err != nil {
				return md5buf, 0, fmt.Errorf("write changelog to data tar: %w", err)
			}

			instSize += size
		default:
			size, err := copyToTarAndDigest(file, tw, &md5buf)
			if err != nil {
				return md5buf, 0, fmt.Errorf("write %q to data tar: %w", file.Destination, err)
			}

			instSize += size
		}
	}

	return md5buf, instSize, nil
}

func copyToTarAndDigest(file *files.Content, tw *tar.Writer, md5w io.Writer) (int64, error) {
	tarFile, err := os.OpenFile(file.Source, os.O_RDONLY, 0o600) //nolint:gosec
	if err != nil {
		return 0, fmt.Errorf("could not add tarFile to the archive: %w", err)
	}
	// don't care if it errs while closing...
	defer tarFile.Close() // nolint: errcheck,gosec

	header, err := tarHeader(file)
	if err != nil {
		return 0, err
	}

	if err := tw.WriteHeader(header); err != nil {
		return 0, fmt.Errorf("cannot write header of %s to data.tar.gz: %w", file.Source, err)
	}
	digest := md5.New() // nolint:gas
	if _, err := io.Copy(tw, io.TeeReader(tarFile, digest)); err != nil {
		return 0, fmt.Errorf("%s: failed to copy: %w", file.Source, err)
	}
	if _, err := fmt.Fprintf(md5w, "%x  %s\n", digest.Sum(nil), header.Name); err != nil {
		return 0, fmt.Errorf("%s: failed to write md5: %w", file.Source, err)
	}
	return file.Size(), nil
}

func withChangelogIfRequested(info *nfpm.Info) *nfpm.Info {
	if info.Changelog == "" {
		return info
	}

	// https://www.debian.org/doc/manuals/developers-reference/pkgs.de.html#recording-changes-in-the-package
	// https://lintian.debian.org/tags/debian-changelog-file-missing-or-wrong-name
	info.Contents = append(info.Contents, &files.Content{
		Destination: fmt.Sprintf("/usr/share/doc/%s/changelog.Debian.gz", info.Name),
		Type:        files.TypeDebChangelog, // this type is handeled in createDataTarball
	})

	return info
}

func createChangelogInsideDataTar(
	tarw *tar.Writer,
	g io.Writer,
	info *nfpm.Info,
	fileName string,
) (int64, error) {
	var buf bytes.Buffer
	// we need here a non timestamped compression -> https://github.com/klauspost/pgzip doesn't support that
	// https://github.com/klauspost/pgzip/blob/v1.2.6/gzip.go#L322 vs.
	// https://cs.opensource.google/go/go/+/refs/tags/go1.20.4:src/compress/gzip/gzip.go;l=157
	out, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return 0, fmt.Errorf("could not create gzip writer: %w", err)
	}
	// the writers are properly closed later, this is just in case that we have
	// an error in another part of the code.
	defer out.Close() // nolint: errcheck

	changelogContent, err := formatChangelog(info)
	if err != nil {
		return 0, err
	}

	if _, err = io.WriteString(out, changelogContent); err != nil {
		return 0, err
	}

	if err = out.Close(); err != nil {
		return 0, fmt.Errorf("closing %s: %w", filepath.Base(fileName), err)
	}

	changelogData := buf.Bytes()

	digest := md5.New() // nolint:gas
	if _, err = digest.Write(changelogData); err != nil {
		return 0, err
	}

	if _, err = fmt.Fprintf(
		g,
		"%x  %s\n",
		digest.Sum(nil),
		files.AsExplicitRelativePath(fileName),
	); err != nil {
		return 0, err
	}

	if err = newFileInsideTar(tarw, fileName, changelogData, modtime.Get(info.MTime)); err != nil {
		return 0, err
	}

	return int64(len(changelogData)), nil
}

func formatChangelog(info *nfpm.Info) (string, error) {
	changelog, err := info.GetChangeLog()
	if err != nil {
		return "", err
	}

	tpl, err := chglog.DebTemplate()
	if err != nil {
		return "", err
	}

	formattedChangelog, err := chglog.FormatChangelog(changelog, tpl)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(formattedChangelog) + "\n", nil
}

// nolint:funlen
func createControl(instSize int64, md5sums []byte, info *nfpm.Info) (controlTarGz []byte, err error) {
	var buf bytes.Buffer
	compress := gzip.NewWriter(&buf)
	out := tar.NewWriter(compress)
	// the writers are properly closed later, this is just in case that we have
	// an error in another part of the code.
	defer out.Close()      // nolint: errcheck
	defer compress.Close() // nolint: errcheck

	var body bytes.Buffer
	if err = writeControl(&body, controlData{
		Info:          info,
		InstalledSize: instSize / 1024,
	}); err != nil {
		return nil, err
	}

	mtime := modtime.Get(info.MTime)
	if err := newFileInsideTar(out, "./control", body.Bytes(), mtime); err != nil {
		return nil, err
	}
	if err := newFileInsideTar(out, "./md5sums", md5sums, mtime); err != nil {
		return nil, err
	}
	if err := newFileInsideTar(out, "./conffiles", conffiles(info), mtime); err != nil {
		return nil, err
	}

	if triggers := createTriggers(info); len(triggers) > 0 {
		if err := newFileInsideTar(out, "./triggers", triggers, mtime); err != nil {
			return nil, err
		}
	}

	type fileAndMode struct {
		fileName string
		mode     int64
	}

	specialFiles := map[string]*fileAndMode{
		"preinst": {
			fileName: info.Scripts.PreInstall,
			mode:     0o755,
		},
		"postinst": {
			fileName: info.Scripts.PostInstall,
			mode:     0o755,
		},
		"prerm": {
			fileName: info.Scripts.PreRemove,
			mode:     0o755,
		},
		"postrm": {
			fileName: info.Scripts.PostRemove,
			mode:     0o755,
		},
		"rules": {
			fileName: info.Overridables.Deb.Scripts.Rules,
			mode:     0o755,
		},
		"templates": {
			fileName: info.Overridables.Deb.Scripts.Templates,
			mode:     0o644,
		},
		"config": {
			fileName: info.Overridables.Deb.Scripts.Config,
			mode:     0o755,
		},
	}

	for _, filename := range maps.Keys(specialFiles) {
		dets := specialFiles[filename]
		if dets.fileName == "" {
			continue
		}
		if err := newFilePathInsideTar(out, dets.fileName, filename, dets.mode, mtime); err != nil {
			return nil, err
		}
	}

	if err := out.Close(); err != nil {
		return nil, fmt.Errorf("closing control.tar.gz: %w", err)
	}
	if err := compress.Close(); err != nil {
		return nil, fmt.Errorf("closing control.tar.gz: %w", err)
	}
	return buf.Bytes(), nil
}

func newItemInsideTar(out *tar.Writer, content []byte, header *tar.Header) error {
	if err := out.WriteHeader(header); err != nil {
		return fmt.Errorf("cannot write header of %s file to control.tar.gz: %w", header.Name, err)
	}
	if _, err := out.Write(content); err != nil {
		return fmt.Errorf("cannot write %s file to control.tar.gz: %w", header.Name, err)
	}
	return nil
}

func newFileInsideTar(out *tar.Writer, name string, content []byte, modtime time.Time) error {
	return newItemInsideTar(out, content, &tar.Header{
		Name:     files.AsExplicitRelativePath(name),
		Size:     int64(len(content)),
		Mode:     0o644,
		ModTime:  modtime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatGNU,
	})
}

func newFilePathInsideTar(out *tar.Writer, path, dest string, mode int64, modtime time.Time) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return newItemInsideTar(out, content, &tar.Header{
		Name:     files.AsExplicitRelativePath(dest),
		Size:     int64(len(content)),
		Mode:     mode,
		ModTime:  modtime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatGNU,
	})
}

func conffiles(info *nfpm.Info) []byte {
	// nolint: prealloc
	var confs []string
	for _, file := range info.Contents {
		switch file.Type {
		case files.TypeConfig, files.TypeConfigNoReplace, files.TypeConfigMissingOK:
			confs = append(confs, files.NormalizeAbsoluteFilePath(file.Destination))
		}
	}
	return []byte(strings.Join(confs, "\n") + "\n")
}

func createTriggers(info *nfpm.Info) []byte {
	var buffer bytes.Buffer

	// https://man7.org/linux/man-pages/man5/deb-triggers.5.html
	triggerEntries := []struct {
		Directive    string
		TriggerNames *[]string
	}{
		{"interest", &info.Deb.Triggers.Interest},
		{"interest-await", &info.Deb.Triggers.InterestAwait},
		{"interest-noawait", &info.Deb.Triggers.InterestNoAwait},
		{"activate", &info.Deb.Triggers.Activate},
		{"activate-await", &info.Deb.Triggers.ActivateAwait},
		{"activate-noawait", &info.Deb.Triggers.ActivateNoAwait},
	}

	for _, triggerEntry := range triggerEntries {
		for _, triggerName := range *triggerEntry.TriggerNames {
			fmt.Fprintf(&buffer, "%s %s\n", triggerEntry.Directive, triggerName)
		}
	}

	return buffer.Bytes()
}

const controlTemplate = `
{{- /* Mandatory fields */ -}}
Package: {{.Info.Name}}
Version: {{ if .Info.Epoch}}{{ .Info.Epoch }}:{{ end }}{{.Info.Version}}
         {{- if .Info.Prerelease}}~{{ .Info.Prerelease }}{{- end }}
         {{- if .Info.VersionMetadata}}+{{ .Info.VersionMetadata }}{{- end }}
         {{- if .Info.Release}}-{{ .Info.Release }}{{- end }}
Section: {{.Info.Section}}
Priority: {{.Info.Priority}}
Architecture: {{ if ne .Info.Platform "linux"}}{{ .Info.Platform }}-{{ end }}{{.Info.Arch}}
{{- /* Optional fields */ -}}
{{- if .Info.License }}
License: {{.Info.License}}
{{- end }}
{{- if .Info.Maintainer}}
Maintainer: {{.Info.Maintainer}}
{{- end }}
Installed-Size: {{.InstalledSize}}
{{- with .Info.Replaces}}
Replaces: {{join .}}
{{- end }}
{{- with nonEmpty .Info.Provides}}
Provides: {{join .}}
{{- end }}
{{- with .Info.Deb.Predepends}}
Pre-Depends: {{join .}}
{{- end }}
{{- with .Info.Depends}}
Depends: {{join .}}
{{- end }}
{{- with .Info.Recommends}}
Recommends: {{join .}}
{{- end }}
{{- with .Info.Suggests}}
Suggests: {{join .}}
{{- end }}
{{- with .Info.Conflicts}}
Conflicts: {{join .}}
{{- end }}
{{- with .Info.Deb.Breaks}}
Breaks: {{join .}}
{{- end }}
{{- if .Info.Homepage}}
Homepage: {{.Info.Homepage}}
{{- end }}
{{- /* Mandatory fields */}}
Description: {{multiline .Info.Description}}
{{- range $key, $value := .Info.Deb.Fields }}
{{- if $value }}
{{$key}}: {{$value}}
{{- end }}
{{- end }}
`

type controlData struct {
	Info          *nfpm.Info
	InstalledSize int64
}

func writeControl(w io.Writer, data controlData) error {
	return writeTemplate("control", controlTemplate, w, data)
}

func writeTemplate(name, t string, w io.Writer, data interface{}) error {
	tmpl := template.New(name)
	tmpl.Funcs(template.FuncMap{
		"join": func(strs []string) string {
			return strings.Trim(strings.Join(strs, ", "), " ")
		},
		"multiline": func(strs string) string {
			var b strings.Builder
			s := bufio.NewScanner(strings.NewReader(strings.TrimSpace(strs)))
			s.Scan()
			b.Write(bytes.TrimSpace(s.Bytes()))
			for s.Scan() {
				b.WriteString("\n ")
				l := bytes.TrimSpace(s.Bytes())
				if len(l) == 0 {
					b.WriteByte('.')
				} else {
					b.Write(l)
				}
			}
			return b.String()
		},
		"nonEmpty": func(strs []string) []string {
			var result []string
			for _, s := range strs {
				s := strings.TrimSpace(s)
				if s == "" {
					continue
				}
				result = append(result, s)
			}
			return result
		},
	})
	return template.Must(tmpl.Parse(t)).Execute(w, data)
}

func tarHeader(content *files.Content, preferredModTimes ...time.Time) (*tar.Header, error) {
	const (
		ISUID = 0o4000 // Set uid
		ISGID = 0o2000 // Set gid
		ISVTX = 0o1000 // Save text (sticky bit)
	)

	fm := content.Mode()

	h := &tar.Header{
		Name: content.Name(),
		ModTime: modtime.Get(
			append(preferredModTimes, content.ModTime())...),
		Mode:   int64(fm & 0o7777),
		Uname:  content.FileInfo.Owner,
		Gname:  content.FileInfo.Group,
		Format: tar.FormatGNU,
	}

	switch {
	case content.IsDir() || fm&fs.ModeDir != 0:
		h.Typeflag = tar.TypeDir
		h.Name = files.AsExplicitRelativePath(content.Destination)
	case content.Type == files.TypeSymlink || fm&fs.ModeSymlink != 0:
		h.Typeflag = tar.TypeSymlink
		h.Name = files.AsExplicitRelativePath(content.Destination)
		h.Linkname = content.Source
	case fm&fs.ModeDevice != 0:
		if fm&fs.ModeCharDevice != 0 {
			h.Typeflag = tar.TypeChar
		} else {
			h.Typeflag = tar.TypeBlock
		}
	case fm&fs.ModeNamedPipe != 0:
		h.Typeflag = tar.TypeFifo
	case fm&fs.ModeSocket != 0:
		return nil, fmt.Errorf("archive/tar: sockets not supported")
	default:
		h.Typeflag = tar.TypeReg
		h.Name = files.AsExplicitRelativePath(content.Destination)
		h.Size = content.Size()
	}

	if fm&fs.ModeSetuid != 0 {
		h.Mode |= ISUID
	}
	if fm&fs.ModeSetgid != 0 {
		h.Mode |= ISGID
	}
	if fm&fs.ModeSticky != 0 {
		h.Mode |= ISVTX
	}

	return h, nil
}
