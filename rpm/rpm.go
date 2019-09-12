// Package rpm implements nfpm.Packager providing .rpm bindings through rpmbuild.
package rpm

import (
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/rpmpack"
	"github.com/goreleaser/nfpm"
	"github.com/goreleaser/nfpm/glob"
	"github.com/pkg/errors"
)

// nolint: gochecknoinits
func init() {
	nfpm.Register("rpm", Default)
}

// Default RPM packager
// nolint: gochecknoglobals
var Default = &RPM{}

// RPM is a RPM packager implementation
type RPM struct{}

// nolint: gochecknoglobals
var archToRPM = map[string]string{
	"amd64": "x86_64",
	"386":   "i386",
	"arm64": "aarch64",
}

func ensureValidArch(info nfpm.Info) nfpm.Info {
	arch, ok := archToRPM[info.Arch]
	if ok {
		info.Arch = arch
	}
	return info
}

// Package writes a new RPM package to the given writer using the given info
func (*RPM) Package(info nfpm.Info, w io.Writer) error {
	info = ensureValidArch(info)
	err := nfpm.Validate(info)
	if err != nil {
		return err
	}

	vInfo := strings.SplitN(info.Version, "-", 2)
	vInfo = append(vInfo, "")
	rpm, err := rpmpack.NewRPM(rpmpack.RPMMetaData{
		Name:    info.Name,
		Description: info.Description,
		Version: vInfo[0],
		Release: vInfo[1],
		Arch:    info.Arch,
		Platform: info.Platform,
		Licence: info.License,
		URL: info.Homepage,
		Vendor: info.Vendor,
		Packager: info.Maintainer,
		Provides: info.Provides,
		Depends: info.Depends,
		Replaces: info.Replaces,
		Suggests: info.Suggests,
		Conflicts: info.Conflicts,
		Compressor: info.RPM.Compression,
	})
	if err != nil {
		return err
	}
	addEmptyDirsRPM(info, rpm)
	if err = createFilesInsideRPM(info, rpm); err != nil {
		return err
	}

	if err = addScriptFiles(info, rpm); err != nil {
		return err
	}

	if err = rpm.Write(w); err != nil {
		return err
	}

	return nil
}

func addScriptFiles(info nfpm.Info, rpm *rpmpack.RPM) error {
	if info.Scripts.PreInstall != "" {
		data, err := ioutil.ReadFile(info.Scripts.PreInstall)
		if err != nil {
			return err
		}
		rpm.AddPrein(string(data))
	}

	if info.Scripts.PreRemove != "" {
		data, err := ioutil.ReadFile(info.Scripts.PreRemove)
		if err != nil {
			return err
		}
		rpm.AddPreun(string(data))
	}

	if info.Scripts.PostInstall != "" {
		data, err := ioutil.ReadFile(info.Scripts.PostInstall)
		if err != nil {
			return err
		}
		rpm.AddPostin(string(data))
	}

	if info.Scripts.PostRemove != "" {
		data, err := ioutil.ReadFile(info.Scripts.PostRemove)
		if err != nil {
			return err
		}
		rpm.AddPostun(string(data))
	}

	return nil
}

func addEmptyDirsRPM(info nfpm.Info, rpm *rpmpack.RPM) {
	for _, dir := range info.EmptyFolders {
		rpm.AddFile(
			rpmpack.RPMFile{
				Name: dir,
				Mode: uint(1 | 040000),
			})
	}
}

func createFilesInsideRPM(info nfpm.Info, rpm *rpmpack.RPM) error {
	copy := func(files map[string]string, config bool) error {
		for srcglob, dstroot := range files {
			globbed, err := glob.Glob(srcglob, dstroot)
			if err != nil {
				return err
			}
			for src, dst := range globbed {
					err := copyToRPM(rpm, src, dst, config)
					if err != nil {
					return err
				}
			}
		}

		return nil
	}
	err := copy(info.Files, false)
	if err != nil {
		return err
	}
	err = copy(info.ConfigFiles, true)
	if err != nil {
		return err
	}
	return nil
}

func copyToRPM(rpm *rpmpack.RPM, src, dst string, config bool) error {
	file, err := os.OpenFile(src, os.O_RDONLY, 0600) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "could not add file to the archive")
	}
	// don't care if it errs while closing...
	defer file.Close() // nolint: errcheck
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.IsDir() {
		// TODO: this should probably return an error
		return nil
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	rpmFile := rpmpack.RPMFile{
		Name: dst,
		Body: data,
		Mode: uint(info.Mode()),
	}

	if config {
		rpmFile.Type = rpmpack.ConfigFile
	}

	rpm.AddFile(rpmFile)

	return nil
}
