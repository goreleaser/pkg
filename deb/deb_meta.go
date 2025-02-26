package deb

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/internal/sign"
)

const debChangesTemplate = `
{{- /* Mandatory fields */ -}}
Format: 1.8
Date: {{.Date}}
Source: {{.Info.Name}}
Binary: {{.Info.Deb.Metadata.Binary}}
Architecture: {{ if ne .Info.Platform "linux"}}{{ .Info.Platform }}-{{ end }}{{.Info.Arch}}
Version: {{ if .Info.Epoch}}{{ .Info.Epoch }}:{{ end }}{{.Info.Version}}
         {{- if .Info.Prerelease}}~{{ .Info.Prerelease }}{{- end }}
         {{- if .Info.VersionMetadata}}+{{ .Info.VersionMetadata }}{{- end }}
         {{- if .Info.Release}}-{{ .Info.Release }}{{- end }}
Distribution: {{.Info.Deb.Metadata.Distribution}}
{{- if .Info.Deb.Metadata.Urgency }}
Urgency: {{.Info.Deb.Metadata.Urgency}}
{{- end }}
Maintainer: {{.Info.Maintainer}}
{{- if .Info.Deb.Metadata.ChangedBy }}
Changed-By: {{.Info.Deb.Metadata.ChangedBy}}
{{- end }}
Description: {{ multiline .Info.Description }}
{{- range $key, $value := .Info.Deb.Metadata.Fields }}
{{- if $value }}
{{$key}}: {{$value}}
{{- end }}
{{- end }}
Changes:
{{range .Changes}} {{.}}{{end}}
Checksums-Sha256:
{{range .Files}} {{ .Sha256Sum }} {{.Size}} {{.Name}}{{end}}
Checksums-Sha1:
{{range .Files}} {{ .Sha1Sum }} {{.Size}} {{.Name}}{{end}}
Files:
{{range .Files}} {{ .Md5Sum }} {{.Size}} {{.Section}} {{.Priority}} {{.Name}}{{end}}

`

type changesData struct {
	Date    string
	Info    *nfpm.Info
	Changes []string
	Files   []changesFileData
}

type changesFileData struct {
	Name      string
	Size      int
	Section   string
	Priority  string
	Md5Sum    string
	Sha1Sum   string
	Sha256Sum string
}

var now = time.Now

func (d *Deb) ConventionalMetadataFileName(info *nfpm.Info) string {
	target := info.Target

	if target == "" {
		target = d.ConventionalFileName(info)
	}

	return strings.Replace(target, ".deb", ".changes", 1)
}

func (d *Deb) PackageMetadata(metaInfo *nfpm.MetaInfo, w io.Writer) error {
	data, err := createChanges(metaInfo)
	if err != nil {
		return err
	}

	if metaInfo.Info.Deb.Signature.KeyFile == "" {
		_, err = w.Write(data.Bytes())
		return err
	}

	signedData, err := signChanges(data, metaInfo.Info)
	if err != nil {
		return err
	}

	_, err = w.Write(signedData)
	return err
}

func createChanges(info *nfpm.MetaInfo) (*bytes.Buffer, error) {
	data, err := prepareChangesData(info)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)

	if err := writeTemplate("changes", debChangesTemplate, buf, data); err != nil {
		return nil, err
	}

	return buf, nil
}

func prepareChangesData(meta *nfpm.MetaInfo) (*changesData, error) {
	info := meta.Info

	_, err := meta.Package.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(meta.Package)
	if err != nil {
		return nil, err
	}

	return &changesData{
		Date: now().Format(time.RFC1123Z),
		Info: info,
		Changes: []string{
			fmt.Sprintf("%s (%s) %s; urgency=%s\n  * Package created with nFPM",
				info.Name, info.Version, info.Deb.Metadata.Distribution, info.Deb.Metadata.Urgency),
		},
		Files: []changesFileData{
			{
				Name:      filepath.Base(info.Target),
				Size:      buf.Len(),
				Section:   info.Section,
				Priority:  info.Priority,
				Md5Sum:    fmt.Sprintf("%x", md5.Sum(buf.Bytes())),
				Sha1Sum:   fmt.Sprintf("%x", sha1.Sum(buf.Bytes())),
				Sha256Sum: fmt.Sprintf("%x", sha256.Sum256(buf.Bytes())),
			},
		},
	}, nil
}

func signChanges(data *bytes.Buffer, info *nfpm.Info) ([]byte, error) {
	signConfig := info.Deb.Signature
	signature, err := sign.PGPClearSignWithKeyID(data, signConfig.KeyFile, signConfig.KeyPassphrase, signConfig.KeyID)
	if err != nil {
		return nil, &nfpm.ErrSigningFailure{Err: err}
	}
	return signature, nil
}
