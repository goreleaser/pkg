package deb

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/goreleaser/nfpm/v2"
	"github.com/goreleaser/nfpm/v2/internal/sign"
	"github.com/stretchr/testify/require"
)

func fakeTime() time.Time {
	t, _ := time.Parse(time.RFC1123Z, "Mon, 30 Jan 2023 08:36:31 +0300")
	return t
}

func TestMetaFilename(t *testing.T) {
	info := exampleInfo()

	require.Equal(t, "foo_1.0.0_amd64.changes", Default.ConventionalMetadataFileName(info))
}

func TestMetaFilenameTarget(t *testing.T) {
	info := exampleInfo()
	info.Target = "bar_1.0.0_amd64.deb"

	require.Equal(t, "bar_1.0.0_amd64.changes", Default.ConventionalMetadataFileName(info))
}

func TestMetaFields(t *testing.T) {
	now = fakeTime

	var w bytes.Buffer
	pkg := bytes.NewReader([]byte{1, 2, 3})
	info := nfpm.WithDefaults(&nfpm.Info{
		Name:           "foo",
		Description:    "Foo does things",
		Priority:       "extra",
		Maintainer:     "Carlos A Becker <pkg@carlosbecker.com>",
		Version:        "v1.0.0",
		Section:        "default",
		Homepage:       "http://carlosbecker.com",
		EnableMetadata: true,
		Overridables: nfpm.Overridables{
			Deb: nfpm.Deb{
				Metadata: nfpm.DebMetadata{
					Binary:       "foo",
					Distribution: "unstable",
					Urgency:      "medium",
					ChangedBy:    "Carlos A Becker <pkg@carlosbecker.com>",
					Fields: map[string]string{
						"Bugs":  "https://github.com/goreleaser/nfpm/issues",
						"Empty": "",
					},
				},
			},
		},
	})
	info.Target = Default.ConventionalFileName(info)

	require.NoError(t, Default.PackageMetadata(&nfpm.MetaInfo{
		Info:    info,
		Package: pkg,
	}, &w))
	golden := "testdata/changes.golden"
	if *update {
		require.NoError(t, os.WriteFile(golden, w.Bytes(), 0o600))
	}
	bts, err := os.ReadFile(golden) //nolint:gosec
	require.NoError(t, err)
	require.Equal(t, string(bts), w.String())
}

func TestMetaSignature(t *testing.T) {
	info := exampleInfo()
	info.Target = Default.ConventionalFileName(info)
	info.Deb.Signature.KeyFile = "../internal/sign/testdata/privkey.asc"
	info.Deb.Signature.KeyPassphrase = "hunter2"

	var w bytes.Buffer
	pkg := bytes.NewReader([]byte{1, 2, 3})

	require.NoError(t, Default.PackageMetadata(&nfpm.MetaInfo{
		Info:    info,
		Package: pkg,
	}, &w))

	_, err := sign.PGPReadMessage(w.Bytes(), "../internal/sign/testdata/pubkey.asc")
	require.NoError(t, err)
}

func TestMetaSignatureError(t *testing.T) {
	now = fakeTime
	info := exampleInfo()
	info.Target = Default.ConventionalFileName(info)
	info.Deb.Signature.KeyFile = "/does/not/exist"

	var w bytes.Buffer
	pkg := bytes.NewReader([]byte{1, 2, 3})
	err := Default.PackageMetadata(&nfpm.MetaInfo{
		Info:    info,
		Package: pkg,
	}, &w)
	require.Error(t, err)

	var expectedError *nfpm.ErrSigningFailure
	require.ErrorAs(t, err, &expectedError)
}
