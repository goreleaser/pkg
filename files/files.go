package files

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goreleaser/nfpm/v2/internal/glob"
)

const (
	// TypeFile is the type of a regular file. This is also the type that is
	// implied when no type is specified.
	TypeFile = "file"
	// TypeDir is the type of a directory that is explicitly added in order to
	// declare ownership or non-standard permission.
	TypeDir = "dir"
	/// TypeImplicitDir is the type of a directory that is implicitly added as a
	//parent of a file.
	TypeImplicitDir = "implicit dir"
	// TypeTree is the type of a whole directory tree structure.
	TypeTree = "tree"
	// TypeSymlink is the type of a symlink that is created at the destination
	// path and points to the source path.
	TypeSymlink = "symlink"
	// TypeConfig is the type of a configuration file that may be changed by the
	// user of the package.
	TypeConfig = "config"
	// TypeConfigNoReplace is like TypeConfig with an added noreplace directive
	// that is respected by RPM-based distributions.
	// For all other package formats it is handled exactly like TypeConfig.
	TypeConfigNoReplace = "config|noreplace"
	// TypeConfigMissingOK is like TypeConfig with an added missingok directive
	// that is respected by RPM-based distributions.
	// For all other package formats it is handled exactly like TypeConfig.
	TypeConfigMissingOK = "config|missingok"
	// TypeGhost is the type of an RPM ghost file which is ignored by other packagers.
	TypeRPMGhost = "ghost"
	// TypeRPMDoc is the type of an RPM doc file which is treated as a regular file by other packagers.
	TypeRPMDoc = "doc"
	// TypeRPMLicence is the type of an RPM licence file which is treated as a regular file by other packagers.
	TypeRPMLicence = "licence"
	// TypeRPMLicense a different spelling of TypeRPMLicence.
	TypeRPMLicense = "license"
	// TypeRPMReadme is the type of an RPM readme file which is treated as a regular file by other packagers.
	TypeRPMReadme = "readme"
	// TypeDebChangelog is the type of a Debian changelog archive file which is
	// ignored by other packagers. This type should never be set for a content
	// entry as it is automatically added when a changelog is configred.
	TypeDebChangelog = "debian changelog"
)

// Content describes the source and destination
// of one file to copy into a package.
type Content struct {
	Source      string           `yaml:"src,omitempty" json:"src,omitempty"`
	Destination string           `yaml:"dst" json:"dst"`
	Type        string           `yaml:"type,omitempty" json:"type,omitempty" jsonschema:"enum=symlink,enum=ghost,enum=config,enum=config|noreplace,enum=dir,enum=tree,enum=,default="`
	Packager    string           `yaml:"packager,omitempty" json:"packager,omitempty"`
	FileInfo    *ContentFileInfo `yaml:"file_info,omitempty" json:"file_info,omitempty"`
	Expand      bool             `yaml:"expand,omitempty" json:"expand,omitempty"`
}

type ContentFileInfo struct {
	Owner string      `yaml:"owner,omitempty" json:"owner,omitempty"`
	Group string      `yaml:"group,omitempty" json:"group,omitempty"`
	Mode  os.FileMode `yaml:"mode,omitempty" json:"mode,omitempty"`
	MTime time.Time   `yaml:"mtime,omitempty" json:"mtime,omitempty"`
	Size  int64       `yaml:"-" json:"-"`
}

// Contents list of Content to process.
type Contents []*Content

func (c Contents) Len() int {
	return len(c)
}

func (c Contents) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c Contents) Less(i, j int) bool {
	a, b := c[i], c[j]

	if a.Destination != b.Destination {
		return a.Destination < b.Destination
	}

	if a.Type != b.Type {
		return a.Type < b.Type
	}

	return a.Packager < b.Packager
}

func (c Contents) ContainsDestination(dst string) bool {
	for _, content := range c {
		if strings.TrimRight(content.Destination, "/") == strings.TrimRight(dst, "/") {
			return true
		}
	}

	return false
}

func (c *Content) WithFileInfoDefaults(umask fs.FileMode, mtime time.Time) *Content {
	cc := &Content{
		Source:      c.Source,
		Destination: c.Destination,
		Type:        c.Type,
		Packager:    c.Packager,
		FileInfo:    c.FileInfo,
	}
	if cc.Type == "" {
		cc.Type = TypeFile
	}
	if cc.FileInfo == nil {
		cc.FileInfo = &ContentFileInfo{}
	}
	if cc.FileInfo.Owner == "" {
		cc.FileInfo.Owner = "root"
	}
	if cc.FileInfo.Group == "" {
		cc.FileInfo.Group = "root"
	}
	if (cc.Type == TypeDir || cc.Type == TypeImplicitDir) && cc.FileInfo.Mode == 0 {
		cc.FileInfo.Mode = 0o755
	}
	if cc.FileInfo.MTime.IsZero() {
		cc.FileInfo.MTime = mtime
	}

	// determine if we still need info
	fileInfoAlreadyComplete := (!cc.FileInfo.MTime.IsZero() &&
		cc.FileInfo.Mode != 0 &&
		(cc.FileInfo.Size != 0 || (cc.Type == TypeDir || cc.Type == TypeImplicitDir)))

	// only stat source when we actually need more information
	if cc.Source != "" && !fileInfoAlreadyComplete {
		info, err := os.Stat(cc.Source)
		if err == nil {
			if cc.FileInfo.MTime.IsZero() {
				cc.FileInfo.MTime = info.ModTime()
			}
			if cc.FileInfo.Mode == 0 {
				cc.FileInfo.Mode = info.Mode() &^ umask
			}
			cc.FileInfo.Size = info.Size()
		}
	}

	if cc.FileInfo.MTime.IsZero() {
		cc.FileInfo.MTime = mtime
	}
	return cc
}

// Name to part of the os.FileInfo interface
func (c *Content) Name() string {
	return c.Source
}

// Size to part of the os.FileInfo interface
func (c *Content) Size() int64 {
	return c.FileInfo.Size
}

// Mode to part of the os.FileInfo interface
func (c *Content) Mode() os.FileMode {
	return c.FileInfo.Mode
}

// ModTime to part of the os.FileInfo interface
func (c *Content) ModTime() time.Time {
	return c.FileInfo.MTime
}

// IsDir to part of the os.FileInfo interface
func (c *Content) IsDir() bool {
	return c.Type == TypeDir || c.Type == TypeImplicitDir
}

// Sys to part of the os.FileInfo interface
func (c *Content) Sys() interface{} {
	return nil
}

func (c *Content) String() string {
	var properties []string
	if c.Source != "" {
		properties = append(properties, "src="+c.Source)
	}
	if c.Destination != "" {
		properties = append(properties, "dst="+c.Destination)
	}
	if c.Type != "" {
		properties = append(properties, "type="+c.Type)
	}
	if c.Packager != "" {
		properties = append(properties, "packager="+c.Packager)
	}
	if c.FileInfo != nil {
		if c.FileInfo.Owner != "" {
			properties = append(properties, "owner="+c.FileInfo.Owner)
		}
		if c.FileInfo.Group != "" {
			properties = append(properties, "group="+c.FileInfo.Group)
		}
		if c.Mode() != 0 {
			properties = append(properties, "mode="+c.Mode().String())
		}
		if !c.ModTime().IsZero() {
			properties = append(properties, "modtime="+c.ModTime().String())
		}
		properties = append(properties, "size="+strconv.Itoa(int(c.FileInfo.Size)))
	}

	return fmt.Sprintf("Content(%s)", strings.Join(properties, ","))
}

// PrepareForPackager performs the following steps to prepare the contents for
// the provided packager:
//
//   - It filters out content that is irrelevant for the specified packager
//   - It expands globs (if enabled) and file trees
//   - It adds implicit directories (parent directories of files)
//   - It adds ownership and other file information if not specified directly
//   - It applies the given umask if the file does not have a specific mode
//   - It normalizes content source paths to be unix style paths
//   - It normalizes content destination paths to be absolute paths with a trailing
//     slash if the entry is a directory
//
// If no packager is specified, only the files that are relevant for any
// packager are considered.
func PrepareForPackager(
	rawContents Contents,
	umask fs.FileMode,
	packager string,
	disableGlobbing bool,
	mtime time.Time,
) (Contents, error) {
	contentMap := make(map[string]*Content)

	for _, content := range rawContents {
		if !isRelevantForPackager(packager, content) {
			continue
		}

		switch content.Type {
		case TypeDir:
			// implicit directories at the same destination can just be overwritten
			presentContent, destinationOccupied := contentMap[NormalizeAbsoluteDirPath(content.Destination)]
			if destinationOccupied && presentContent.Type != TypeImplicitDir {
				return nil, contentCollisionError(content, presentContent)
			}

			err := addParents(contentMap, content.Destination, mtime)
			if err != nil {
				return nil, err
			}

			cc := content.WithFileInfoDefaults(umask, mtime)
			cc.Source = ToNixPath(cc.Source)
			cc.Destination = NormalizeAbsoluteDirPath(cc.Destination)
			contentMap[cc.Destination] = cc
		case TypeImplicitDir:
			// if there's an implicit directory, the contents probably already
			// have been expanded so we can just ignore it, it will be created
			// by another content element again anyway
		case TypeRPMGhost, TypeSymlink, TypeRPMDoc, TypeRPMLicence, TypeRPMLicense, TypeRPMReadme, TypeDebChangelog:
			presentContent, destinationOccupied := contentMap[NormalizeAbsoluteFilePath(content.Destination)]
			if destinationOccupied {
				return nil, contentCollisionError(content, presentContent)
			}

			err := addParents(contentMap, content.Destination, mtime)
			if err != nil {
				return nil, err
			}

			cc := content.WithFileInfoDefaults(umask, mtime)
			cc.Source = ToNixPath(cc.Source)
			cc.Destination = NormalizeAbsoluteFilePath(cc.Destination)
			contentMap[cc.Destination] = cc
		case TypeTree:
			err := addTree(contentMap, content, umask, mtime)
			if err != nil {
				return nil, fmt.Errorf("add tree: %w", err)
			}
		case TypeConfig, TypeConfigNoReplace, TypeConfigMissingOK, TypeFile, "":
			globbed, err := glob.Glob(
				filepath.ToSlash(content.Source),
				filepath.ToSlash(content.Destination),
				disableGlobbing,
			)
			if err != nil {
				return nil, err
			}

			if err := addGlobbedFiles(contentMap, globbed, content, umask, mtime); err != nil {
				return nil, fmt.Errorf("add globbed files from %q: %w", content.Source, err)
			}
		default:
			return nil, fmt.Errorf("invalid content type: %s", content.Type)
		}
	}

	res := make(Contents, 0, len(contentMap))

	for _, content := range contentMap {
		res = append(res, content)
	}

	sort.Sort(res)

	return res, nil
}

func isRelevantForPackager(packager string, content *Content) bool {
	if packager == "" {
		return true
	}

	if content.Packager != "" && content.Packager != packager {
		return false
	}

	// Intentionally pass through TypeRPMDoc, TypeRPMLicen[cs]e, and TypeRPMReadme.
	// It's convenient to install them without the extra type info with other packagers,
	// instead of having to duplicate the entries in config without the type info.
	if packager != "rpm" && content.Type == TypeRPMGhost {
		return false
	}

	if packager != "deb" && content.Type == TypeDebChangelog {
		return false
	}

	return true
}

func addParents(contentMap map[string]*Content, path string, mtime time.Time) error {
	for _, parent := range sortedParents(path) {
		parent = NormalizeAbsoluteDirPath(parent)
		// check for content collision and just overwrite previously created
		// implicit directories
		c, ok := contentMap[parent]
		if ok {
			// either we already created this directory as an explicit directory
			// or as an implicit directory of another file
			if c.Type == TypeDir || c.Type == TypeImplicitDir {
				continue
			}

			return contentCollisionError(&Content{
				Type:        "parent directory for " + path,
				Destination: parent,
			}, c)
		}

		contentMap[parent] = &Content{
			Destination: parent,
			Type:        TypeImplicitDir,
			FileInfo: &ContentFileInfo{
				Owner: "root",
				Group: "root",
				Mode:  0o755,
				MTime: mtime,
			},
		}
	}

	return nil
}

func sortedParents(dst string) []string {
	paths := []string{}
	base := strings.Trim(dst, "/")
	for {
		base = filepath.Dir(base)
		if base == "." {
			break
		}
		paths = append(paths, ToNixPath(base))
	}

	// reverse in place
	for i := len(paths)/2 - 1; i >= 0; i-- {
		oppositeIndex := len(paths) - 1 - i
		paths[i], paths[oppositeIndex] = paths[oppositeIndex], paths[i]
	}

	return paths
}

func addGlobbedFiles(
	all map[string]*Content,
	globbed map[string]string,
	origFile *Content,
	umask fs.FileMode,
	mtime time.Time,
) error {
	for src, dst := range globbed {
		dst = NormalizeAbsoluteFilePath(dst)
		presentContent, destinationOccupied := all[dst]
		if destinationOccupied {
			c := *origFile
			c.Destination = dst
			return contentCollisionError(&c, presentContent)
		}

		if err := addParents(all, dst, mtime); err != nil {
			return err
		}

		// if the file has a FileInfo, we need to copy it but recalculate its size
		newFileInfo := origFile.FileInfo
		if newFileInfo != nil {
			newFileInfoVal := *newFileInfo
			newFileInfoVal.Size = 0
			newFileInfo = &newFileInfoVal
		}

		newFile := (&Content{
			Destination: NormalizeAbsoluteFilePath(dst),
			Source:      ToNixPath(src),
			Type:        origFile.Type,
			FileInfo:    newFileInfo,
			Packager:    origFile.Packager,
		}).WithFileInfoDefaults(umask, mtime)
		if dst, err := os.Readlink(src); err == nil {
			newFile.Source = dst
			newFile.Type = TypeSymlink
		}

		all[dst] = newFile
	}

	return nil
}

func addTree(
	all map[string]*Content,
	tree *Content,
	umask os.FileMode,
	mtime time.Time,
) error {
	if tree.Destination != "/" && tree.Destination != "" {
		presentContent, destinationOccupied := all[NormalizeAbsoluteDirPath(tree.Destination)]
		if destinationOccupied && presentContent.Type != TypeImplicitDir {
			return contentCollisionError(tree, presentContent)
		}
	}

	err := addParents(all, tree.Destination, mtime)
	if err != nil {
		return err
	}

	return filepath.WalkDir(tree.Source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(tree.Source, path)
		if err != nil {
			return err
		}

		destination := filepath.Join(tree.Destination, relPath)

		c := &Content{
			FileInfo: &ContentFileInfo{},
		}
		if tree.FileInfo != nil && !ownedByFilesystem(tree.Destination) {
			c.FileInfo.Owner = tree.FileInfo.Owner
			c.FileInfo.Group = tree.FileInfo.Group
		}

		switch {
		case d.IsDir():
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("get directory information: %w", err)
			}

			c.Type = TypeDir
			c.Destination = NormalizeAbsoluteDirPath(destination)
			c.FileInfo.Mode = info.Mode() &^ umask
			c.FileInfo.MTime = info.ModTime()
			if ownedByFilesystem(c.Destination) {
				c.Type = TypeImplicitDir
			}
		case d.Type()&os.ModeSymlink != 0:
			linkDestination, err := os.Readlink(path)
			if err != nil {
				return err
			}

			c.Type = TypeSymlink
			c.Source = filepath.ToSlash(strings.TrimPrefix(linkDestination, filepath.VolumeName(linkDestination)))
			c.Destination = NormalizeAbsoluteFilePath(destination)
		default:
			c.Type = TypeFile
			c.Source = path
			c.Destination = NormalizeAbsoluteFilePath(destination)
			c.FileInfo.Mode = d.Type() &^ umask
		}

		if tree.FileInfo != nil && tree.FileInfo.Mode != 0 && c.Type != TypeSymlink {
			c.FileInfo.Mode = tree.FileInfo.Mode
		}

		all[c.Destination] = c.WithFileInfoDefaults(umask, mtime)

		return nil
	})
}

var ErrContentCollision = fmt.Errorf("content collision")

func contentCollisionError(newc *Content, present *Content) error {
	var presentSource string
	if present.Source != "" {
		presentSource = " with source " + present.Source
	}

	return fmt.Errorf("adding %s at destination %s: "+
		"%s%s is already present at this destination: %w",
		newc.Type, newc.Destination, present.Type, presentSource, ErrContentCollision,
	)
}

// ToNixPath converts the given path to a nix-style path.
//
// Windows-style path separators are considered escape
// characters by some libraries, which can cause issues.
func ToNixPath(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

// As relative path converts a path to an explicitly relative path starting with
// a dot (e.g. it converts /foo -> ./foo and foo -> ./foo).
func AsExplicitRelativePath(path string) string {
	return "./" + AsRelativePath(path)
}

// AsRelativePath converts a path to a relative path without a "./" prefix. This
// function leaves trailing slashes to indicate that the path refers to a
// directory, and converts the path to Unix path.
func AsRelativePath(path string) string {
	cleanedPath := strings.TrimLeft(ToNixPath(path), "/")
	if len(cleanedPath) > 1 && strings.HasSuffix(path, "/") {
		return cleanedPath + "/"
	}
	return cleanedPath
}

// NormalizeAbsoluteFilePath returns an absolute cleaned path separated by
// slashes.
func NormalizeAbsoluteFilePath(src string) string {
	return ToNixPath(filepath.Join("/", src))
}

// normalizeFirPath is linke NormalizeAbsoluteFilePath with a trailing slash.
func NormalizeAbsoluteDirPath(path string) string {
	return NormalizeAbsoluteFilePath(strings.TrimRight(path, "/")) + "/"
}
