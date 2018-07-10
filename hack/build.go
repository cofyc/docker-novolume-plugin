package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"
)

func runCommand(pwd string, command string, cmdArgs ...string) error {
	cmd := exec.Command(command, cmdArgs...)
	if len(pwd) != 0 {
		cmd.Dir = pwd
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

type build struct {
	Package       string
	Version       string
	Revision      string
	DistroName    string
	Arch          string
	BinaryURLBase string
}

func (b *build) run() error {
	dstdir, err := ioutil.TempDir(os.TempDir(), "debs")
	if err != nil {
		return err
	}
	if !optKeepTemp {
		defer os.RemoveAll(dstdir)
	}

	if err := os.Mkdir(filepath.Join(dstdir, "debian"), 0755); err != nil {
		return err
	}

	srcdir := filepath.Join(optWorkDir, "debian")
	err = filepath.Walk(srcdir, func(srcfile string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relpath, err := filepath.Rel(srcdir, srcfile)
		if err != nil {
			return err
		}
		if relpath == "." {
			// Ignore root directory.
			return nil
		}
		dstfile := filepath.Join(dstdir, "debian", relpath)
		log.Printf("sync %s to %s", srcfile, dstfile)
		if info.IsDir() {
			return os.Mkdir(dstfile, info.Mode())
		}
		t, err := template.New("").Funcs(builtins).Option("missingkey=error").ParseFiles(srcfile)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(dstfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := t.Templates()[0].Execute(f, b); err != nil {
			return err
		}
		if err := os.Chmod(dstfile, info.Mode()); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Build package.
	err = runCommand(dstdir, "dpkg-buildpackage", "-us", "-uc", "-b", "-a"+b.Arch)
	if err != nil {
		return err
	}

	dstPath := filepath.Join(optWorkDir, "build", b.DistroName, b.Arch)
	err = os.MkdirAll(dstPath, 0755)
	if err != nil {
		return err
	}

	fileName := fmt.Sprintf("%s_%s-%s_%s.deb", b.Package, b.Version, b.Revision, b.Arch)
	err = runCommand(optWorkDir, "mv", filepath.Join("/tmp", fileName), dstPath)
	if err != nil {
		return err
	}

	return nil
}

var (
	optKeepTemp      bool
	optVersion       string
	optPkgRevision   int
	optWorkDir       string
	optBinaryURLBase string
	builtins         = map[string]interface{}{
		"date": func() string {
			return time.Now().Format(time.RFC1123Z)
		},
	}
)

func init() {
	flag.StringVar(&optWorkDir, "work-dir", "", "work dir")
	flag.BoolVar(&optKeepTemp, "keep-tmp", false, "keep tmp dir after build")
	flag.StringVar(&optVersion, "version", "", "version of software")
	flag.IntVar(&optPkgRevision, "pkg-revision", 0, "revision of package")
	flag.StringVar(&optBinaryURLBase, "binary-url-base", "", "binary url base")
}

func main() {
	flag.Parse()

	if optWorkDir == "" {
		optWorkDir, _ = os.Getwd()
	}

	if optBinaryURLBase == "" {
		cwd, _ := os.Getwd()
		optBinaryURLBase = fmt.Sprintf("file://%s", cwd)
	}

	if optVersion == "" {
		log.Printf("error: --version is required")
		flag.Usage()
		return
	}

	b := &build{
		Package:       "docker-novolume-plugin",
		Version:       optVersion,
		Revision:      fmt.Sprintf("%02d", optPkgRevision),
		DistroName:    "xenial",
		Arch:          "amd64",
		BinaryURLBase: optBinaryURLBase,
	}
	if err := b.run(); err != nil {
		log.Fatal(err)
	}
}
