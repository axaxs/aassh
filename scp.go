// Copyright (c) 2015, Alex A Skinner
// see LICENSE file

package aassh

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func permString(f *os.File) string {
	fileStat, err := f.Stat()
	if err != nil {
		return "0644"
	}
	return fmt.Sprintf("%#o", fileStat.Mode().Perm())
}

// PushBytes is used to push bytes from memory without writing a file first.
// dest should be the full remote path, and perms a typical permission string - 
// eg "0644"
func (c *SSHClient) PushBytes(b []byte, dest, perms string) error {
	sess, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	errchan := make(chan error, 1)
	go func() {
		stdin, err := sess.StdinPipe()
		if err != nil {
			errchan <- err
			return
		}
		defer stdin.Close()
		toSend := fmt.Sprintf("C%s %d %s", perms, len(b), filepath.Base(dest))
		_, err = fmt.Fprintln(stdin, toSend)
		if err != nil {
			errchan <- err
			return
		}
		_, err = stdin.Write(b)
		if err != nil {
			errchan <- err
			return
		}
		_, err = fmt.Fprint(stdin, "\x00")
		errchan <- err

	}()
	err = sess.Run(fmt.Sprintf("/usr/bin/scp -qrt \"%s\"", filepath.Dir(dest)))
	if err != nil {
		procerr, err2 := ioutil.ReadAll(stdout)
		if err2 != nil {
			return err2
		}
		if len(procerr) > 0 {
			return fmt.Errorf(string(procerr))
		}
		return err
	}
	err = <-errchan
	if err != nil {
		return err
	}
	return nil
}

// PushFile sends local file src to remote host to file/folder dest.
// If preserve is set, timestamps are preserved.
func (c *SSHClient) PushFile(src, dest string, preserve bool) error {
	flags := "qrt"
	if preserve {
		flags = "p" + flags
	}
	sess, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	errchan := make(chan error, 1)
	go func() {
		stdin, err := sess.StdinPipe()
		if err != nil {
			errchan <- err
			return
		}
		defer stdin.Close()
		errchan <- writeFile(stdin, src, dest, preserve)

	}()
	err = sess.Run(fmt.Sprintf("/usr/bin/scp -%s \"%s\"", flags, filepath.Dir(dest)))
	if err != nil {
		procerr, err2 := ioutil.ReadAll(stdout)
		if err2 != nil {
			return err2
		}
		if len(procerr) > 0 {
			return fmt.Errorf(string(procerr))
		}
		return err
	}
	err = <-errchan
	if err != nil {
		return err
	}
	return nil
}

// PushDir sends local folder src to remote host to folder dest.
// If preserve is set, timestamps are kept.
func (c *SSHClient) PushDir(src string, dest string, preserve bool) error {
	flags := "qrt"
	if preserve {
		flags = "p" + flags
	}
	sess, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	errchan := make(chan error, 1)
	go func() {
		stdin, err := sess.StdinPipe()
		if err != nil {
			errchan <- err
			return
		}
		defer stdin.Close()
		folderSrc, err := os.Open(src)
		if err != nil {
			errchan <- err
			return
		}
		defer folderSrc.Close()
		if preserve {
			stats, err := folderSrc.Stat()
			if err != nil {
				errchan <- err
			}
			ts := fmt.Sprintf("%d", stats.ModTime().Unix())
			toSend := fmt.Sprintf("T%s 0 %s 0", ts, ts)
			_, err = fmt.Fprintln(stdin, toSend)
			if err != nil {
				errchan <- err
			}
		}
		toSend := fmt.Sprintf("D%s 0 %s", permString(folderSrc), filepath.Base(dest))
		_, err = fmt.Fprintln(stdin, toSend)
		if err != nil {
			errchan <- err
			return
		}
		err = walkDir(stdin, src, preserve)
		if err != nil {
			errchan <- err
			return
		}
		_, err = fmt.Fprintln(stdin, "E")
		errchan <- err

	}()
	err = sess.Run(fmt.Sprintf("/usr/bin/scp -%s \"%s\"", flags, filepath.Dir(dest)))
	if err != nil {
		procerr, err2 := ioutil.ReadAll(stdout)
		if err2 != nil {
			return err2
		}
		if len(procerr) > 0 {
			return fmt.Errorf(string(procerr))
		}
		return err
	}
	err = <-errchan
	if err != nil {
		return err
	}
	return nil

}

func writeFile(w io.WriteCloser, src, dest string, preserve bool) error {
	fileSrc, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fileSrc.Close()
	srcStat, err := fileSrc.Stat()
	if err != nil {
		return err
	}
	if preserve {
		ts := fmt.Sprintf("%d", srcStat.ModTime().Unix())
		toSend := fmt.Sprintf("T%s 0 %s 0", ts, ts)
		_, err = fmt.Fprintln(w, toSend)
		if err != nil {
			return err
		}
	}
	toSend := fmt.Sprintf("C%s %d %s", permString(fileSrc), srcStat.Size(), filepath.Base(dest))
	_, err = fmt.Fprintln(w, toSend)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, fileSrc)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(w, "\x00")
	return err
}

func makeTS(ts string) (time.Time, time.Time, error) {
	var mtime, atime time.Time
	if len(ts) > 0 {
		spts := strings.Split(ts, " ")
		if len(spts) < 4 {
			return mtime, atime, fmt.Errorf("Length of timestamp line must be 4, got %d", len(spts))
		}
		if len(spts[0]) < 2 {
			return mtime, atime, fmt.Errorf("Invalid MTIME given - %s", spts[0])
		}
		mtime64, err := strconv.ParseInt(spts[0][1:], 10, 64)
		if err != nil {
			return mtime, atime, err
		}
		mtime = time.Unix(mtime64, 0)
		atime64, err := strconv.ParseInt(spts[2], 10, 64)
		if err != nil {
			return mtime, atime, err
		}
		atime = time.Unix(atime64, 0)
	}
	return mtime, atime, nil
}

func handleFile(b *bufio.Reader, ln, dest, ts string) error {
	spln := strings.Split(ln, " ")
	if len(spln) != 3 {
		return fmt.Errorf("Length of create must be 3, got %d", len(spln))
	}
	if len(spln[0]) != 5 {
		return fmt.Errorf("Length of create header must be 5, C####.  Got %s", spln[0])
	}
	mode, err := strconv.ParseUint(spln[0][1:], 8, 32)
	if err != nil {
		return err
	}
	fimode := os.FileMode(mode)
	fisize, err := strconv.Atoi(spln[1])
	if err != nil {
		return err
	}
	finame := dest
	dstf, err := os.Stat(dest)
	if err == nil {
		if dstf.IsDir() {
			finame = dest + "/" + spln[2]
		}
	}
	mtime, atime, err := makeTS(ts)
	if err != nil {
		return err
	}
	byt := make([]byte, fisize)
	_, err = b.Read(byt)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(finame, os.O_WRONLY|os.O_CREATE, fimode)
	if err != nil {
		return err
	}
	_, err = f.Write(byt)
	if err != nil {
		f.Close()
		return err
	}
	f.Close()
	if len(ts) > 0 {
		err = os.Chtimes(finame, atime, mtime)
		if err != nil {
			return err
		}
	}
	_, _ = b.Read([]byte{'0'})
	return nil
}

func handleDir(ln, ts, dest string) (string, error) {
	spln := strings.Split(ln, " ")
	if len(spln) != 3 {
		return "", fmt.Errorf("Length of directory must be 3, got %d", len(spln))
	}
	if len(spln[0]) != 5 {
		return "", fmt.Errorf("Length of directory header must be 5, D####.  Got %s", spln[0])
	}
	mode, err := strconv.ParseUint(spln[0][1:], 8, 32)
	if err != nil {
		return "", err
	}
	fimode := os.FileMode(mode)
	mtime, atime, err := makeTS(ts)
	if err != nil {
		return "", err
	}
	dirname := dest
	st, err := os.Stat(dest)
	if err != nil {
		dirname = dest
	} else {
		if st.IsDir() {
			dirname = dest + "/" + spln[2]
		}
	}
	err = os.MkdirAll(dirname, fimode)
	if err != nil {
		return "", err
	}
	if len(ts) > 0 {
		err = os.Chtimes(dirname, atime, mtime)
		if err != nil {
			return "", err
		}
	}
	return dirname, nil
}

func handleIncoming(w io.WriteCloser, r io.Reader, rr io.Reader, dest string) error {
	bufr := bufio.NewReader(r)
	_, err := fmt.Fprint(w, "\x00")
	if err != nil {
		return err
	}
	ts := ""
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(dest, "/") {
		dest = cwd + "/" + dest
	}
	for ln, err := bufr.ReadString('\n'); err == nil; ln, err = bufr.ReadString('\n') {
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return err
		}
		ln = strings.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		_, err = fmt.Fprint(w, "\x00")
		if err != nil {
			return err
		}
		switch ln[0] {
		case 'C':
			err = handleFile(bufr, ln, dest, ts)
			if err != nil {
				return err
			}
			ts = ""
		case 'T':
			ts = ln
		case 'D':
			dest, err = handleDir(ln, ts, dest)
			if err != nil {
				return err
			}
			ts = ""
		case 'E':
			spldest := strings.Split(strings.TrimRight(dest, "/"), "/")
			dest = strings.Join(spldest[:len(spldest)-1], "/")
			ts = ""
		}
		_, err = fmt.Fprint(w, "\x00")
		if err != nil {
			return err
		}
	}
	return err
}

func walkDir(w io.WriteCloser, dir string, preserve bool) error {
	fi, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, f := range fi {
		if f.IsDir() {
			folderSrc, err := os.Open(dir + "/" + f.Name())
			if err != nil {
				return err
			}
			if preserve {
				stats, err := folderSrc.Stat()
				if err != nil {
					return err
				}
				ts := fmt.Sprintf("%d", stats.ModTime().Unix())
				toSend := fmt.Sprintf("T%s 0 %s 0", ts, ts)
				_, err = fmt.Fprintln(w, toSend)
				if err != nil {
					return err
				}
			}
			toSend := fmt.Sprintf("D%s 0 %s", permString(folderSrc), f.Name())
			_, err = fmt.Fprintln(w, toSend)
			if err != nil {
				return err
			}
			err = walkDir(w, dir+"/"+f.Name(), preserve)
			if err != nil {
				return err
			}
			fmt.Fprintln(w, "E")
		} else {
			err = writeFile(w, dir+"/"+f.Name(), f.Name(), preserve)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Receive receives a file or folder from remote host at location src, and
// writes it to local machine as dest.
func (c *SSHClient) Receive(src, dest string) error {
	sess, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	errchan := make(chan error, 1)
	go func() {
		stdout, err := sess.StdoutPipe()
		stdin, err := sess.StdinPipe()
		stderr, err := sess.StderrPipe()
		if err != nil {
			errchan <- err
			return
		}
		defer stdin.Close()
		errchan <- handleIncoming(stdin, stdout, stderr, dest)
	}()
	err = sess.Run(fmt.Sprintf("/usr/bin/scp -qrf \"%s\"", src))
	if err != nil {
		return err
	}
	err = <-errchan
	if err != nil {
		return err
	}
	return nil
}
