// Copyright (c) 2015, Alex A Skinner
// see LICENSE file

// Package aassh provides a wrapper around go.crypto/ssh to keep a stateful tcp
// connection alive so that one may send multiple commands without needing to
// reconnect.  Additionally, one may send or receive files over scp in the same
// session without reconnecting.

package aassh

import (
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"io/ioutil"
	"os/user"
)

type SSHClient struct {
	client *ssh.Client
}

// getKey tries to grab /home/user/ssh/id_rsa first, then id_dsa, else fails
func getKey(filename string) (ssh.Signer, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	var b []byte
	b, err = ioutil.ReadFile(usr.HomeDir + "/.ssh/" + filename)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// RunCmd runs the command given on the host to which the connection is
// currently established.  It returns stdout, stderr, and an error.
func (c *SSHClient) RunCmd(command string) (string, string, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()
	var b bytes.Buffer
	var e bytes.Buffer
	sess.Stdout = &b
	sess.Stderr = &e
	err = sess.Run(command)
	if err != nil {
		return b.String(), e.String(), err
	}
	return b.String(), e.String(), nil
}

// Close closes the remote connection.
func (c *SSHClient) Close() error {
	return c.client.Close()
}

// NewSSHClient returns a new SSHClient object.
// hostport should be in format server.name:22
// password is optional.  it is tried instead of keys if not blank
func NewSSHClient(username, password, hostport string) (*SSHClient, error) {
	var client *ssh.Client
	var err error
	var key ssh.Signer
	if password != "" {
		cfg := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{ssh.Password(password)},
		}
		client, err = ssh.Dial("tcp", hostport, cfg)
		if err != nil {
			return nil, err
		}

		return &SSHClient{client: client}, nil
	}

	for _, v := range []string{"id_rsa", "id_dsa"} {
		key, err = getKey(v)
		if err != nil {
			continue
		}
		cfg := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
		}
		client, err = ssh.Dial("tcp", hostport, cfg)
		if err != nil {
			continue
		}
		break
	}

	if err != nil {
		return nil, err
	}

	return &SSHClient{client: client}, nil
}
