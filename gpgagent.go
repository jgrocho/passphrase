package passphrase

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

var (
	errGpgAgentNotOK = fmt.Errorf("did not receive OK from gpg agent")
	errGpgAgentRead  = fmt.Errorf("could not read from gpg agent")
	errGpgAgentSend  = fmt.Errorf("could not send to gpg agent")
)

type gpgAgent struct{}

func (agent *gpgAgent) findAgent() (io.ReadWriteCloser, error) {
	info := strings.SplitN(os.Getenv("GPG_AGENT_INFO"), ":", 3)
	if len(info) == 0 || len(info[0]) == 0 {
		return nil, fmt.Errorf("no gpg agent running")
	}

	conn, err := net.Dial("unix", info[0])
	if err != nil {
		return nil, err
	}

	return conn, nil
}

type cmdIO struct {
	reader io.ReadCloser
	writer io.WriteCloser
}

func (io *cmdIO) Read(p []byte) (int, error) {
	return io.reader.Read(p)
}

func (io *cmdIO) Write(p []byte) (int, error) {
	return io.writer.Write(p)
}

func (io *cmdIO) Close() error {
	rerr := io.reader.Close()
	werr := io.writer.Close()
	if rerr != nil {
		return rerr
	}
	return werr
}

func (agent *gpgAgent) startAgent() (io.ReadWriteCloser, error) {
	cmd := exec.Command("gpg-agent", "--server")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &cmdIO{stdout, stdin}, nil
}

func (agent *gpgAgent) clearCachedPassphrase(cacheId string) {
	conn, err := agent.findAgent()
	if err != nil {
		return
	}
	defer conn.Close()

	br := bufio.NewReader(conn)
	if buf, err := br.ReadSlice('\n'); err != nil || !bytes.HasPrefix(buf, []byte("OK")) {
		return
	}

	fmt.Fprintf(conn, "CLEAR_PASSPHRASE %s\n", cacheId)
}

func (agent *gpgAgent) getPassphrase(cacheId, prompt, description, errorMsg string, ask, confirm bool) (passphrase string, err error) {
	readWriteCloser, err := agent.findAgent()
	if err != nil {
		readWriteCloser, err = agent.startAgent()
		if err != nil {
			return "", fmt.Errorf("could not use gpg agent")
		}
	}
	defer readWriteCloser.Close()

	br := bufio.NewReader(readWriteCloser)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", errGpgAgentRead
	}
	if !strings.HasPrefix(line, "OK") {
		return "", errGpgAgentNotOK
	}

	sendOK := func(format string, a ...interface{}) error {
		cmd := fmt.Sprintf(format, a...)
		if _, err := fmt.Fprintf(readWriteCloser, cmd); err != nil {
			return errGpgAgentSend
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return errGpgAgentRead
		}
		if !strings.HasPrefix(line, "OK") {
			return errGpgAgentNotOK
		}
		return nil
	}

	if err := sendOK("RESET\n"); err != nil {
		return "", err
	}

	if tty, err := os.Readlink("/proc/self/fd/0"); err != nil {
		if err := sendOK("OPTION ttyname=%s\n", tty); err != nil {
			return "", err
		}
	}
	if term := os.Getenv("TERM"); term != "" {
		if err := sendOK("OPTION ttytype=%s\n", term); err != nil {
			return "", err
		}
	}

	if display := os.Getenv("DISPLAY"); display != "" {
		if err := sendOK("OPTION display=%s\n", display); err != nil {
			return "", err
		}
	}

	if xauthority := os.Getenv("XAUTHORITY"); xauthority != "" {
		if err := sendOK("OPTION xauthority=%s\n", xauthority); err != nil {
			return "", err
		}
	}

	opts := "--data "
	if !ask {
		opts += "--no-ask "
	}
	if confirm {
		if err := sendOK("GETINFO cmd_has_option GET_PASSPHRASE repeat\n"); err != nil && err == errGpgAgentNotOK {
			return "", fmt.Errorf("gpg agent does not support confirmation")
		} else if err != nil {
			return "", err
		}
		opts += "--repeat=1 "
	}

	if cacheId == "" {
		cacheId = "X"
	}
	_, err = fmt.Fprintf(readWriteCloser, "GET_PASSPHRASE %s-- %s %s %s %s\n",
		opts,
		cacheId,
		encodeOrX(errorMsg),
		encodeOrX(prompt),
		encodeOrX(description))
	if err != nil {
		return "", errGpgAgentSend
	}

	var data []byte
	for {
		buffer, err := br.ReadSlice('\n')
		if err != nil {
			return "", errGpgAgentRead
		}

		if bytes.HasPrefix(buffer, []byte("D ")) {
			data = append(data, buffer[2:len(buffer)-1]...)
		} else if bytes.HasPrefix(buffer, []byte("OK")) {
			break
		} else if bytes.HasPrefix(buffer, []byte("ERR 67108922")) {
			return "", ErrNoData
		} else if bytes.HasPrefix(buffer, []byte("ERR 83886179")) {
			return "", ErrUserCancel
		}
	}
	if data != nil {
		return string(data), nil
	}

	return "", fmt.Errorf("gpg agent failed to get passphrase")
}

func encodeOrX(str string) string {
	if str == "" {
		return "X"
	}
	return url.QueryEscape(str)
}
