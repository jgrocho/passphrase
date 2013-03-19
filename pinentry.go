package passphrase

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var (
	errPinEntryNotOK = fmt.Errorf("did not receive OK from pinentry")
	errPinEntryRead  = fmt.Errorf("could not read from pinentry")
	errPinEntrySend  = fmt.Errorf("could not send to pinentry")
)

type pinEntry struct{}

func (entry *pinEntry) clearCachedPassphrase(cachedId string) {
	return
}

func (entry *pinEntry) getPassphrase(cachedId, prompt, description, errorMsg string, confirm bool) (passphrase string, err error) {
	return "", fmt.Errorf("pinentry: not yet implemented")

	pinentry := exec.Command("pinentry")

	stdout, err := pinentry.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("could not connect to pinentry stdout")
	}
	defer stdout.Close()

	stdin, err := pinentry.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("could not connect to pinentry stdin")
	}
	defer stdin.Close()

	if err := pinentry.Start(); err != nil {
		return "", fmt.Errorf("could not start pinentry")
	}

	br := bufio.NewReader(stdout)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", errPinEntryRead
	}
	if !strings.HasPrefix(line, "OK") {
		return "", errPinEntryNotOK
	}

	sendOK := func(format string, a ...interface{}) error {
		cmd := fmt.Sprintf(format, a...)
		if _, err := fmt.Fprintf(stdin, cmd); err != nil {
			return errPinEntrySend
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return errPinEntryRead
		}
		if !strings.HasPrefix(line, "OK") {
			return errPinEntryNotOK
		}
		return nil
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

	if err := sendOK("SETPROMPT %s\n", prompt); err != nil {
		return "", err
	}
	if err := sendOK("SETDESC %s\n", description); err != nil {
		return "", err
	}
	if err := sendOK("SETERROR %s\n", errorMsg); err != nil {
		return "", err
	}

	_, err = fmt.Fprintf(stdin, "GETPIN\n")
	if err != nil {
		return "", errPinEntrySend
	}
	line, err = br.ReadString('\n')
	if err != nil {
		return "", errPinEntryRead
	}

	if strings.HasPrefix(line, "D ") {
		return line[2:len(line)-1], nil
	} else if strings.HasPrefix(line, "ERR 67108922") || strings.HasPrefix(line, "OK") {
		return "", ErrNoData
	} else if strings.HasPrefix(line, "ERR 83886179") {
		return "", ErrUserCancel
	}

	return "", fmt.Errorf("pinEntry: not yet implemented")
}
