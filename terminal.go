package passphrase

import (
	"fmt"
)

type terminal struct{}

func (term *terminal) clearCachedPassphrase(cachedId string) {
	return
}

func (term *terminal) getPassphrase(cachedId, prompt, description, errorMsg string, confirm bool) (passphrase string, err error) {
	return "", fmt.Errorf("terminal: not yet implemented")
}
