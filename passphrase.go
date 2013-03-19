package passphrase

import (
	"fmt"
)
var (
	ErrNoMethod   = fmt.Errorf("passphrase: no suitable passphrase input method found")
	ErrUserCancel = fmt.Errorf("passphrase: passphrase input cancelled by user")
	ErrNoData     = fmt.Errorf("passphrase: no data input by user")
	ErrNoMatch    = fmt.Errorf("passphrase: passphrases did not match")
)

func init() {
	defaultMethods.methods = []passphraseMethod{
		new(gpgAgent),
		//new(pinEntry),
		//new(terminal),
	}
}

type passphraseMethod interface {
	getPassphrase(cachedId, prompt, description, errorMsg string, ask, confirm bool) (passphrase string, err error)
	clearCachedPassphrase(cacheId string)
}

type allMethods struct {
	methods []passphraseMethod
}

var defaultMethods allMethods

/*
func GetPassphrase(prompt, description string) (string, error) {
	return getPassphrase("", prompt, description, "", false)
}

func GetConfirmedPassphrase(prompt, description string) (string, error) {
	return getPassphrase("", prompt, description, "", true)
}

func GetCachedPassphrase(cacheId, prompt, description string) (string, error) {
	return getPassphrase(cacheId, prompt, description, "", false)
}
*/

func GetPassphrase(cacheId, prompt, description, errorMsg string, ask, confirm bool) (string, error) {
	return defaultMethods.GetPassphrase(cacheId, prompt, description, errorMsg, ask, confirm)
}

func (all *allMethods) GetPassphrase(cacheId, prompt, description, errorMsg string, ask, confirm bool) (passphrase string, err error) {
	for _, method := range all.methods {
		passphrase, err = method.getPassphrase(cacheId, prompt, description, errorMsg, ask, confirm)
		if err == nil || err == ErrUserCancel || err == ErrNoData {
			return
		}
	}
	return "", ErrNoMethod
}

func ClearCachedPassphrase(cacheId string) {
	defaultMethods.ClearCachedPassphrase(cacheId)
}

func (all *allMethods) ClearCachedPassphrase(cacheId string) {
	for _, method := range all.methods {
		method.clearCachedPassphrase(cacheId)
	}
}
