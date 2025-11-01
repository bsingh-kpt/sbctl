package config

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/foxboron/sbctl/logging"
	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

// A type to wrap piv.Yubikey to manage the yubikey handle
type YubikeyReader struct {
	key       *piv.YubiKey
	Overwrite bool
	Pin       string
	PinPrompt bool
}

func (y *YubikeyReader) GetManagementKey() ([]byte, error) {
	var err error
	if err = y.connectToYubikey(); err != nil {
		return nil, err
	}
	if y.Pin == "" && y.PinPrompt {
		y.Pin, err = pinPrompt()
		if err != nil {
			return nil, err
		}
	}
	m, err := y.key.Metadata(y.Pin)
	if err != nil {
		return nil, err
	}
	return *m.ManagementKey, nil
}

func (y *YubikeyReader) GetPIVKeyCert(slot piv.Slot) (*x509.Certificate, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.Certificate(slot)
}

func (y *YubikeyReader) GetPIVAttestationCert(slot piv.Slot) (*x509.Certificate, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.Attest(slot)
}

func (y *YubikeyReader) GenerateKey(key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.GenerateKey(key, slot, opts)
}

func (y *YubikeyReader) PrivateKey(slot piv.Slot, public crypto.PublicKey) (crypto.PrivateKey, error) {
	var err error
	if y.Pin == "" && y.PinPrompt {
		y.Pin, err = pinPrompt()
		if err != nil {
			return nil, err
		}
	}
	auth := piv.KeyAuth{PIN: y.Pin}
	if err := y.connectToYubikey(); err != nil {
		return nil, err
	}
	return y.key.PrivateKey(slot, public, auth)
}

func yubikeyWithTimeout(waitTime time.Duration) (string, error) {
	logging.Println(fmt.Sprintf("Please connect yubikey! Waiting %v seconds...", int(waitTime.Seconds())))
	c := make(chan []string, 1)
	timeout := time.After(waitTime)
	for {
		select {
		case <-time.After(500 * time.Millisecond):
			if newCards, err := piv.Cards(); err == nil && len(newCards) > 0 {
				c <- newCards
				goto end
			}
		case <-timeout:
			// time out
			goto end
		}
	}

end:
	select {
	case cards := <-c:
		if len(cards) != 1 {
			return "", fmt.Errorf("error %d yubikeys connected", len(cards))
		}
		if !strings.Contains(strings.ToLower(cards[0]), "yubikey") {
			return "", fmt.Errorf("invalid piv key connected: %s", cards[0])
		}
		return cards[0], nil
	default:
		return "", fmt.Errorf("timeout waiting for yubikey")
	}
}

func (y *YubikeyReader) connectToYubikey() error {
	if y.key != nil {
		return nil
	}
	card, err := yubikeyWithTimeout(90 * time.Second)
	if err != nil {
		return err
	}

	var yk *piv.YubiKey
	if yk, err = piv.Open(card); err != nil || yk == nil {
		return fmt.Errorf("error opening yubikey: %v", err)
	}

	y.key = yk
	return nil
}

func (y *YubikeyReader) Close() error {
	if y.key != nil {
		return y.key.Close()
	}
	return nil
}

func pinPrompt() (string, error) {
	fmt.Print("Enter PIN: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("yubikey: PIN read failed")
	}

	pin := strings.TrimSpace(string(bytePassword))
	if pin == "" {
		return "", fmt.Errorf("yubikey: no PIN provided")
	}

	return pin, nil
}
