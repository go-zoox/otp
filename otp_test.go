package otp

import (
	"testing"

	"github.com/go-zoox/fetch"
)

func TestOTP(t *testing.T) {
	otp := &OTP{}
	secret := otp.Secret()
	token := otp.Token()
	if !otp.Verify(secret, token) {
		t.Errorf("Verify failed")
	}
}

func TestOTPWithRemote(t *testing.T) {
	otp := New()
	secret := otp.Secret()

	remote, err := fetch.Get("https://httpbin.zcorky.com/2fa", &fetch.Config{
		Query: map[string]string{
			"secret": secret,
		},
	})
	if err != nil {
		t.Error(err)
	}

	if remote.Get("token").String() != otp.Token() {
		t.Errorf("Token expect %s, but got %s", remote.Get("token"), otp.Token())
	}
}

func TestOTPWithCustomSecret(t *testing.T) {
	secret := "GAXGK3L2OJRGI2LS"
	otp := New(secret)

	if !otp.Verify(secret, otp.Token()) {
		t.Errorf("Verify failed")
	}

	remote, err := fetch.Get("https://httpbin.zcorky.com/2fa", &fetch.Config{
		Query: map[string]string{
			"secret": secret,
		},
	})
	if err != nil {
		t.Error(err)
	}

	if remote.Get("token").String() != otp.Token() {
		t.Errorf("Token expect %s, but got %s", remote.Get("token"), otp.Token())
	}
}
