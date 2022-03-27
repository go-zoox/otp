package otp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type OTP struct {
	secret string
}

func New(secret ...string) *OTP {
	if len(secret) > 1 {
		panic("secret must be one")
	}

	if len(secret) == 1 {
		return &OTP{secret: secret[0]}
	}

	return &OTP{}
}

func (o *OTP) Token() string {
	// _secret := secret // base32.StdEncoding.EncodeToString([]byte(secret))
	// token, err := totp.GenerateCodeCustom(_secret, time.Now(), totp.ValidateOpts{
	// 	Period:    30,
	// 	Skew:      1,
	// 	Digits:    otp.DigitsSix,
	// 	Algorithm: otp.AlgorithmSHA1,
	// })

	secret := o.Secret()

	token, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		panic(err)
	}

	return token
}

func (o *OTP) Verify(secret, token string) bool {
	return o.Token() == token
}

func (o *OTP) Secret() string {
	if o.secret == "" {
		key, err := totp.Generate(totp.GenerateOpts{
			Period:      30,
			Digits:      otp.DigitsSix,
			Algorithm:   otp.AlgorithmSHA1,
			Issuer:      "Zero",
			AccountName: "Zero Ramdom",
		})

		if err != nil {
			fmt.Println("err:", err)
			return ""
		}

		o.secret = key.Secret()
	}

	return o.secret
}

func (o *OTP) TTL() int {
	return 30 - time.Now().Second()%30
}
