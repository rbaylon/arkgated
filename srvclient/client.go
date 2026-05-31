package srvclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	Arkcommand "github.com/rbaylon/arkgated/arkcommand"
	pfconfigmodel "github.com/rbaylon/srvcman/modules/pfconfig/model"
)

type Token struct {
	Name string
	Jwt  string
}

func Enroll(urlbase string, token *string, pf *pfconfigmodel.Pfconfig) error {
	create_url := urlbase + "pfconfig/create"
	query_url := urlbase + "pfconfig/query/" + pf.Router
	client := &http.Client{}
	req, err := http.NewRequest("GET", query_url, nil)
	if err != nil {
		log.Println(err)
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return err
	}
	if res.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		cfg, _ := json.Marshal(pf)
		log.Println("Enrolling...")
		req, err := http.NewRequest("POST", create_url, bytes.NewBuffer(cfg))
		if err != nil {
			log.Println("Failed to POST router", err)
			return err
		}
		log.Println(*token)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
		res, err := client.Do(req)
		if err != nil {
			log.Println(err)
			res.Body.Close()
			return err
		}

		if res.StatusCode != 200 {
			b, err := io.ReadAll(res.Body)
			if err != nil {
				log.Println("Read body error", err)
			}
			log.Println(string(b))
			log.Println("Failed to enroll router", err)
			res.Body.Close()
			return fmt.Errorf("failed to enroll router")
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	log.Println("Enrolled")
	return nil
}

func GetToken(creds string, api_login_url string) (*string, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", api_login_url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", creds))
	res, err := client.Do(req)
	log.Println("StatusCode", res.StatusCode)
	if res.StatusCode != 200 {
		log.Fatalln("API login failed")
		res.Body.Close()
		return nil, fmt.Errorf("api login failed.")
	}
	if err != nil {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return nil, err
	}
	responseData, ioerr := io.ReadAll(res.Body)
	if ioerr != nil {
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return nil, ioerr
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	var t Token
	json.Unmarshal(responseData, &t)
	return &t.Jwt, nil
}

func ExecScripts(cmd *Arkcommand.Arkcmd, outfile string, wt time.Duration) {
	for {
		ret, out := cmd.RunWithOutput()
		if ret == 0 {
			err := os.WriteFile(outfile, out, 0644)
			if err != nil {
				log.Println(err)
			}
		}
		time.Sleep(wt * time.Second)
	}
}

func CheckExpirationWithoutVerify(tokenStr string) (bool, error) {
	parser := jwt.NewParser()
	var claims jwt.MapClaims

	// Parse unverified explicitly skips signature validation
	_, _, err := parser.ParseUnverified(tokenStr, &claims)
	if err != nil {
		return false, err
	}

	// Extract the standard 'exp' claim safely
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return false, fmt.Errorf("failed to get expiration: %w", err)
	}

	if exp == nil {
		return false, fmt.Errorf("exp claim is missing from token")
	}

	// Compare token expiration timestamp with current system time
	isExpired := exp.Before(time.Now())
	return isExpired, nil
}
