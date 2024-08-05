package srvclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	pfconfig "github.com/rbaylon/arkgated/config/pf"
)

type Token struct {
	Name string
	Jwt  string
}

func Enroll(urlbase string, token *string, pf *pfconfig.PfConfig) error {
	create_url := urlbase + "pfconfig/create"
	query_url := urlbase + "pfconfig/query/" + pf.Router
	client := &http.Client{}
	req, _ := http.NewRequest("GET", query_url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
	res, err := client.Do(req)
	if err != nil {
		log.Println("yyyy", err)
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		cfg, _ := json.Marshal(pf)
		log.Println("Enrolling...")
		req, _ = http.NewRequest("POST", create_url, bytes.NewBuffer(cfg))
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *token))
		res, _ = client.Do(req)
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("Failed to enroll router")
		}
	}
	log.Println("Enrolled")
	return nil
}

func GetToken(creds string, api_login_url string) (*string, error) {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", api_login_url, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", creds))
	res, err := client.Do(req)
	defer res.Body.Close()
	if err != nil {
		return nil, err
	}
	responseData, ioerr := ioutil.ReadAll(res.Body)
	if ioerr != nil {
		return nil, ioerr
	}

	var t Token
	json.Unmarshal(responseData, &t)
	return &t.Jwt, nil
}
