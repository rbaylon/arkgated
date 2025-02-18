package srvclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

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
		defer res.Body.Close()
		if res.StatusCode != 200 {
			b, err := io.ReadAll(res.Body)
			if err != nil {
				log.Println("Read body error",err)
			}
			log.Println(string(b))
			log.Println("Failed to enroll router", err)
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
	log.Println("StatusCode",res.StatusCode)
	if res.StatusCode != 200 {
		log.Fatalln("API login failed")
	}
	if err != nil {
		return nil, err
	}
	responseData, ioerr := io.ReadAll(res.Body)
	if ioerr != nil {
		return nil, ioerr
	}

	var t Token
	json.Unmarshal(responseData, &t)
	return &t.Jwt, nil
}
