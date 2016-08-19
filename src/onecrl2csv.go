package main

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func getJSON(url string, target interface{}) error {
	r, err := http.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(target)
}

func hexify(arr []byte) string {
	var encoded bytes.Buffer
	for i := 0; i < len(arr); i++ {
		encoded.WriteString(strings.ToUpper(hex.EncodeToString(arr[i : i+1])))
		if i < len(arr)-1 {
			encoded.WriteString(":")
		}
	}
	return encoded.String()
}

type Results struct {
	Data []struct {
		IssuerName   string
		SerialNumber string
	}
}

func rfc4514ish(rdns *pkix.RDNSequence) string {
	retval := ""
	for _, rdn := range *rdns {
		if len(rdn) == 0 {
			continue
		}
		atv := rdn[0]
		value, ok := atv.Value.(string)
		if !ok {
			continue
		}
		t := atv.Type
		tStr := ""
		if len(t) == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
			switch t[3] {
			case 3:
				tStr = "CN"
			case 7:
				tStr = "L"
			case 8:
				tStr = "ST"
			case 10:
				tStr = "O"
			case 11:
				tStr = "OU"
			case 6:
				tStr = "C"
			case 9:
				tStr = "STREET"
			}
		}
		sep := ""
		if len(retval) > 0 {
			sep = ","
		}
		retval = tStr + "=" + value + sep + retval
	}
	return retval
}

func main() {
	listURL := "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records"
	res := new(Results)
	getJSON(listURL, res)
	for idx := range res.Data {
		IssuerName := res.Data[idx].IssuerName
		rawIssuer, _ := base64.StdEncoding.DecodeString(IssuerName)
		rdns := new(pkix.RDNSequence)
		_, err3 := asn1.Unmarshal(rawIssuer, rdns)
		if nil != err3 {
			log.Print(err3)
		}
		SerialNumber := res.Data[idx].SerialNumber
		rawSerial, err2 := base64.StdEncoding.DecodeString(SerialNumber)
		if nil != err2 {
			log.Print(err2)
		}
		hexSerial := hexify(rawSerial)
		fmt.Printf("\"%s\",\"%s\"\n", rfc4514ish(rdns), hexSerial)
	}
}
