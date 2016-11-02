package main

import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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

func hexify(arr []byte, separate bool, upperCase bool) string {
	var encoded bytes.Buffer
	for i := 0; i < len(arr); i++ {
		encoded.WriteString(strings.ToUpper(hex.EncodeToString(arr[i : i+1])))
		if i < len(arr)-1 && separate {
			encoded.WriteString(":")
		}
	}
	retval := encoded.String()
	if !upperCase {
		retval = strings.ToLower(retval)
	}
	return retval;
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

func decodeDN(name string) (string, error) {
	rawDN, _ := base64.StdEncoding.DecodeString(name)
	rdns := new(pkix.RDNSequence)
	_, err := asn1.Unmarshal(rawDN, rdns)
	if nil != err {
		fmt.Printf("problem decoding %s\n", name);
		//return "", err
	}
	
	return rfc4514ish(rdns), err
}

func decodeSerial(encoded string, separate bool, upper bool) (string, error) {
	rawSerial, err := base64.StdEncoding.DecodeString(encoded)
	return hexify(rawSerial, separate, upper), err
}

func getRevocationsTxt(filename string, separate bool, upper bool) error {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var dn = ""
	for scanner.Scan() {
		// process line
		line := scanner.Text()
		// Ignore comments
		if 0 == strings.Index(line, "#") {
			continue
		}
		if 0 == strings.Index(line, " ") {
			if len(dn) == 0 {
				log.Fatal("A serial number with no issuer is not valid. Exiting.")
			}
			issuer, err2 := decodeDN(dn)
			if nil != err2 {
				log.Print(err2)
			}
			
			serial, err3 := decodeSerial(strings.Trim(line, " "), separate, upper)
			if nil != err3 {
				log.Print(err3)
			}
			fmt.Printf("\"%s\",\"%s\"\n", issuer, serial);
			continue
		}
		if 0 == strings.Index(line, "\t") {
			log.Fatal("revocations.txt containing subject / pubkey pairs not yet supported");
			log.Fatal("A public key hash with no subject is not valid. Exiting.")
		}
		dn = line
	}
	
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return nil;
}

func main() {
	urlPtr := flag.String("url", "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records", "The URL of the blocklist record data")
	filePtr := flag.String("file", "", "revocations.txt to load entries from");
	upper := flag.Bool("upper", false, "Should hex values be upper case?")
	separate := flag.Bool("separate", false, "Should the serial number bytes be colon separated?")
	flag.Parse()
	res := new(Results)
	// If no file is specificied, fall back to loading from an URL
	if len(*filePtr) == 0 {
		getJSON(*urlPtr, res)
	} else {
		getRevocationsTxt(*filePtr, *separate, *upper)
	}
	for idx := range res.Data {
		IssuerName := res.Data[idx].IssuerName
		SerialNumber := res.Data[idx].SerialNumber
		hexSerial, err2 := decodeSerial(SerialNumber, *separate, *upper)
		if nil != err2 {
			log.Print(err2)
		}
		decodedIssuer, err3 := decodeDN(IssuerName)
		if err3 != nil {
			log.Print(err3)
		}
		fmt.Printf("\"%s\",\"%s\"\n", decodedIssuer, hexSerial)
	}
}
