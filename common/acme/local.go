package acme

import "io/ioutil"

func SaveCert(key, cert []byte) error {

	if err := ioutil.WriteFile(keyPath, key, 0644); err != nil {
		return err
	}

	if err := ioutil.WriteFile(certPath, cert, 0644); err != nil {
		return err
	}
	return nil
}

func LoadCert() ([]byte, []byte, error) {
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}
