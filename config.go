package subtocheck

import (
	"fmt"
	"io/ioutil"

	"os"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type config struct {
	Defined bool
	Email   emailConfig `yaml:"email"`
}

type emailConfig struct {
	Provider           string
	Host               string
	Port               string
	Username           string
	Password           string
	Region             string
	AWSAccessKeyID     string `yaml:"aws_access_key_id"`
	AWSSecretAccessKey string `yaml:"aws_secret_access_key"`
	AWSSessionToken    string `yaml:"aws_session_token"`
	Source             string
	Subject            string
	Recipients         []string
	SkipNoVulns        bool `yaml:"skip_no_vulns"`
}

func parseConfigFileContent(content []byte) (config config, err error) {
	unmarshalErr := yaml.Unmarshal(content, &config)
	if unmarshalErr != nil {
		err = errors.WithStack(unmarshalErr)
		return
	}
	return
}

func readConfig(path string) (config config) {
	var configFileContent []byte
	var err error
	configFileContent, err = ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("failed to read: \"%s\"\n", path)
		fmt.Println(" -- error --")
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
	config, err = parseConfigFileContent(configFileContent)
	if err != nil {
		fmt.Printf("failed to parse configuration: \"%s\"\n", path)
		fmt.Println(" -- error --")
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
	return
}
