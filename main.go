package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&sotoonDNSProviderSolver{},
	)
}

// sotoonDNSProviderSolver implements Sotoon DNS logic needed to
// 'present' an ACME challenge TXT record. To do so, it must implement
// the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type sotoonDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// sootonNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and a reference to credentials
// that's needed to add TXT record in Sotoon to solve the challenge for this
// particular certificate. If credentials need to be used by your provider here,
// you should reference a Kubernetes Secret resource and fetch these credentials
// using a Kubernetes clientset.
type sotoonDNSProviderConfig struct {
	// This field will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	APIKeySecretRef v1.SecretKeySelector `json:"apiKeySecretRef"`
	BaseURL         string               `json:"baseUrl"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (s *sotoonDNSProviderSolver) Name() string {
	return "sotoon"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (s *sotoonDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	secret, err := s.client.CoreV1().Secrets(ch.ResourceNamespace).Get(
		context.Background(), cfg.APIKeySecretRef.LocalObjectReference.Name, metav1.GetOptions{})
	secretByteString, ok := secret.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return fmt.Errorf("couldn't fetch apikey from key %q of secret %s in namespace %s",
			cfg.APIKeySecretRef.Key, cfg.APIKeySecretRef.Name, ch.ResourceNamespace)
	}

	apiKey := string(secretByteString)

	httpClient := &http.Client{}
	dnsUrl := fmt.Sprintf("%s/%s", cfg.BaseURL, ch.ResolvedZone)
	req, err := http.NewRequest("GET", dnsUrl, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	if err != nil {
		return fmt.Errorf("couldn't create http request object with error %v", err)
	}

	response, err := httpClient.Do(req)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("couldn't read Sotoon dns response's body with error %v", err)
	}

	var dnsData map[string]interface{}
	err = json.Unmarshal(body, &dnsData)
	if err != nil {
		return fmt.Errorf("couldn't parse Sotoon dns response's body %s", string(body))
	}

	// Check whether the key is already present in DNS
	for recordName, records := range dnsData["spec"].(map[string]interface{})["records"].(map[string]interface{}) {
		if recordName == ch.ResolvedFQDN {
			for _, record := range records.([]interface{}) {
				val, ok := record.(map[string]interface{})["TXT"]
				if ok && val.(string) == ch.Key {
					return nil
				}
			}
		}
	}

	// If code reaches here the key is not present and we should add a record containing that key
	patchPayload := []byte(fmt.Sprintf(`[{"op":"add","path":"/spec/records/%s","value":[{"TXT":"%s","ttl":300}]}]`, ch.ResolvedFQDN, ch.Key))
	req, err = http.NewRequest("PATCH", dnsUrl, bytes.NewBuffer(patchPayload))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Content-type", "application/json")
	response, err = httpClient.Do(req)
	if response.StatusCode != 200 {
		return fmt.Errorf("couldn't add record for %s with response status code of: %d", ch.ResolvedFQDN, response.StatusCode)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *sotoonDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (s *sotoonDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	// Initializing kubernetes client to access credentials secret
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	s.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (sotoonDNSProviderConfig, error) {
	cfg := sotoonDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
