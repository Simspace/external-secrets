/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package onepassword

import (
	"context"
	"fmt"
	"sort"

	"github.com/1Password/connect-sdk-go/connect"
	"github.com/1Password/connect-sdk-go/onepassword"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	userAgent = "external-secrets"

	errOnePasswordStore                   = "received invalid 1Password SecretStore resource"
	errClusterSecretStoreNamespaceMissing = "missing namespace in ClusterSecretStore SecretRef"
	errSecretStoreNamespaceSet            = "only ClusterSecretStore SecretRefs may set namespace"
	errFetchK8sSecret                     = "could not fetch ConnectToken Secret: %w"
	errMissingToken                       = "missing Secret Token"
	errGetVault                           = "error finding 1Password Vault: %w"
	errExpectedOneVault                   = "expected one 1Password Vault matching %w"
	errExpectedOneItem                    = "expected one 1Password Item matching %w"
	errGetItem                            = "error finding 1Password Item: %w"
	errKeyNotFound                        = "key not found in 1Password Vaults: %w"
	errDocumentNotFound                   = "error finding 1Password Document: %w"
	errExpectedOneField                   = "expected one 1Password ItemField matching %w"
)

// ProviderOnePassword is a provider for 1Password.
type ProviderOnePassword struct {
	vaults map[string]int
	client connect.Client
}

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1beta1.SecretsClient = &ProviderOnePassword{}
var _ esv1beta1.Provider = &ProviderOnePassword{}

// NewClient constructs a 1Password Provider.
func (provider *ProviderOnePassword) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube kclient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	config := store.GetSpec().Provider.OnePassword

	credentialsSecret := &corev1.Secret{}
	objectKey := types.NamespacedName{
		Name:      config.Auth.SecretRef.ConnectToken.Name,
		Namespace: namespace,
	}

	// only ClusterSecretStore is allowed to set namespace (and then it's required)
	if store.GetObjectKind().GroupVersionKind().Kind == esv1beta1.ClusterSecretStoreKind {
		if config.Auth.SecretRef.ConnectToken.Namespace == nil {
			return nil, fmt.Errorf(errClusterSecretStoreNamespaceMissing)
		}
		objectKey.Namespace = *config.Auth.SecretRef.ConnectToken.Namespace
	}

	err := kube.Get(ctx, objectKey, credentialsSecret)
	if err != nil {
		return nil, fmt.Errorf(errFetchK8sSecret, err)
	}
	token := credentialsSecret.Data[config.Auth.SecretRef.ConnectToken.Key]
	if (token == nil) || (len(token) == 0) {
		return nil, fmt.Errorf(errMissingToken)
	}
	provider.client = connect.NewClientWithUserAgent(config.ConnectHost, string(token), userAgent)
	provider.vaults = config.Vaults

	return provider, nil
}

// ValidateStore checks if the provided store is valid
func (provider *ProviderOnePassword) ValidateStore(store esv1beta1.GenericStore) error {
	storeSpec := store.GetSpec()
	if storeSpec == nil || storeSpec.Provider == nil || storeSpec.Provider.OnePassword == nil {
		return fmt.Errorf(errOnePasswordStore)
	}
	config := storeSpec.Provider.OnePassword

	// only ClusterSecretStore is allowed to set namespace (and then it's required)
	if store.GetObjectKind().GroupVersionKind().Kind == esv1beta1.ClusterSecretStoreKind {
		if config.Auth.SecretRef.ConnectToken.Namespace == nil {
			return fmt.Errorf(errClusterSecretStoreNamespaceMissing)
		}
	} else {
		if config.Auth.SecretRef.ConnectToken.Namespace != nil {
			return fmt.Errorf(errSecretStoreNamespaceSet)
		}
	}

	return nil
}

// GetSecret returns a single secret from the provider.
func (provider *ProviderOnePassword) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	item, err := provider.findItem(ref.Key)
	if err != nil {
		return nil, err
	}

	// handle files
	if item.Category == "DOCUMENT" {
		for _, file := range item.Files {
			// default to the first file when ref.Property is empty
			if file.Name == ref.Property || ref.Property == "" {
				contents, err := provider.client.GetFileContent(file)
				if err != nil {
					return nil, err
				}

				return contents, nil
			}
		}

		return nil, fmt.Errorf(errDocumentNotFound, fmt.Errorf("'%s', '%s'", item.Title, ref.Property))
	}

	// default to a field labeled `password`
	fieldLabel := "password"
	if ref.Property != "" {
		fieldLabel = ref.Property
	}

	if length := countFieldsWithLabel(fieldLabel, item.Fields); length != 1 {
		return nil, fmt.Errorf(errExpectedOneField, fmt.Errorf("'%s' in '%s', got %d", fieldLabel, item.Title, length))
	}

	// caution: do not use client.GetValue here because it has undesireable behavior on keys with a dot in them
	value := ""
	for _, field := range item.Fields {
		if field.Label == fieldLabel {
			value = field.Value
			break
		}
	}

	return []byte(value), nil
}

// Validate checks if the client is configured correctly
// to be able to retrieve secrets from the provider
func (provider *ProviderOnePassword) Validate() error {
	for vaultName := range provider.vaults {
		_, err := provider.client.GetItems(vaultName)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetSecretMap returns multiple k/v pairs from the provider, for dataFrom
func (provider *ProviderOnePassword) GetSecretMap(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	item, err := provider.findItem(ref.Key)
	if err != nil {
		return nil, err
	}

	secretData := make(map[string][]byte)

	// handle files
	if item.Category == "DOCUMENT" {
		for _, file := range item.Files {
			contents, err := provider.client.GetFileContent(file)
			if err != nil {
				return nil, err
			}
			secretData[file.Name] = contents
		}

		return secretData, nil
	}

	for _, field := range item.Fields {
		if length := countFieldsWithLabel(field.Label, item.Fields); length != 1 {
			return nil, fmt.Errorf(errExpectedOneField, fmt.Errorf("'%s' in '%s', got %d", field.Label, item.Title, length))
		}

		// caution: do not use client.GetValue here because it has undesireable behavior on keys with a dot in them
		secretData[field.Label] = []byte(field.Value)
	}

	return secretData, nil
}

// GetAllSecrets syncs multiple 1password Items into a single Kubernetes Secret.
func (provider *ProviderOnePassword) GetAllSecrets(ctx context.Context, ref esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	// TODO
	// item, err := provider.findItem(ref.Key)
	// if err != nil {
	//     return nil, err
	// }

	secretData := make(map[string][]byte)

	// // handle files
	// if item.Category == "DOCUMENT" {
	//     for _, file := range item.Files {
	//         contents, err := provider.client.GetFileContent(file)
	//         if err != nil {
	//             return nil, err
	//         }
	//         secretData[file.Name] = contents
	//     }

	//     return secretData, nil
	// }

	// for _, field := range item.Fields {
	//     if length := countFieldsWithLabel(field.Label, item.Fields); length != 1 {
	//         return nil, fmt.Errorf(errExpectedOneField, fmt.Errorf("'%s' in '%s', got %d", field.Label, item.Title, length))
	//     }

	//     // caution: do not use client.GetValue here because it has undesireable behavior on keys with a dot in them
	//     secretData[field.Label] = []byte(field.Value)
	// }

	return secretData, nil
}

// Close closes the client connection.
func (provider *ProviderOnePassword) Close(ctx context.Context) error {
	return nil
}

func (provider *ProviderOnePassword) findItem(name string) (*onepassword.Item, error) {
	sortedVaults := sortVaults(provider.vaults)
	for _, vaultName := range sortedVaults {
		vaults, err := provider.client.GetVaultsByTitle(vaultName)
		if err != nil {
			return nil, fmt.Errorf(errGetVault, err)
		}
		if len(vaults) != 1 {
			return nil, fmt.Errorf(errExpectedOneVault, fmt.Errorf("'%s', got %d", vaultName, len(vaults)))
		}

		// use GetItemsByTitle instead of GetItemByTitle in order to handle length cases
		items, err := provider.client.GetItemsByTitle(name, vaults[0].ID)
		if err != nil {
			return nil, fmt.Errorf(errGetItem, err)
		}
		switch {
		case len(items) == 1:
			return provider.client.GetItem(items[0].ID, items[0].Vault.ID)
		case len(items) > 1:
			return nil, fmt.Errorf(errExpectedOneItem, fmt.Errorf("'%s', got %d", name, len(items)))
		}
	}

	return nil, fmt.Errorf(errKeyNotFound, fmt.Errorf("%s in: %v", name, provider.vaults))
}

func countFieldsWithLabel(fieldLabel string, fields []*onepassword.ItemField) int {
	count := 0
	for _, field := range fields {
		if field.Label == fieldLabel {
			count++
		}
	}

	return count
}

type orderedVault struct {
	Name  string
	Order int
}

type orderedVaultList []orderedVault

func (list orderedVaultList) Len() int           { return len(list) }
func (list orderedVaultList) Swap(i, j int)      { list[i], list[j] = list[j], list[i] }
func (list orderedVaultList) Less(i, j int) bool { return list[i].Order < list[j].Order }

func sortVaults(vaults map[string]int) []string {
	list := make(orderedVaultList, len(vaults))
	index := 0
	for key, value := range vaults {
		list[index] = orderedVault{key, value}
		index++
	}
	sort.Sort(list)
	sortedVaults := []string{}
	for _, item := range list {
		sortedVaults = append(sortedVaults, item.Name)
	}

	return sortedVaults
}

func init() {
	esv1beta1.Register(&ProviderOnePassword{}, &esv1beta1.SecretStoreProvider{
		OnePassword: &esv1beta1.OnePasswordProvider{},
	})
}
