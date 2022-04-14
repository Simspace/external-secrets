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
	"reflect"
	"testing"

	"github.com/1Password/connect-sdk-go/onepassword"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	fake "github.com/external-secrets/external-secrets/pkg/provider/onepassword/fake"
)

func TestFindItem(t *testing.T) {
	type check struct {
		checkNote    string
		findItemName string
		expectedItem *onepassword.Item
		expectedErr  error
	}

	type testCase struct {
		setupNote string
		provider  *ProviderOnePassword
		checks    []check
	}

	testCases := []testCase{
		{
			setupNote: "valid basic: one vault, one item, one field",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1"),
			},
			checks: []check{
				{
					checkNote:    "pass",
					findItemName: "my-item",
					expectedErr:  nil,
					expectedItem: &onepassword.Item{
						ID:    "my-item-id",
						Title: "my-item",
						Vault: onepassword.ItemVault{ID: "my-vault-id"},
						Fields: []*onepassword.ItemField{
							{
								Label: "key1",
								Value: "value1",
							},
						},
					},
				},
			},
		},
		{
			setupNote: "multiple vaults, multiple items",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1, "my-shared-vault": 2},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1").
					AddPredictableVault("my-shared-vault").
					AddPredictableItemWithField("my-shared-vault", "my-shared-item", "sharedkey1", "sharedvalue1"),
			},
			checks: []check{
				{
					checkNote:    `can still get "my-item"`,
					findItemName: "my-item",
					expectedErr:  nil,
					expectedItem: &onepassword.Item{
						ID:    "my-item-id",
						Title: "my-item",
						Vault: onepassword.ItemVault{ID: "my-vault-id"},
						Fields: []*onepassword.ItemField{
							{
								Label: "key1",
								Value: "value1",
							},
						},
					},
				},
				{
					checkNote:    `can also get "my-shared-item"`,
					findItemName: "my-shared-item",
					expectedErr:  nil,
					expectedItem: &onepassword.Item{
						ID:    "my-shared-item-id",
						Title: "my-shared-item",
						Vault: onepassword.ItemVault{ID: "my-shared-vault-id"},
						Fields: []*onepassword.ItemField{
							{
								Label: "sharedkey1",
								Value: "sharedvalue1",
							},
						},
					},
				},
			},
		},
		{
			setupNote: "multiple vault matches when should be one",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1, "my-shared-vault": 2},
				client: fake.NewMockClient().
					AppendVault("my-vault", onepassword.Vault{
						ID:   "my-vault-id",
						Name: "my-vault",
					}).
					AppendVault("my-vault", onepassword.Vault{
						ID:   "my-vault-extra-match-id",
						Name: "my-vault-extra-match",
					}),
			},
			checks: []check{
				{
					checkNote:    "two vaults",
					findItemName: "my-item",
					expectedErr:  fmt.Errorf(errExpectedOneVault, fmt.Errorf("'my-vault', got 2")),
				},
			},
		},
		{
			setupNote: "no item matches when should be one",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault"),
			},
			checks: []check{
				{
					checkNote:    "no exist",
					findItemName: "my-item-no-exist",
					expectedErr:  fmt.Errorf(errKeyNotFound, fmt.Errorf("my-item-no-exist in: map[my-vault:1]")),
				},
			},
		},
		{
			setupNote: "multiple item matches when should be one",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1").
					AppendItem("my-vault-id", onepassword.Item{
						ID:    "asdf",
						Title: "my-item",
						Vault: onepassword.ItemVault{ID: "my-vault-id"},
					}),
			},
			checks: []check{
				{
					checkNote:    "multiple match",
					findItemName: "my-item",
					expectedErr:  fmt.Errorf(errExpectedOneItem, fmt.Errorf("'my-item', got 2")),
				},
			},
		},
		{
			setupNote: "ordered vaults",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1, "my-shared-vault": 2, "my-other-vault": 3},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableVault("my-shared-vault").
					AddPredictableVault("my-other-vault").

					//// my-item
					// returned: my-item in my-vault
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1").
					// preempted: my-item in my-shared-vault
					AppendItem("my-shared-vault-id", onepassword.Item{
						ID:    "my-item-id",
						Title: "my-item",
						Vault: onepassword.ItemVault{ID: "my-shared-vault-id"},
					}).
					AppendItemField("my-shared-vault-id", "my-item-id", onepassword.ItemField{
						Label: "key1",
						Value: "value1-from-my-shared-vault",
					}).
					// preempted: my-item in my-other-vault
					AppendItem("my-other-vault-id", onepassword.Item{
						ID:    "my-item-id",
						Title: "my-item",
						Vault: onepassword.ItemVault{ID: "my-other-vault-id"},
					}).
					AppendItemField("my-other-vault-id", "my-item-id", onepassword.ItemField{
						Label: "key1",
						Value: "value1-from-my-other-vault",
					}).

					//// my-shared-item
					// returned: my-shared-item in my-shared-vault
					AddPredictableItemWithField("my-shared-vault", "my-shared-item", "sharedkey1", "sharedvalue1-from-my-shared-vault").
					// preempted: my-shared-item in my-other-vault
					AppendItem("my-other-vault-id", onepassword.Item{
						ID:    "my-shared-item-id",
						Title: "my-shared-item",
						Vault: onepassword.ItemVault{ID: "my-other-vault-id"},
					}).
					AppendItemField("my-other-vault-id", "my-shared-item-id", onepassword.ItemField{
						Label: "sharedkey1",
						Value: "sharedvalue1-from-my-other-vault",
					}).

					//// my-other-item
					// returned: my-other-item in my-other-vault
					AddPredictableItemWithField("my-other-vault", "my-other-item", "otherkey1", "othervalue1-from-my-other-vault"),
			},
			checks: []check{
				{
					// my-item in all three vaults, gets the one from my-vault
					checkNote:    "gets item from my-vault",
					findItemName: "my-item",
					expectedErr:  nil,
					expectedItem: &onepassword.Item{
						ID:    "my-item-id",
						Title: "my-item",
						Vault: onepassword.ItemVault{ID: "my-vault-id"},
						Fields: []*onepassword.ItemField{
							{
								Label: "key1",
								Value: "value1",
							},
						},
					},
				},
				{
					// my-shared-item in my-shared-vault and my-other-vault, gets the one from my-shared-vault
					checkNote:    "gets item from my-shared-vault",
					findItemName: "my-shared-item",
					expectedErr:  nil,
					expectedItem: &onepassword.Item{
						ID:    "my-shared-item-id",
						Title: "my-shared-item",
						Vault: onepassword.ItemVault{ID: "my-shared-vault-id"},
						Fields: []*onepassword.ItemField{
							{
								Label: "sharedkey1",
								Value: "sharedvalue1-from-my-shared-vault",
							},
						},
					},
				},
				{
					// my-other-item in my-other-vault
					checkNote:    "gets item from my-other-vault",
					findItemName: "my-other-item",
					expectedErr:  nil,
					expectedItem: &onepassword.Item{
						ID:    "my-other-item-id",
						Title: "my-other-item",
						Vault: onepassword.ItemVault{ID: "my-other-vault-id"},
						Fields: []*onepassword.ItemField{
							{
								Label: "otherkey1",
								Value: "othervalue1-from-my-other-vault",
							},
						},
					},
				},
			},
		},
	}

	// run the tests
	for _, tc := range testCases {
		for _, check := range tc.checks {
			got, err := tc.provider.findItem(check.findItemName)
			notes := fmt.Sprintf("Setup: '%s', Check: '%s'", tc.setupNote, check.checkNote)
			if check.expectedErr == nil && err != nil {
				// expected no error, got one
				t.Errorf("%s: onepassword.findItem(...): -expected, +got:\n-%#v\n+%#v\n", notes, nil, err)
			}
			if check.expectedErr != nil && err == nil {
				// expected an error, didn't get one
				t.Errorf("%s: onepassword.findItem(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedErr.Error(), nil)
			}
			if check.expectedErr != nil && err != nil && err.Error() != check.expectedErr.Error() {
				// expected an error, got the wrong one
				t.Errorf("%s: onepassword.findItem(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedErr.Error(), err.Error())
			}
			if check.expectedItem != nil {
				if !reflect.DeepEqual(check.expectedItem, got) {
					// expected a predefined item, got something else
					t.Errorf("%s: onepassword.findItem(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedItem, got)
				}
			}
		}
	}
}

// most functionality is tested in TestFindItem
//   here we just check that an empty Property defaults to `password`,
//   files are loaded, and
//   the data or errors are properly returned
func TestGetSecret(t *testing.T) {
	type check struct {
		checkNote     string
		ref           esv1beta1.ExternalSecretDataRemoteRef
		expectedValue string
		expectedErr   error
	}

	type testCase struct {
		setupNote string
		provider  *ProviderOnePassword
		checks    []check
	}

	testCases := []testCase{
		{
			setupNote: "one vault, one item, two fields",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1").
					AppendItemField("my-vault-id", "my-item-id", onepassword.ItemField{
						Label: "password",
						Value: "value2",
					}),
			},
			checks: []check{
				{
					checkNote: "key1",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key:      "my-item",
						Property: "key1",
					},
					expectedValue: "value1",
					expectedErr:   nil,
				},
				{
					checkNote: "'password' (defaulted property)",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key: "my-item",
					},
					expectedValue: "value2",
					expectedErr:   nil,
				},
			},
		},
		{
			setupNote: "files are loaded",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AppendItem("my-vault-id", onepassword.Item{
						ID:       "my-item-id",
						Title:    "my-item",
						Vault:    onepassword.ItemVault{ID: "my-vault-id"},
						Category: "DOCUMENT",
						Files: []*onepassword.File{
							{
								ID:   "my-file-id",
								Name: "my-file.png",
							},
						},
					}).
					SetFileContents("my-file.png", []byte("my-contents")),
			},
			checks: []check{
				{
					checkNote: "file named my-file.png",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key:      "my-item",
						Property: "my-file.png",
					},
					expectedValue: "my-contents",
					expectedErr:   nil,
				},
				{
					checkNote: "empty ref.Property",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key: "my-item",
					},
					expectedValue: "my-contents",
					expectedErr:   nil,
				},
				{
					checkNote: "file non existent",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key:      "my-item",
						Property: "you-cant-find-me.png",
					},
					expectedErr: fmt.Errorf(errDocumentNotFound, fmt.Errorf("'my-item', 'you-cant-find-me.png'")),
				},
			},
		},
		{
			setupNote: "one vault, one item, two fields w/ same Label",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1").
					AppendItemField("my-vault-id", "my-item-id", onepassword.ItemField{
						Label: "key1",
						Value: "value2",
					}),
			},
			checks: []check{
				{
					checkNote: "key1",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key:      "my-item",
						Property: "key1",
					},
					expectedErr: fmt.Errorf(errExpectedOneField, fmt.Errorf("'key1' in 'my-item', got 2")),
				},
			},
		},
	}

	// run the tests
	for _, tc := range testCases {
		for _, check := range tc.checks {
			got, err := tc.provider.GetSecret(context.Background(), check.ref)
			notes := fmt.Sprintf("Setup: '%s', Check: '%s'", tc.setupNote, check.checkNote)
			if check.expectedErr == nil && err != nil {
				// expected no error, got one
				t.Errorf("%s: onepassword.GetSecret(...): -expected, +got:\n-%#v\n+%#v\n", notes, nil, err)
			}
			if check.expectedErr != nil && err == nil {
				// expected an error, didn't get one
				t.Errorf("%s: onepassword.GetSecret(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedErr.Error(), nil)
			}
			if check.expectedErr != nil && err != nil && err.Error() != check.expectedErr.Error() {
				// expected an error, got the wrong one
				t.Errorf("%s: onepassword.GetSecret(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedErr.Error(), err.Error())
			}
			if check.expectedValue != "" {
				if check.expectedValue != string(got) {
					// expected a predefined value, got something else
					t.Errorf("%s: onepassword.GetSecret(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedValue, string(got))
				}
			}
		}
	}
}

// most functionality is tested in TestFindItem. here we just check:
//   all keys are fetched and the map is compiled correctly,
//   files are loaded, and the data or errors are properly returned.
func TestGetSecretMap(t *testing.T) {
	type check struct {
		checkNote   string
		ref         esv1beta1.ExternalSecretDataRemoteRef
		expectedMap map[string][]byte
		expectedErr error
	}

	type testCase struct {
		setupNote string
		provider  *ProviderOnePassword
		checks    []check
	}

	testCases := []testCase{
		{
			setupNote: "one vault, one item, two fields",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1").
					AppendItemField("my-vault-id", "my-item-id", onepassword.ItemField{
						Label: "password",
						Value: "value2",
					}),
			},
			checks: []check{
				{
					checkNote: "all Properties",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key: "my-item",
					},
					expectedMap: map[string][]byte{
						"key1":     []byte("value1"),
						"password": []byte("value2"),
					},
					expectedErr: nil,
				},
			},
		},
		{
			setupNote: "files",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AppendItem("my-vault-id", onepassword.Item{
						ID:       "my-item-id",
						Title:    "my-item",
						Vault:    onepassword.ItemVault{ID: "my-vault-id"},
						Category: "DOCUMENT",
						Files: []*onepassword.File{
							{
								ID:   "my-file-id",
								Name: "my-file.png",
							},
							{
								ID:   "my-file-2-id",
								Name: "my-file-2.png",
							},
						},
					}).
					SetFileContents("my-file.png", []byte("my-contents")).
					SetFileContents("my-file-2.png", []byte("my-contents-2")),
			},
			checks: []check{
				{
					checkNote: "all Properties",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key: "my-item",
					},
					expectedMap: map[string][]byte{
						"my-file.png":   []byte("my-contents"),
						"my-file-2.png": []byte("my-contents-2"),
					},
					expectedErr: nil,
				},
			},
		},
		{
			setupNote: "one vault, one item, two fields w/ same Label",
			provider: &ProviderOnePassword{
				vaults: map[string]int{"my-vault": 1},
				client: fake.NewMockClient().
					AddPredictableVault("my-vault").
					AddPredictableItemWithField("my-vault", "my-item", "key1", "value1").
					AppendItemField("my-vault-id", "my-item-id", onepassword.ItemField{
						Label: "key1",
						Value: "value2",
					}),
			},
			checks: []check{
				{
					checkNote: "key1",
					ref: esv1beta1.ExternalSecretDataRemoteRef{
						Key: "my-item",
					},
					expectedMap: nil,
					expectedErr: fmt.Errorf(errExpectedOneField, fmt.Errorf("'key1' in 'my-item', got 2")),
				},
			},
		},
	}

	// run the tests
	for _, tc := range testCases {
		for _, check := range tc.checks {
			gotMap, err := tc.provider.GetSecretMap(context.Background(), check.ref)
			notes := fmt.Sprintf("Setup: '%s', Check: '%s'", tc.setupNote, check.checkNote)
			if check.expectedErr == nil && err != nil {
				// expected no error, got one
				t.Errorf("%s: onepassword.GetSecretMap(...): -expected, +got:\n-%#v\n+%#v\n", notes, nil, err)
			}
			if check.expectedErr != nil && err == nil {
				// expected an error, didn't get one
				t.Errorf("%s: onepassword.GetSecretMap(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedErr.Error(), nil)
			}
			if check.expectedErr != nil && err != nil && err.Error() != check.expectedErr.Error() {
				// expected an error, got the wrong one
				t.Errorf("%s: onepassword.GetSecretMap(...): -expected, +got:\n-%#v\n+%#v\n", notes, check.expectedErr.Error(), err.Error())
			}
			if !reflect.DeepEqual(check.expectedMap, gotMap) {
				// expected a predefined map, got something else
				t.Errorf("%s: onepassword.GetSecretMap(...): -expected, +got:\n-%v\n+%v\n", notes, check.expectedMap, gotMap)
			}
		}
	}
}

func TestSortVaults(t *testing.T) {
	type testCase struct {
		vaults   map[string]int
		expected []string
	}

	testCases := []testCase{
		{
			vaults: map[string]int{
				"one":   1,
				"three": 3,
				"two":   2,
			},
			expected: []string{
				"one",
				"two",
				"three",
			},
		},
		{
			vaults: map[string]int{
				"four":  100,
				"one":   1,
				"three": 3,
				"two":   2,
			},
			expected: []string{
				"one",
				"two",
				"three",
				"four",
			},
		},
	}

	// run the tests
	for _, tc := range testCases {
		got := sortVaults(tc.vaults)
		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf("onepassword.sortVaults(...): -expected, +got:\n-%#v\n+%#v\n", tc.expected, got)
		}
	}
}
