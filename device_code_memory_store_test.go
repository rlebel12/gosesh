package gosesh

import (
	"testing"
)

func TestMemoryDeviceCodeStore(t *testing.T) {
	contract := DeviceCodeStoreContract{
		NewStore: func() DeviceCodeStore {
			return NewMemoryDeviceCodeStore()
		},
	}
	contract.Test(t)
}
