package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestNewKeyGenerator(t *testing.T) {
	tests := []struct {
		name                   string
		secretKeyBaseHexString string
		wantErr                bool
	}{
		{
			name:                   "not a hex string",
			secretKeyBaseHexString: "not a hex string",
			wantErr:                true,
		},
		{
			name:                   "hex string",
			secretKeyBaseHexString: hex.EncodeToString([]byte("secret key base")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKeyGenerator(tt.secretKeyBaseHexString)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeyGenerator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestKeyGenerator_Generate(t *testing.T) {
	g, err := NewKeyGenerator(hex.EncodeToString([]byte("secret key base")))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		115, 236, 174, 71, 230, 135, 104, 219, 39, 4,
		83, 119, 191, 176, 217, 109, 133, 166, 220, 148,
		8, 26, 50, 125, 113, 91, 5, 92, 231, 73,
		238, 58,
	}
	if got := g.Generate("salt"); !reflect.DeepEqual(got, want) {
		t.Errorf("Generate() = %v, want %v", got, want)
	}
}
