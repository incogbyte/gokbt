package util

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ropnop/gokrb5/v8/crypto"
	"github.com/ropnop/gokrb5/v8/iana/etypeID"
	"github.com/ropnop/gokrb5/v8/messages"
	"github.com/ropnop/gokrb5/v8/types"
)

func ASRepToHashcat(asrep messages.ASRep) (string, error) {
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		asrep.EncPart.EType,
		asrep.CName.PrincipalNameString(),
		asrep.CRealm,
		hex.EncodeToString(asrep.EncPart.Cipher[:16]),
		hex.EncodeToString(asrep.EncPart.Cipher[16:])), nil
}

func ParseNTLMHash(hash string) (*types.EncryptionKey, error) {
	hash = strings.TrimSpace(hash)
	hash = strings.TrimPrefix(hash, "0x")
	hash = strings.TrimPrefix(hash, "0X")
	
	if len(hash) != 32 {
		return nil, fmt.Errorf("invalid hash length: expected 32 hex characters")
	}
	
	keyBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	
	key := types.EncryptionKey{
		KeyType:  int32(23),
		KeyValue: keyBytes,
	}
	
	return &key, nil
}

func ParseAESHash(hash string, etype int32) (*types.EncryptionKey, error) {
	hash = strings.TrimSpace(hash)
	hash = strings.TrimPrefix(hash, "0x")
	hash = strings.TrimPrefix(hash, "0X")
	
	var expectedLen int
	switch etype {
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		expectedLen = 32
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		expectedLen = 64
	default:
		return nil, fmt.Errorf("unsupported etype for AES hash: %d", etype)
	}
	
	if len(hash) != expectedLen {
		return nil, fmt.Errorf("invalid hash length: expected %d hex characters", expectedLen)
	}
	
	keyBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	
	key := types.EncryptionKey{
		KeyType:  etype,
		KeyValue: keyBytes,
	}
	
	return &key, nil
}

func DeriveKeyFromPassword(password string, cname types.PrincipalName, realm string, etype int32) (*types.EncryptionKey, error) {
	key, _, err := crypto.GetKeyFromPassword(password, cname, realm, etype, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	return &key, nil
}
