package btcstaking_test

import (
	"encoding/hex"
	"math/rand"
	"testing"
	"time"

	"github.com/babylonlabs-io/babylon/btcstaking"
	"github.com/babylonlabs-io/babylon/testutil/datagen"
	bbn "github.com/babylonlabs-io/babylon/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestSortKeys(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().Unix()))

	_, pks, err := datagen.GenRandomBTCKeyPairs(r, 10)
	require.NoError(t, err)

	sortedPKs := btcstaking.SortKeys(pks)

	btcPKs := bbn.NewBIP340PKsFromBTCPKs(pks)
	sortedBTCPKs := bbn.SortBIP340PKs(btcPKs)

	// ensure sorted PKs and sorted BIP340 PKs are in reverse order
	for i := range sortedPKs {
		pkBytes := schnorr.SerializePubKey(sortedPKs[i])

		btcPK := sortedBTCPKs[len(sortedBTCPKs)-1-i]
		btcPKBytes := btcPK.MustMarshal()

		require.Equal(t, pkBytes, btcPKBytes, "comparing %d-th key", i)
	}
}

// "covenant_pks": [
//
//	"03d45c70d28f169e1f0c7f4a78e2bc73497afe585b70aa897955989068f3350aaa",
//	"034b15848e495a3a62283daaadb3f458a00859fe48e321f0121ebabbdd6698f9fa",
//	"0223b29f89b45f4af41588dcaf0ca572ada32872a88224f311373917f1b37d08d1",
//	"02d3c79b99ac4d265c2f97ac11e3232c07a598b020cf56c6f055472c893c0967ae",
//	"038242640732773249312c47ca7bdb50ca79f15f2ecc32b9c83ceebba44fb74df7",
//	"03e36200aaa8dce9453567bba108bdc51f7f1174b97a65e4dc4402fc5de779d41c",
//	"03cbdd028cfe32c1c1f2d84bfec71e19f92df509bba7b8ad31ca6c1a134fe09204",
//	"03f178fcce82f95c524b53b077e6180bd2d779a9057fdff4255a0af95af918cee0",
//	"03de13fc96ea6899acbdc5db3afaa683f62fe35b60ff6eb723dad28a11d2b12f8c"
//
// ],
func TestSortKeysWithCovenantPKs(t *testing.T) {
	covenantPKs := []string{
		"03d45c70d28f169e1f0c7f4a78e2bc73497afe585b70aa897955989068f3350aaa",
		"034b15848e495a3a62283daaadb3f458a00859fe48e321f0121ebabbdd6698f9fa",
		"0223b29f89b45f4af41588dcaf0ca572ada32872a88224f311373917f1b37d08d1",
		"02d3c79b99ac4d265c2f97ac11e3232c07a598b020cf56c6f055472c893c0967ae",
		"038242640732773249312c47ca7bdb50ca79f15f2ecc32b9c83ceebba44fb74df7",
		"03e36200aaa8dce9453567bba108bdc51f7f1174b97a65e4dc4402fc5de779d41c",
		"03cbdd028cfe32c1c1f2d84bfec71e19f92df509bba7b8ad31ca6c1a134fe09204",
		"03f178fcce82f95c524b53b077e6180bd2d779a9057fdff4255a0af95af918cee0",
		"03de13fc96ea6899acbdc5db3afaa683f62fe35b60ff6eb723dad28a11d2b12f8c",
	}

	var pks []*btcec.PublicKey
	for _, pkHex := range covenantPKs {
		pkBytes, err := hex.DecodeString(pkHex)
		require.NoError(t, err)
		pk, err := btcec.ParsePubKey(pkBytes)
		require.NoError(t, err)
		pks = append(pks, pk)
	}

	sortedPKs := btcstaking.SortKeys(pks)

	t.Log("排序后的公钥顺序：")
	for i, pk := range sortedPKs {
		t.Logf("%d: %x", i, schnorr.SerializePubKey(pk))
	}

}
