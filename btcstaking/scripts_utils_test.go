package btcstaking

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestBuildTimeLockScript(t *testing.T) {
	// 创建一个确定的公钥
	pubKeyHex := "0b93d2d388a2b89c2ba2ef28e99c0cfc20735b693cb8b2350fe8aceca2d0f393"
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)
	pubKey, err := XOnlyPublicKeyFromBytes(pubKeyBytes)
	require.NoError(t, err)

	// 设置锁定时间
	lockTime := uint16(64000)

	// 调用buildTimeLockScript函数
	script, err := buildTimeLockScript(pubKey.PubKey, lockTime)
	require.NoError(t, err)
	fmt.Println(hex.EncodeToString(script))
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
func TestCovenantMultisigScript(t *testing.T) {
	covenantKeys := []*btcec.PublicKey{
		mustParsePublicKey("03d45c70d28f169e1f0c7f4a78e2bc73497afe585b70aa897955989068f3350aaa"),
		mustParsePublicKey("034b15848e495a3a62283daaadb3f458a00859fe48e321f0121ebabbdd6698f9fa"),
		mustParsePublicKey("0223b29f89b45f4af41588dcaf0ca572ada32872a88224f311373917f1b37d08d1"),
		mustParsePublicKey("02d3c79b99ac4d265c2f97ac11e3232c07a598b020cf56c6f055472c893c0967ae"),
		mustParsePublicKey("038242640732773249312c47ca7bdb50ca79f15f2ecc32b9c83ceebba44fb74df7"),
		mustParsePublicKey("03e36200aaa8dce9453567bba108bdc51f7f1174b97a65e4dc4402fc5de779d41c"),
		mustParsePublicKey("03cbdd028cfe32c1c1f2d84bfec71e19f92df509bba7b8ad31ca6c1a134fe09204"),
		mustParsePublicKey("03f178fcce82f95c524b53b077e6180bd2d779a9057fdff4255a0af95af918cee0"),
		mustParsePublicKey("03de13fc96ea6899acbdc5db3afaa683f62fe35b60ff6eb723dad28a11d2b12f8c"),
	}
	covenantQuorum := uint32(6)
	covenantMultisigScript, err := buildMultiSigScript(
		covenantKeys,
		covenantQuorum,
		// covenant multisig is always last in script so we do not run verify and leave
		// last value on the stack. If we do not leave at least one element on the stack
		// script will always error
		false,
	)
	require.NoError(t, err)
	fmt.Println(hex.EncodeToString(covenantMultisigScript))
}

func mustParsePublicKey(hexStr string) *btcec.PublicKey {
	pubKeyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	if len(pubKeyBytes) == 32 {
		pubKey, err := XOnlyPublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			panic(err)
		}
		return pubKey.PubKey
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		panic(err)
	}
	return pubKey
}

func TestFPMultisigScript(t *testing.T) {
	fpKeys := []*btcec.PublicKey{
		mustParsePublicKey("db9160428e401753dc1a9952ffd4fa3386c7609cf8411d2b6d79c42323ca9923"),
	}
	fpQuorum := uint32(1)
	fpMultisigScript, err := buildMultiSigScript(fpKeys, fpQuorum, true)
	require.NoError(t, err)
	fmt.Println(hex.EncodeToString(fpMultisigScript))
}

func TestStakerSigScript(t *testing.T) {
	stakerKey := mustParsePublicKey("0b93d2d388a2b89c2ba2ef28e99c0cfc20735b693cb8b2350fe8aceca2d0f393")
	stakerSigScript, err := buildSingleKeySigScript(stakerKey, true)
	require.NoError(t, err)
	fmt.Println(hex.EncodeToString(stakerSigScript))
}

func TestTaprootScriptHolder(t *testing.T) {
	covenantMultisigScriptHex := "2023b29f89b45f4af41588dcaf0ca572ada32872a88224f311373917f1b37d08d1ac204b15848e495a3a62283daaadb3f458a00859fe48e321f0121ebabbdd6698f9faba208242640732773249312c47ca7bdb50ca79f15f2ecc32b9c83ceebba44fb74df7ba20cbdd028cfe32c1c1f2d84bfec71e19f92df509bba7b8ad31ca6c1a134fe09204ba20d3c79b99ac4d265c2f97ac11e3232c07a598b020cf56c6f055472c893c0967aeba20d45c70d28f169e1f0c7f4a78e2bc73497afe585b70aa897955989068f3350aaaba20de13fc96ea6899acbdc5db3afaa683f62fe35b60ff6eb723dad28a11d2b12f8cba20e36200aaa8dce9453567bba108bdc51f7f1174b97a65e4dc4402fc5de779d41cba20f178fcce82f95c524b53b077e6180bd2d779a9057fdff4255a0af95af918cee0ba569c"
	fpMulitsigScriptHex := "20db9160428e401753dc1a9952ffd4fa3386c7609cf8411d2b6d79c42323ca9923ad"
	timelockScriptHex := "200b93d2d388a2b89c2ba2ef28e99c0cfc20735b693cb8b2350fe8aceca2d0f393ad0300fa00b2"
	stakerSigScriptHex := "200b93d2d388a2b89c2ba2ef28e99c0cfc20735b693cb8b2350fe8aceca2d0f393ad"

	timelockScript, err := hex.DecodeString(timelockScriptHex)
	require.NoError(t, err)
	stakerSigScript, err := hex.DecodeString(stakerSigScriptHex)
	require.NoError(t, err)
	covenantMultisigScript, err := hex.DecodeString(covenantMultisigScriptHex)
	require.NoError(t, err)
	fpMultisigScript, err := hex.DecodeString(fpMulitsigScriptHex)
	require.NoError(t, err)

	unbondingPathScript := aggregateScripts(
		stakerSigScript,
		covenantMultisigScript,
	)

	slashingPathScript := aggregateScripts(
		stakerSigScript,
		fpMultisigScript,
		covenantMultisigScript,
	)

	fmt.Println(hex.EncodeToString(unbondingPathScript))
	fmt.Println(hex.EncodeToString(slashingPathScript))

	var unbondingPaths [][]byte
	unbondingPaths = append(unbondingPaths, timelockScript)
	unbondingPaths = append(unbondingPaths, unbondingPathScript)
	unbondingPaths = append(unbondingPaths, slashingPathScript)

	unspendableKeyPathKey := unspendableKeyPathInternalPubKey()
	holder, err := newTaprootScriptHolder(&unspendableKeyPathKey, unbondingPaths)
	require.NoError(t, err)

	printTapTree(holder.scriptTree)

	taprootPkScript, err := holder.taprootPkScript(&chaincfg.MainNetParams)
	require.NoError(t, err)
	fmt.Println(hex.EncodeToString(taprootPkScript))
}

func printTapTree(tree *txscript.IndexedTapScriptTree) {
	printTapTreeNode(tree.RootNode, 0)
	for hash, idx := range tree.LeafProofIndex {
		fmt.Printf("leaf proof %s: %d\n", hex.EncodeToString(hash[:]), idx)
	}
}

func printTapTreeNode(node txscript.TapNode, depth int) {
	indent := strings.Repeat("  ", depth)
	hash := node.TapHash()
	fmt.Printf("%sNode Hash: %s\n", indent, hex.EncodeToString(hash[:]))

	if leaf, ok := node.(txscript.TapLeaf); ok {
		fmt.Printf("%sLeaf Script: %x\n", indent, leaf.Script)
		return
	}

	if branch, ok := node.(txscript.TapBranch); ok {
		fmt.Printf("%sLeft Child:\n", indent)
		printTapTreeNode(branch.Left(), depth+1)
		fmt.Printf("%sRight Child:\n", indent)
		printTapTreeNode(branch.Right(), depth+1)
	}
}

func TestTapLeafHash(t *testing.T) {

	timelockScriptHex := "200b93d2d388a2b89c2ba2ef28e99c0cfc20735b693cb8b2350fe8aceca2d0f393ad0300fa00b2"
	timelockScript, err := hex.DecodeString(timelockScriptHex)
	require.NoError(t, err)

	var leafEncoding bytes.Buffer

	_ = leafEncoding.WriteByte(byte(txscript.BaseLeafVersion))
	_ = wire.WriteVarBytes(&leafEncoding, 0, timelockScript)

	fmt.Println(hex.EncodeToString(leafEncoding.Bytes()))

	leaf := txscript.NewBaseTapLeaf(timelockScript)
	hash := leaf.TapHash()
	//The hash.String() is byte-reversed, so we directly print the hex string of the hash
	fmt.Println(hex.EncodeToString(hash[:]))
}
