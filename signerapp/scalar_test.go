package signerapp_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/babylonchain/covenant-signer/btcclient"
	"github.com/babylonchain/covenant-signer/config"
	"github.com/babylonchain/covenant-signer/signerapp"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	btcvault "github.com/scalarorg/btc-vault/btcvault"
	"github.com/stretchr/testify/require"
)

var (
	testnet             = &chaincfg.TestNet3Params
	broadcastNodeConfig = &config.ParsedBtcConfig{
		Host:    "localhost:18556",
		User:    "user",
		Pass:    "password",
		Network: testnet,
	}
	signerNodeConfig = &config.ParsedBtcConfig{
		Host:    "localhost:18556",
		User:    "user",
		Pass:    "password",
		Network: testnet,
	}
)

type TestManager struct {
	t                 *testing.T
	BtcClient         *btcclient.BtcClient
	MagicBytes        []byte
	BondHolderPubkey  *btcec.PublicKey
	BondHolderPrivkey *btcec.PrivateKey
	ServiceKey        *btcec.PrivateKey
	AllCovenantKeys   []*btcec.PublicKey
	CovenantQuorum    uint32
	ChainParams       *chaincfg.Params
}

func StartManager(t *testing.T) *TestManager {
	bondHolderPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	bondHolderPubKey := bondHolderPrivKey.PubKey()

	serviceKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	// Client for testing purposes
	client, err := btcclient.NewBtcClient(broadcastNodeConfig)
	require.NoError(t, err)

	return &TestManager{
		t:                 t,
		BtcClient:         client,
		MagicBytes:        []byte{0x0, 0x1, 0x2, 0x3},
		BondHolderPubkey:  bondHolderPubKey,
		BondHolderPrivkey: bondHolderPrivKey,
		ServiceKey:        serviceKey,
		AllCovenantKeys:   CreateCovenantKeys(t),
		CovenantQuorum:    2,
		ChainParams:       &chaincfg.TestNet3Params,
	}
}
func TestSigner(t *testing.T) {
	tm := StartManager(t)
	fmt.Printf("%d", tm.CovenantQuorum)
	CreateBondingTx(tm, 100000, []byte{0x0, 0x1, 0x2, 0x3}, []byte{0x0, 0x1, 0x2, 0x3}, []byte{0x0, 0x1, 0x2, 0x3})
	// txHashHex := "2010c5d35ae7b7e79681f34dea70971a49396c543615999e3815dff42216907b"
	// // txHash := common.HexToHash(txHashHex)
	// txHash, err := chainhash.NewHashFromStr(txHashHex)
	// fmt.Printf("TxHash: %+v\n", txHash)
	// // stakerAddress := "tb1qpzmmqzc0wgx0tnp70cu24ts62u4ev2ey8xlgn3"
	// stakerPubkeyHex := "001408b7b00b0f720cf5cc3e7e38aaae1a572b962b24"
	// servicePubkeyHex := "00143207d84bd242dec927f5056ddc9c938da443e8b3"
	// stakerPubKeyBytes, err := hex.DecodeString(stakerPubkeyHex)
	// require.NoError(t, err)
	// servicePubkeyBytes, err := hex.DecodeString(servicePubkeyHex)
	// require.NoError(t, err)
	// stakerPubkey, err := btcec.ParsePubKey(stakerPubKeyBytes)
	// require.NoError(t, err)
	// servicePubkey, err := btcec.ParsePubKey(servicePubkeyBytes)
	// require.NoError(t, err)

	// covenantPks := []string{
	// 	hex.EncodeToString(localCovenantKey.PubKey().SerializeCompressed()),
	// 	hex.EncodeToString(remoteCovenantKey1.PubKey().SerializeCompressed()),
	// 	hex.EncodeToString(remoteCovenantKey2.PubKey().SerializeCompressed()),
	// }

	// unbondingTx := CreateUnlockingTx(t, stakerPubkey, servicePubkey, 100000, *txHash, covenantPks, 2, 10000)
	// fmt.Printf("%+v\n", unbondingTx)
	// // stakingTx := CreateStakingTx(t, stakerPubKey, dAppPubKey, 100000, testnet)
	// // stakingOutputPkScript := stakingTx.TxOut[0].PkScript
	// // stakingTxHash := stakingTx.TxHash()
	// // unlockingTx := CreateUnlockingTx(t, stakerPubKey, dAppPubKey, 100000, stakingTxHash, testnet)
	// // unlockingTxStakerSig, err := SignUnlockingTx(t, stakingOutputPkScript, unlockingTx, nil)
	// // require.NoError(t, err)
	// // _, err = SignUnlockingTx(t, stakingOutputPkScript, unlockingTx, unlockingTxStakerSig)
	// require.NoError(t, err)
}

func CreateCovenantKeys(t *testing.T) []*btcec.PublicKey {
	localCovenantKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, localCovenantKey)

	remoteCovenantKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, remoteCovenantKey1)

	remoteCovenantKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, remoteCovenantKey2)
	covenantPks := []*btcec.PublicKey{
		localCovenantKey.PubKey(),
		remoteCovenantKey1.PubKey(),
		remoteCovenantKey2.PubKey(),
	}
	return covenantPks
}

func CreateBondingTx(tm *TestManager, bondingAmount uint64, destChainId []byte, userAddress []byte,
	smartContractAddress []byte, mintAmount []byte) *wire.MsgTx {
	info, err := btcvault.BuildV0IdentifiableVaultOutputs(
		tm.MagicBytes,
		tm.BondHolderPubkey,
		tm.ServiceKey.PubKey(),
		tm.AllCovenantKeys,
		tm.CovenantQuorum,
		btcutil.Amount(bondingAmount),
		destChainId,
		userAddress,
		smartContractAddress,
		mintAmount,
		&net,
	)
	require.NoError(tm.t, err)
	// staking output will always have index 0
	tx, err := tm.btcClient.CreateAndSignTx(
		[]*wire.TxOut{info.StakingOutput, info.OpReturnOutput},
		d.stakingFeeRate,
		tm.walletAddress,
	)
	require.NoError(tm.t, err)
}

func SignBondingTx(t *testing.T) {

}

func CreateUnlockingTx(t *testing.T, stakerPubKey *btcec.PublicKey,
	dAppPubKey *btcec.PublicKey,
	value int64,
	stakingTxHash chainhash.Hash,
	covenantPubkeys []*btcec.PublicKey,
	covenantQuorum uint32,
	feeAmount btcutil.Amount) *wire.MsgTx {
	vaultInfo, err := btcvault.BuildVaultInfo(stakerPubKey,
		[]*btcec.PublicKey{dAppPubKey},
		covenantPubkeys,
		covenantQuorum,
		btcutil.Amount(value-int64(feeAmount)),
		&net)
	// unbondingInfo, err := btcstaking.BuildUnbondingInfo(
	// 	stakerPubKey,
	// 	[]*btcec.PublicKey{dAppPubKey},
	// 	params.CovenantPublicKeys,
	// 	params.CovenantQuorum,
	// 	params.UnbondingTime,
	// 	btcutil.Amount(value-int64(params.UnbondingFee)),
	// 	&net,
	// )
	require.NoError(t, err)
	unlockingTx := wire.NewMsgTx(wire.TxVersion)
	//Create outpoint from stakingTxHash with fist output
	outpoint := wire.NewOutPoint(&stakingTxHash, 0)
	unlockingTx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
	// unlockingTx.AddTxOut(unbondingInfo.UnbondingOutput)
	unlockingTx.AddTxOut(vaultInfo.VaultOutput)
	return unlockingTx
}

func SignUnlockingTx(t *testing.T,
	stakingOutputPkScript []byte,
	unlockingTx *wire.MsgTx,
	unlockingTxStakerSig *schnorr.Signature) (*schnorr.Signature, error) {
	deps := NewMockedDependencies(t)
	signerApp := signerapp.NewSignerApp(deps.s, deps.bi, deps.pr, &net)
	receivedSignature, err := signerApp.SignUnbondingTransaction(
		context.Background(),
		stakingOutputPkScript,
		unlockingTx,
		unlockingTxStakerSig,
		deps.params.CovenantPublicKeys[0],
	)

	require.NoError(t, err)
	require.NotNil(t, receivedSignature)
	return receivedSignature, err
}
