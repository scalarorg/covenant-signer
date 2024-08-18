package signerapp_test

import (
	"context"
	"testing"

	"github.com/babylonchain/babylon/btcstaking"
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
	testnet = &chaincfg.TestNet3Params
)

func CreateUnlockingTx(t *testing.T, stakerPubKey *btcec.PublicKey,
	dAppPubKey *btcec.PublicKey,
	value int64,
	stakingTxHash chainhash.Hash, params *signerapp.BabylonParams) *wire.MsgTx {
	btcvault.BuildVaultInfo()
	unbondingInfo, err := btcstaking.BuildUnbondingInfo(
		stakerPubKey,
		[]*btcec.PublicKey{dAppPubKey},
		params.CovenantPublicKeys,
		params.CovenantQuorum,
		params.UnbondingTime,
		btcutil.Amount(value-int64(params.UnbondingFee)),
		&net,
	)
	require.NoError(t, err)
	unlockingTx := wire.NewMsgTx(wire.TxVersion)
	//Create outpoint from stakingTxHash with fist output
	outpoint := wire.NewOutPoint(&stakingTxHash, 0)
	unlockingTx.AddTxIn(wire.NewTxIn(outpoint, nil, nil))
	unlockingTx.AddTxOut(unbondingInfo.UnbondingOutput)
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
