package derive

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/ethereum-optimism/optimism/op-service/testutils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blsBatchTxTest struct {
	name      string
	trials    int
	mkTx      func(rng *rand.Rand, signer types.Signer) *types.Transaction
	protected bool
}

func TestBLSBatchTxConvert(t *testing.T) {
	cases := []blsBatchTxTest{
		{"unprotected legacy tx", 32, testutils.RandomLegacyTx, false},
		{"legacy tx", 32, testutils.RandomLegacyTx, true},
		{"access list tx", 32, testutils.RandomAccessListTx, true},
		{"dynamic fee tx", 32, testutils.RandomDynamicFeeTx, true},
		{"bls fee tx", 32, testutils.RandomBLSTx, true},
	}

	for i, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(0x1331 + i)))
			chainID := big.NewInt(rng.Int63n(1000))
			signer := types.NewBLSSigner(chainID)
			if testCase.name != "bls fee tx" {
				signer = types.NewLondonSigner(chainID)
				if !testCase.protected {
					signer = types.HomesteadSigner{}
				}
			}

			for txIdx := 0; txIdx < testCase.trials; txIdx++ {
				tx := testCase.mkTx(rng, signer)

				blstx, err := newBLSBatchTx(*tx)
				require.NoError(t, err)

				v, r, s := tx.RawSignatureValues()
				tx2, err := blstx.convertToFullTx(tx.Nonce(), tx.Gas(), tx.To(), chainID, v, r, s)
				require.NoError(t, err)

				// compare after marshal because we only need inner field of transaction
				txEncoded, err := tx.MarshalBinary()
				require.NoError(t, err)
				tx2Encoded, err := tx2.MarshalBinary()
				require.NoError(t, err)

				assert.Equal(t, txEncoded, tx2Encoded)
			}
		})
	}
}

func TestBLSBatchTxRoundTrip(t *testing.T) {
	cases := []blsBatchTxTest{
		{"unprotected legacy tx", 32, testutils.RandomLegacyTx, false},
		{"legacy tx", 32, testutils.RandomLegacyTx, true},
		{"access list tx", 32, testutils.RandomAccessListTx, true},
		{"dynamic fee tx", 32, testutils.RandomDynamicFeeTx, true},
		{"bls fee tx", 32, testutils.RandomBLSTx, true},
	}

	for i, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(0x1332 + i)))
			chainID := big.NewInt(rng.Int63n(1000))
			signer := types.NewBLSSigner(chainID)
			if testCase.name != "bls fee tx" {
				signer = types.NewLondonSigner(chainID)
				if !testCase.protected {
					signer = types.HomesteadSigner{}
				}
			}

			for txIdx := 0; txIdx < testCase.trials; txIdx++ {
				tx := testCase.mkTx(rng, signer)

				sbtx, err := newBLSBatchTx(*tx)
				require.NoError(t, err)

				sbtxEncoded, err := sbtx.MarshalBinary()
				require.NoError(t, err)

				var sbtx2 blsBatchTx
				err = sbtx2.UnmarshalBinary(sbtxEncoded)
				require.NoError(t, err)

				assert.Equal(t, sbtx, &sbtx2)
			}
		})
	}
}

type blsBatchDummyTxData struct{}

func (txData *blsBatchDummyTxData) txType() byte { return types.DepositTxType }

func TestBLSBatchTxInvalidTxType(t *testing.T) {
	// span batch never contain deposit tx
	depositTx := types.NewTx(&types.DepositTx{})
	_, err := newBLSBatchTx(*depositTx)
	require.ErrorContains(t, err, "invalid tx type")

	var blstx blsBatchTx
	blstx.inner = &blsBatchDummyTxData{}
	_, err = blstx.convertToFullTx(0, 0, nil, nil, common.Big0, common.Big0, common.Big0)
	require.ErrorContains(t, err, "invalid tx type")
}

func TestBLSBatchTxDecodeInvalid(t *testing.T) {
	var sbtx blsBatchTx
	_, err := sbtx.decodeTyped([]byte{})
	require.ErrorIs(t, err, ErrTypedTxTooShort)

	tx := types.NewTx(&types.LegacyTx{})
	txEncoded, err := tx.MarshalBinary()
	require.NoError(t, err)

	// legacy tx is not typed tx
	_, err = sbtx.decodeTyped(txEncoded)
	require.EqualError(t, err, types.ErrTxTypeNotSupported.Error())

	tx2 := types.NewTx(&types.AccessListTx{})
	tx2Encoded, err := tx2.MarshalBinary()
	require.NoError(t, err)

	tx2Encoded[0] = types.DynamicFeeTxType
	_, err = sbtx.decodeTyped(tx2Encoded)
	require.ErrorContains(t, err, "transaction type not supported")

	tx3 := types.NewTx(&types.DynamicFeeTx{})
	tx3Encoded, err := tx3.MarshalBinary()
	require.NoError(t, err)

	tx3Encoded[0] = types.AccessListTxType
	_, err = sbtx.decodeTyped(tx3Encoded)
	require.ErrorContains(t, err, "transaction type not supported")
}
