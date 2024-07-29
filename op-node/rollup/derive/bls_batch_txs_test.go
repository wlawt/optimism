package derive

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum-optimism/optimism/op-service/testutils"
)

func TestBLSBatchTxsContractCreationBits(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234567))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	contractCreationBits := rawBLSBatch.txs.contractCreationBits
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.contractCreationBits = contractCreationBits
	sbt.totalBlockTxCount = totalBlockTxCount

	var buf bytes.Buffer
	err := sbt.encodeContractCreationBits(&buf)
	require.NoError(t, err)

	// contractCreationBit field is fixed length: single bit
	contractCreationBitBufferLen := totalBlockTxCount / 8
	if totalBlockTxCount%8 != 0 {
		contractCreationBitBufferLen++
	}
	require.Equal(t, buf.Len(), int(contractCreationBitBufferLen))

	result := buf.Bytes()
	sbt.contractCreationBits = nil

	r := bytes.NewReader(result)
	err = sbt.decodeContractCreationBits(r)
	require.NoError(t, err)

	require.Equal(t, contractCreationBits, sbt.contractCreationBits)
}

func TestBLSBatchTxsContractCreationCount(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1337))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	contractCreationBits := rawBLSBatch.txs.contractCreationBits
	contractCreationCount, err := rawBLSBatch.txs.contractCreationCount()
	require.NoError(t, err)
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.contractCreationBits = contractCreationBits
	sbt.totalBlockTxCount = totalBlockTxCount

	var buf bytes.Buffer
	err = sbt.encodeContractCreationBits(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	sbt.contractCreationBits = nil

	r := bytes.NewReader(result)
	err = sbt.decodeContractCreationBits(r)
	require.NoError(t, err)

	contractCreationCount2, err := sbt.contractCreationCount()
	require.NoError(t, err)

	require.Equal(t, contractCreationCount, contractCreationCount2)
}

func TestBLSBatchTxsTxNonces(t *testing.T) {
	rng := rand.New(rand.NewSource(0x123456))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	txNonces := rawBLSBatch.txs.txNonces
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.totalBlockTxCount = totalBlockTxCount
	sbt.txNonces = txNonces

	var buf bytes.Buffer
	err := sbt.encodeTxNonces(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	sbt.txNonces = nil

	r := bytes.NewReader(result)
	err = sbt.decodeTxNonces(r)
	require.NoError(t, err)

	require.Equal(t, txNonces, sbt.txNonces)
}

func TestBLSBatchTxsTxGases(t *testing.T) {
	rng := rand.New(rand.NewSource(0x12345))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	txGases := rawBLSBatch.txs.txGases
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.totalBlockTxCount = totalBlockTxCount
	sbt.txGases = txGases

	var buf bytes.Buffer
	err := sbt.encodeTxGases(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	sbt.txGases = nil

	r := bytes.NewReader(result)
	err = sbt.decodeTxGases(r)
	require.NoError(t, err)

	require.Equal(t, txGases, sbt.txGases)
}

func TestBLSBatchTxsTxTos(t *testing.T) {
	rng := rand.New(rand.NewSource(0x54321))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	txTos := rawBLSBatch.txs.txTos
	contractCreationBits := rawBLSBatch.txs.contractCreationBits
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.txTos = txTos
	// creation bits and block tx count must be se to decode tos
	sbt.contractCreationBits = contractCreationBits
	sbt.totalBlockTxCount = totalBlockTxCount

	var buf bytes.Buffer
	err := sbt.encodeTxTos(&buf)
	require.NoError(t, err)

	// to field is fixed length: 20 bytes
	require.Equal(t, buf.Len(), 20*len(txTos))

	result := buf.Bytes()
	sbt.txTos = nil

	r := bytes.NewReader(result)
	err = sbt.decodeTxTos(r)
	require.NoError(t, err)

	require.Equal(t, txTos, sbt.txTos)
}

func TestBLSBatchTxsTxDatas(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	txDatas := rawBLSBatch.txs.txDatas
	txTypes := rawBLSBatch.txs.txTypes
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.totalBlockTxCount = totalBlockTxCount

	sbt.txDatas = txDatas

	var buf bytes.Buffer
	err := sbt.encodeTxDatas(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	sbt.txDatas = nil
	sbt.txTypes = nil

	r := bytes.NewReader(result)
	err = sbt.decodeTxDatas(r)
	require.NoError(t, err)

	require.Equal(t, txDatas, sbt.txDatas)
	require.Equal(t, txTypes, sbt.txTypes)
}
func TestBLSBatchTxsAddTxs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234))
	chainID := big.NewInt(rng.Int63n(1000))
	// make batches to extract txs from
	batches := RandomValidConsecutiveSingularBLSBatches(rng, chainID)
	allTxs := [][]byte{}

	iterativeSBTX, err := newBLSBatchTxs([][]byte{}, chainID)
	require.NoError(t, err)
	for i := 0; i < len(batches); i++ {
		// explicitly extract txs due to mismatch of [][]byte to []hexutil.Bytes
		txs := [][]byte{}
		for j := 0; j < len(batches[i].Transactions); j++ {
			txs = append(txs, batches[i].Transactions[j])
		}
		err = iterativeSBTX.AddTxs(txs, chainID)
		require.NoError(t, err)
		allTxs = append(allTxs, txs...)
	}

	fullSBTX, err := newBLSBatchTxs(allTxs, chainID)
	require.NoError(t, err)

	require.Equal(t, iterativeSBTX, fullSBTX)
}

func TestBLSBatchTxsRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(0x73311337))
	chainID := big.NewInt(rng.Int63n(1000))

	for i := 0; i < 4; i++ {
		rawBLSBatch := RandomRawBLSBatch(rng, chainID)
		sbt := rawBLSBatch.txs
		totalBlockTxCount := sbt.totalBlockTxCount

		var buf bytes.Buffer
		err := sbt.encode(&buf)
		require.NoError(t, err)

		result := buf.Bytes()
		r := bytes.NewReader(result)

		var sbt2 blsBatchTxs
		sbt2.totalBlockTxCount = totalBlockTxCount
		err = sbt2.decode(r)
		require.NoError(t, err)

		require.Equal(t, sbt, &sbt2)
	}
}

func TestBLSBatchTxsRoundTripFullTxs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x13377331))
	chainID := big.NewInt(rng.Int63n(1000))

	cases := []txTypeTest{
		{"bls fee tx", testutils.RandomBLSTx, types.NewBLSSigner(chainID)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			for i := 0; i < 4; i++ {
				totalblockTxCounts := uint64(1 + rng.Int()&0xFF)
				var txs [][]byte
				for i := 0; i < int(totalblockTxCounts); i++ {
					tx := testCase.mkTx(rng, testCase.signer)
					rawTx, err := tx.MarshalBinary()
					require.NoError(t, err)
					txs = append(txs, rawTx)
				}
				sbt, err := newBLSBatchTxs(txs, chainID)
				require.NoError(t, err)

				txs2, err := sbt.fullTxs(chainID)
				require.NoError(t, err)

				require.Equal(t, txs, txs2)
			}
		})
	}
}

func TestBLSBatchTxsFullTxNotEnoughTxTos(t *testing.T) {
	rng := rand.New(rand.NewSource(0x13572468))
	chainID := big.NewInt(rng.Int63n(1000))

	cases := []txTypeTest{
		{"bls fee tx", testutils.RandomBLSTx, types.NewBLSSigner(chainID)},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			totalblockTxCounts := uint64(1 + rng.Int()&0xFF)
			var txs [][]byte
			for i := 0; i < int(totalblockTxCounts); i++ {
				tx := testCase.mkTx(rng, testCase.signer)
				rawTx, err := tx.MarshalBinary()
				require.NoError(t, err)
				txs = append(txs, rawTx)
			}
			sbt, err := newBLSBatchTxs(txs, chainID)
			require.NoError(t, err)

			// drop single to field
			sbt.txTos = sbt.txTos[:len(sbt.txTos)-2]

			_, err = sbt.fullTxs(chainID)
			require.EqualError(t, err, "tx to not enough")
		})
	}
}

func TestBLSBatchTxsMaxContractCreationBitsLength(t *testing.T) {
	var sbt blsBatchTxs
	sbt.totalBlockTxCount = 0xFFFFFFFFFFFFFFFF

	r := bytes.NewReader([]byte{})
	err := sbt.decodeContractCreationBits(r)
	require.ErrorIs(t, err, ErrTooBigBLSBatchSize)
}
