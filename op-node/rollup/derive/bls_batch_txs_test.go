package derive

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"

	"github.com/holiman/uint256"
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

func TestBLSBatchTxsYParityBits(t *testing.T) {
	rng := rand.New(rand.NewSource(0x7331))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	yParityBits := rawBLSBatch.txs.yParityBits
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.yParityBits = yParityBits
	sbt.totalBlockTxCount = totalBlockTxCount

	var buf bytes.Buffer
	err := sbt.encodeYParityBits(&buf)
	require.NoError(t, err)

	// yParityBit field is fixed length: single bit
	yParityBitBufferLen := totalBlockTxCount / 8
	if totalBlockTxCount%8 != 0 {
		yParityBitBufferLen++
	}
	require.Equal(t, buf.Len(), int(yParityBitBufferLen))

	result := buf.Bytes()
	sbt.yParityBits = nil

	r := bytes.NewReader(result)
	err = sbt.decodeYParityBits(r)
	require.NoError(t, err)

	require.Equal(t, yParityBits, sbt.yParityBits)
}

func TestBLSBatchTxsProtectedBits(t *testing.T) {
	rng := rand.New(rand.NewSource(0x7331))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	protectedBits := rawBLSBatch.txs.protectedBits
	txTypes := rawBLSBatch.txs.txTypes
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount
	totalLegacyTxCount := rawBLSBatch.txs.totalLegacyTxCount

	var sbt blsBatchTxs
	sbt.protectedBits = protectedBits
	sbt.totalBlockTxCount = totalBlockTxCount
	sbt.txTypes = txTypes
	sbt.totalLegacyTxCount = totalLegacyTxCount

	var buf bytes.Buffer
	err := sbt.encodeProtectedBits(&buf)
	require.NoError(t, err)

	// protectedBit field is fixed length: single bit
	protectedBitBufferLen := totalLegacyTxCount / 8
	require.NoError(t, err)
	if totalLegacyTxCount%8 != 0 {
		protectedBitBufferLen++
	}
	require.Equal(t, buf.Len(), int(protectedBitBufferLen))

	result := buf.Bytes()
	sbt.protectedBits = nil

	r := bytes.NewReader(result)
	err = sbt.decodeProtectedBits(r)
	require.NoError(t, err)

	require.Equal(t, protectedBits, sbt.protectedBits)
}

func TestBLSBatchTxsTxSigs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x73311337))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	txSigs := rawBLSBatch.txs.txSigs
	totalBlockTxCount := rawBLSBatch.txs.totalBlockTxCount

	var sbt blsBatchTxs
	sbt.totalBlockTxCount = totalBlockTxCount
	sbt.txSigs = txSigs

	var buf bytes.Buffer
	err := sbt.encodeTxSigsRS(&buf)
	require.NoError(t, err)

	// txSig field is fixed length: 32 byte + 32 byte = 64 byte
	require.Equal(t, buf.Len(), 64*int(totalBlockTxCount))

	result := buf.Bytes()
	sbt.txSigs = nil

	r := bytes.NewReader(result)
	err = sbt.decodeTxSigsRS(r)
	require.NoError(t, err)

	// v field is not set
	for i := 0; i < int(totalBlockTxCount); i++ {
		require.Equal(t, txSigs[i].r, sbt.txSigs[i].r)
		require.Equal(t, txSigs[i].s, sbt.txSigs[i].s)
	}
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

func TestBLSBatchTxsRecoverV(t *testing.T) {
	rng := rand.New(rand.NewSource(0x123))

	chainID := big.NewInt(rng.Int63n(1000))
	londonSigner := types.NewLondonSigner(chainID)
	totalblockTxCount := 20 + rng.Intn(100)

	cases := []txTypeTest{
		{"unprotected legacy tx", testutils.RandomLegacyTx, types.HomesteadSigner{}},
		{"legacy tx", testutils.RandomLegacyTx, londonSigner},
		{"access list tx", testutils.RandomAccessListTx, londonSigner},
		{"dynamic fee tx", testutils.RandomDynamicFeeTx, londonSigner},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var blsBatchTxs blsBatchTxs
			var txTypes []int
			var txSigs []spanBatchSignature
			var originalVs []uint64
			yParityBits := new(big.Int)
			protectedBits := new(big.Int)
			totalLegacyTxCount := 0
			for idx := 0; idx < totalblockTxCount; idx++ {
				tx := testCase.mkTx(rng, testCase.signer)
				txType := tx.Type()
				txTypes = append(txTypes, int(txType))
				var txSig spanBatchSignature
				v, r, s := tx.RawSignatureValues()
				if txType == types.LegacyTxType {
					protectedBit := uint(0)
					if tx.Protected() {
						protectedBit = uint(1)
					}
					protectedBits.SetBit(protectedBits, int(totalLegacyTxCount), protectedBit)
					totalLegacyTxCount++
				}
				// Do not fill in txSig.V
				txSig.r, _ = uint256.FromBig(r)
				txSig.s, _ = uint256.FromBig(s)
				txSigs = append(txSigs, txSig)
				originalVs = append(originalVs, v.Uint64())
				yParityBit, err := convertVToYParity(v.Uint64(), int(tx.Type()))
				require.NoError(t, err)
				yParityBits.SetBit(yParityBits, idx, yParityBit)
			}

			blsBatchTxs.yParityBits = yParityBits
			blsBatchTxs.txSigs = txSigs
			blsBatchTxs.txTypes = txTypes
			blsBatchTxs.protectedBits = protectedBits
			// recover txSig.v
			err := blsBatchTxs.recoverV(chainID)
			require.NoError(t, err)

			var recoveredVs []uint64
			for _, txSig := range blsBatchTxs.txSigs {
				recoveredVs = append(recoveredVs, txSig.v)
			}
			require.Equal(t, originalVs, recoveredVs, "recovered v mismatch")
		})
	}
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

		err = sbt2.recoverV(chainID)
		require.NoError(t, err)

		require.Equal(t, sbt, &sbt2)
	}
}

func TestBLSBatchTxsRoundTripFullTxs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x13377331))
	chainID := big.NewInt(rng.Int63n(1000))

	cases := []txTypeTest{
		{"bls fee tx", testutils.RandomBLSTx, types.NewBLSSigner(chainID)},
		{"unprotected legacy tx", testutils.RandomLegacyTx, types.NewLondonSigner(chainID)},
		{"legacy tx", testutils.RandomLegacyTx, types.NewLondonSigner(chainID)},
		{"access list tx", testutils.RandomAccessListTx, types.NewLondonSigner(chainID)},
		{"dynamic fee tx", testutils.RandomDynamicFeeTx, types.NewLondonSigner(chainID)},
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

func TestBLSBatchTxsRecoverVInvalidTxType(t *testing.T) {
	rng := rand.New(rand.NewSource(0x321))
	chainID := big.NewInt(rng.Int63n(1000))

	var sbt blsBatchTxs

	sbt.txTypes = []int{types.DepositTxType}
	sbt.txSigs = []spanBatchSignature{{v: 0, r: nil, s: nil}}
	sbt.yParityBits = new(big.Int)
	sbt.protectedBits = new(big.Int)

	err := sbt.recoverV(chainID)
	require.ErrorContains(t, err, "invalid tx type")
}

func TestBLSBatchTxsFullTxNotEnoughTxTos(t *testing.T) {
	rng := rand.New(rand.NewSource(0x13572468))
	chainID := big.NewInt(rng.Int63n(1000))

	cases := []txTypeTest{
		{"bls fee tx", testutils.RandomBLSTx, types.NewBLSSigner(chainID)},
		{"unprotected legacy tx", testutils.RandomLegacyTx, types.NewLondonSigner(chainID)},
		{"legacy tx", testutils.RandomLegacyTx, types.NewLondonSigner(chainID)},
		{"access list tx", testutils.RandomAccessListTx, types.NewLondonSigner(chainID)},
		{"dynamic fee tx", testutils.RandomDynamicFeeTx, types.NewLondonSigner(chainID)},
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

func TestBLSBatchTxsMaxYParityBitsLength(t *testing.T) {
	var sb RawBLSBatch
	sb.blockCount = 0xFFFFFFFFFFFFFFFF

	r := bytes.NewReader([]byte{})
	err := sb.decodeOriginBits(r)
	require.ErrorIs(t, err, ErrTooBigBLSBatchSize)
}

func TestBLSBatchTxsMaxProtectedBitsLength(t *testing.T) {
	var sb RawBLSBatch
	sb.txs = &blsBatchTxs{}
	sb.txs.totalLegacyTxCount = 0xFFFFFFFFFFFFFFFF

	r := bytes.NewReader([]byte{})
	err := sb.txs.decodeProtectedBits(r)
	require.ErrorIs(t, err, ErrTooBigBLSBatchSize)
}
