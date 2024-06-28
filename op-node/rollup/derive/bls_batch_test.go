package derive

import (
	"bytes"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/testutils"
)

// initializedBLSBatch creates a new BLSBatch with given SingularBatches.
// It is used *only* in tests to create a BLSBatch with given SingularBatches as a convenience.
// It will also ignore any errors that occur during AppendSingularBatch.
// Tests should manually set the first bit of the originBits if needed using SetFirstOriginChangedBit
func initializedBLSBatch(singularBatches []*SingularBatch, genesisTimestamp uint64, chainID *big.Int) *BLSBatch {
	blsBatch := NewBLSBatch(genesisTimestamp, chainID)
	if len(singularBatches) == 0 {
		return blsBatch
	}
	for i := 0; i < len(singularBatches); i++ {
		if err := blsBatch.AppendSingularBatch(singularBatches[i], uint64(i)); err != nil {
			continue
		}
	}
	return blsBatch
}

// setFirstOriginChangedBit sets the first bit of the originBits to the given value
// used for testing when a Span Batch is made with InitializedBLSBatch, which doesn't have a sequence number
func (b *BLSBatch) setFirstOriginChangedBit(bit uint) {
	b.originBits.SetBit(b.originBits, 0, bit)
}

func TestBLSBatchForBatchInterface(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5432177))
	chainID := big.NewInt(rng.Int63n(1000))

	singularBatches := RandomValidConsecutiveSingularBatches(rng, chainID)
	blockCount := len(singularBatches)
	safeL2Head := testutils.RandomL2BlockRef(rng)
	safeL2Head.Hash = common.BytesToHash(singularBatches[0].ParentHash[:])

	blsBatch := initializedBLSBatch(singularBatches, uint64(0), chainID)

	// check interface method implementations except logging
	require.Equal(t, BLSBatchType, blsBatch.GetBatchType())
	require.Equal(t, singularBatches[0].Timestamp, blsBatch.GetTimestamp())
	require.Equal(t, singularBatches[0].EpochNum, blsBatch.GetStartEpochNum())
	require.True(t, blsBatch.CheckOriginHash(singularBatches[blockCount-1].EpochHash))
	require.True(t, blsBatch.CheckParentHash(singularBatches[0].ParentHash))
}

func TestEmptyBLSBatch(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556691))
	chainID := big.NewInt(rng.Int63n(1000))
	blsTxs, err := newBLSBatchTxs(nil, chainID)
	require.NoError(t, err)

	rawBLSBatch := RawBLSBatch{
		blsBatchPrefix: blsBatchPrefix{
			relTimestamp:  uint64(rng.Uint32()),
			l1OriginNum:   rng.Uint64(),
			parentCheck:   *(*[20]byte)(testutils.RandomData(rng, 20)),
			l1OriginCheck: *(*[20]byte)(testutils.RandomData(rng, 20)),
		},
		blsBatchPayload: blsBatchPayload{
			blockCount:    0,
			originBits:    big.NewInt(0),
			blockTxCounts: []uint64{},
			txs:           blsTxs,
		},
	}

	var buf bytes.Buffer
	err = rawBLSBatch.encodeBlockCount(&buf)
	assert.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch

	err = sb.decodeBlockCount(r)
	require.ErrorIs(t, err, ErrEmptyBLSBatch)
}

func TestBLSBatchOriginBits(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77665544))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	blockCount := rawBLSBatch.blockCount

	var buf bytes.Buffer
	err := rawBLSBatch.encodeOriginBits(&buf)
	require.NoError(t, err)

	// originBit field is fixed length: single bit
	originBitBufferLen := blockCount / 8
	if blockCount%8 != 0 {
		originBitBufferLen++
	}
	require.Equal(t, buf.Len(), int(originBitBufferLen))

	result := buf.Bytes()
	var sb RawBLSBatch
	sb.blockCount = blockCount
	r := bytes.NewReader(result)
	err = sb.decodeOriginBits(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.originBits, sb.originBits)
}

func TestBLSBatchPrefix(t *testing.T) {
	rng := rand.New(rand.NewSource(0x44775566))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	// only compare prefix
	rawBLSBatch.blsBatchPayload = blsBatchPayload{}

	var buf bytes.Buffer
	err := rawBLSBatch.encodePrefix(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	err = sb.decodePrefix(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch, &sb)
}

func TestBLSBatchRelTimestamp(t *testing.T) {
	rng := rand.New(rand.NewSource(0x44775566))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodeRelTimestamp(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	err = sb.decodeRelTimestamp(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.relTimestamp, sb.relTimestamp)
}

func TestBLSBatchL1OriginNum(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556688))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodeL1OriginNum(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	err = sb.decodeL1OriginNum(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.l1OriginNum, sb.l1OriginNum)
}

func TestBLSBatchParentCheck(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556689))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodeParentCheck(&buf)
	require.NoError(t, err)

	// parent check field is fixed length: 20 bytes
	require.Equal(t, buf.Len(), 20)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	err = sb.decodeParentCheck(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.parentCheck, sb.parentCheck)
}

func TestBLSBatchL1OriginCheck(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556690))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodeL1OriginCheck(&buf)
	require.NoError(t, err)

	// l1 origin check field is fixed length: 20 bytes
	require.Equal(t, buf.Len(), 20)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	err = sb.decodeL1OriginCheck(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.l1OriginCheck, sb.l1OriginCheck)
}

func TestBLSBatchPayload(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556691))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodePayload(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch

	err = sb.decodePayload(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.blsBatchPayload, sb.blsBatchPayload)
}

func TestBLSBatchBlockCount(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556691))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodeBlockCount(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch

	err = sb.decodeBlockCount(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.blockCount, sb.blockCount)
}

func TestBLSBatchBlockTxCounts(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556692))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodeBlockTxCounts(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch

	sb.blockCount = rawBLSBatch.blockCount
	err = sb.decodeBlockTxCounts(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.blockTxCounts, sb.blockTxCounts)
}

func TestBLSBatchTxs(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556693))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var buf bytes.Buffer
	err := rawBLSBatch.encodeTxs(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch

	sb.blockTxCounts = rawBLSBatch.blockTxCounts
	err = sb.decodeTxs(r)
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch.txs, sb.txs)
}

func TestBLSBatchRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556694))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)

	var result bytes.Buffer
	err := rawBLSBatch.encode(&result)
	require.NoError(t, err)

	var sb RawBLSBatch
	err = sb.decode(bytes.NewReader(result.Bytes()))
	require.NoError(t, err)

	require.Equal(t, rawBLSBatch, &sb)
}

func TestBLSBatchDerive(t *testing.T) {
	rng := rand.New(rand.NewSource(0xbab0bab0))

	chainID := new(big.Int).SetUint64(rng.Uint64())
	l2BlockTime := uint64(2)

	for originChangedBit := 0; originChangedBit < 2; originChangedBit++ {
		singularBatches := RandomValidConsecutiveSingularBLSBatches(rng, chainID)
		safeL2Head := testutils.RandomL2BlockRef(rng)
		safeL2Head.Hash = common.BytesToHash(singularBatches[0].ParentHash[:])
		genesisTimeStamp := 1 + singularBatches[0].Timestamp - 128

		spanBatch := initializedBLSBatch(singularBatches, genesisTimeStamp, chainID)
		// set originChangedBit to match the original test implementation
		spanBatch.setFirstOriginChangedBit(uint(originChangedBit))
		rawSpanBatch, err := spanBatch.ToRawBLSBatch()
		require.NoError(t, err)

		spanBatchDerived, err := rawSpanBatch.derive(l2BlockTime, genesisTimeStamp, chainID)
		require.NoError(t, err)

		blockCount := len(singularBatches)
		require.Equal(t, safeL2Head.Hash.Bytes()[:20], spanBatchDerived.ParentCheck[:])
		require.Equal(t, singularBatches[blockCount-1].Epoch().Hash.Bytes()[:20], spanBatchDerived.L1OriginCheck[:])
		require.Equal(t, len(singularBatches), int(rawSpanBatch.blockCount))

		for i := 1; i < len(singularBatches); i++ {
			require.Equal(t, spanBatchDerived.Batches[i].Timestamp, spanBatchDerived.Batches[i-1].Timestamp+l2BlockTime)
		}

		for i := 0; i < len(singularBatches); i++ {
			require.Equal(t, singularBatches[i].EpochNum, spanBatchDerived.Batches[i].EpochNum)
			require.Equal(t, singularBatches[i].Timestamp, spanBatchDerived.Batches[i].Timestamp)
			require.Equal(t, singularBatches[i].Transactions, spanBatchDerived.Batches[i].Transactions)
		}
	}
}

func TestBLSBatchMerge(t *testing.T) {
	rng := rand.New(rand.NewSource(0x73314433))

	genesisTimeStamp := rng.Uint64()
	chainID := new(big.Int).SetUint64(rng.Uint64())

	for originChangedBit := 0; originChangedBit < 2; originChangedBit++ {
		singularBatches := RandomValidConsecutiveSingularBatches(rng, chainID)
		blockCount := len(singularBatches)

		spanBatch := initializedBLSBatch(singularBatches, genesisTimeStamp, chainID)
		// set originChangedBit to match the original test implementation
		spanBatch.setFirstOriginChangedBit(uint(originChangedBit))
		rawBLSBatch, err := spanBatch.ToRawBLSBatch()
		require.NoError(t, err)

		// check span batch prefix
		require.Equal(t, rawBLSBatch.relTimestamp, singularBatches[0].Timestamp-genesisTimeStamp, "invalid relative timestamp")
		require.Equal(t, rollup.Epoch(rawBLSBatch.l1OriginNum), singularBatches[blockCount-1].EpochNum)
		require.Equal(t, rawBLSBatch.parentCheck[:], singularBatches[0].ParentHash.Bytes()[:20], "invalid parent check")
		require.Equal(t, rawBLSBatch.l1OriginCheck[:], singularBatches[blockCount-1].EpochHash.Bytes()[:20], "invalid l1 origin check")

		// check span batch payload
		require.Equal(t, int(rawBLSBatch.blockCount), len(singularBatches))
		require.Equal(t, rawBLSBatch.originBits.Bit(0), uint(originChangedBit))
		for i := 1; i < blockCount; i++ {
			if rawBLSBatch.originBits.Bit(i) == 1 {
				require.Equal(t, singularBatches[i].EpochNum, singularBatches[i-1].EpochNum+1)
			} else {
				require.Equal(t, singularBatches[i].EpochNum, singularBatches[i-1].EpochNum)
			}
		}
		for i := 0; i < len(singularBatches); i++ {
			txCount := len(singularBatches[i].Transactions)
			require.Equal(t, txCount, int(rawBLSBatch.blockTxCounts[i]))
		}

		// check invariants
		endEpochNum := rawBLSBatch.l1OriginNum
		require.Equal(t, endEpochNum, uint64(singularBatches[blockCount-1].EpochNum))

		// we do not check txs field because it has to be derived to be compared
	}
}

func TestBLSBatchReadTxData(t *testing.T) {
	cases := []spanBatchTxTest{
		{"bls fee tx", 32, testutils.RandomBLSTx, true},
	}

	for i, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(0x109550 + i)))
			chainID := new(big.Int).SetUint64(rng.Uint64())
			signer := types.NewBLSSigner(chainID)

			var rawTxs [][]byte
			var txs []*types.Transaction
			for txIdx := 0; txIdx < testCase.trials; txIdx++ {
				tx := testCase.mkTx(rng, signer)
				rawTx, err := tx.MarshalBinary()
				require.NoError(t, err)
				rawTxs = append(rawTxs, rawTx)
				txs = append(txs, tx)
			}

			for txIdx := 0; txIdx < testCase.trials; txIdx++ {
				r := bytes.NewReader(rawTxs[i])
				_, txType, err := ReadTxData(r)
				require.NoError(t, err)
				assert.Equal(t, int(txs[i].Type()), txType)
			}
		})
	}
}

func TestBLSBatchReadTxDataInvalid(t *testing.T) {
	dummy, err := rlp.EncodeToBytes("dummy")
	require.NoError(t, err)

	// test non list rlp decoding
	r := bytes.NewReader(dummy)
	_, _, err = ReadTxData(r)
	require.ErrorContains(t, err, "tx RLP prefix type must be list")
}

func TestBLSBatchMaxTxData(t *testing.T) {
	rng := rand.New(rand.NewSource(0x177288))

	invalidTx := types.NewTx(&types.DynamicFeeTx{
		Data: testutils.RandomData(rng, MaxSpanBatchElementCount+1),
	})

	txEncoded, err := invalidTx.MarshalBinary()
	require.NoError(t, err)

	r := bytes.NewReader(txEncoded)
	_, _, err = ReadTxData(r)

	require.ErrorIs(t, err, ErrTooBigSpanBatchSize)
}

func TestBLSBatchMaxOriginBitsLength(t *testing.T) {
	var sb RawBLSBatch
	sb.blockCount = math.MaxUint64

	r := bytes.NewReader([]byte{})
	err := sb.decodeOriginBits(r)
	require.ErrorIs(t, err, ErrTooBigBLSBatchSize)
}

func TestBLSBatchMaxBlockCount(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556691))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	rawBLSBatch.blockCount = math.MaxUint64

	var buf bytes.Buffer
	err := rawBLSBatch.encodeBlockCount(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	err = sb.decodeBlockCount(r)
	require.ErrorIs(t, err, ErrTooBigBLSBatchSize)
}

func TestBLSBatchMaxBlockTxCount(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556692))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	rawBLSBatch.blockTxCounts[0] = math.MaxUint64

	var buf bytes.Buffer
	err := rawBLSBatch.encodeBlockTxCounts(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	sb.blockCount = rawBLSBatch.blockCount
	err = sb.decodeBlockTxCounts(r)
	require.ErrorIs(t, err, ErrTooBigBLSBatchSize)
}

func TestBLSBatchTotalBlockTxCountNotOverflow(t *testing.T) {
	rng := rand.New(rand.NewSource(0x77556693))
	chainID := big.NewInt(rng.Int63n(1000))

	rawBLSBatch := RandomRawBLSBatch(rng, chainID)
	rawBLSBatch.blockTxCounts[0] = MaxSpanBatchElementCount - 1
	rawBLSBatch.blockTxCounts[1] = MaxSpanBatchElementCount - 1
	// we are sure that totalBlockTxCount will overflow on uint64

	var buf bytes.Buffer
	err := rawBLSBatch.encodeBlockTxCounts(&buf)
	require.NoError(t, err)

	result := buf.Bytes()
	r := bytes.NewReader(result)
	var sb RawBLSBatch
	sb.blockTxCounts = rawBLSBatch.blockTxCounts
	err = sb.decodeTxs(r)

	require.ErrorIs(t, err, ErrTooBigBLSBatchSize)
}
