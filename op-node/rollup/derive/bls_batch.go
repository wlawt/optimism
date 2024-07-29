package derive

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"
)

var ErrTooBigBLSBatchSize = errors.New("bls batch size limit reached")

var ErrEmptyBLSBatch = errors.New("bls-batch must not be empty")

type blsBatchPrefix struct {
	relTimestamp  uint64   // Relative timestamp of the first block
	l1OriginNum   uint64   // L1 origin number
	parentCheck   [20]byte // First 20 bytes of the first block's parent hash
	l1OriginCheck [20]byte // First 20 bytes of the last block's L1 origin hash
}

type blsBatchPayload struct {
	blockCount    uint64
	originBits    *big.Int
	blockTxCounts []uint64     // List of transaction counts for each L2 block
	txs           *blsBatchTxs // Transactions encoded in BLSBatch specs
	aggregatedSig []byte
}

// RawBLSBatch is another representation of BLSBatch, that encodes data according to BLSBatch specs.
type RawBLSBatch struct {
	blsBatchPrefix
	blsBatchPayload
}

// GetBatchType returns its batch type (batch_version)
func (b *RawBLSBatch) GetBatchType() int {
	return BLSBatchType
}

// decodeOriginBits parses data into bp.originBits
func (bp *blsBatchPayload) decodeOriginBits(r *bytes.Reader) error {
	if bp.blockCount > MaxSpanBatchElementCount {
		return ErrTooBigBLSBatchSize
	}
	bits, err := decodeSpanBatchBits(r, bp.blockCount)
	if err != nil {
		return fmt.Errorf("failed to decode origin bits: %w", err)
	}
	bp.originBits = bits
	return nil
}

// decodeRelTimestamp parses data into bp.relTimestamp
func (bp *blsBatchPrefix) decodeRelTimestamp(r *bytes.Reader) error {
	relTimestamp, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("failed to read rel timestamp: %w", err)
	}
	bp.relTimestamp = relTimestamp
	return nil
}

// decodeL1OriginNum parses data into bp.l1OriginNum
func (bp *blsBatchPrefix) decodeL1OriginNum(r *bytes.Reader) error {
	L1OriginNum, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("failed to read l1 origin num: %w", err)
	}
	bp.l1OriginNum = L1OriginNum
	return nil
}

// decodeParentCheck parses data into bp.parentCheck
func (bp *blsBatchPrefix) decodeParentCheck(r *bytes.Reader) error {
	_, err := io.ReadFull(r, bp.parentCheck[:])
	if err != nil {
		return fmt.Errorf("failed to read parent check: %w", err)
	}
	return nil
}

// decodeL1OriginCheck parses data into bp.decodeL1OriginCheck
func (bp *blsBatchPrefix) decodeL1OriginCheck(r *bytes.Reader) error {
	_, err := io.ReadFull(r, bp.l1OriginCheck[:])
	if err != nil {
		return fmt.Errorf("failed to read l1 origin check: %w", err)
	}
	return nil
}

// decodePrefix parses data into bp.blsBatchPrefix
func (bp *blsBatchPrefix) decodePrefix(r *bytes.Reader) error {
	if err := bp.decodeRelTimestamp(r); err != nil {
		return err
	}
	if err := bp.decodeL1OriginNum(r); err != nil {
		return err
	}
	if err := bp.decodeParentCheck(r); err != nil {
		return err
	}
	if err := bp.decodeL1OriginCheck(r); err != nil {
		return err
	}
	return nil
}

// decodeBlockCount parses data into bp.blockCount
func (bp *blsBatchPayload) decodeBlockCount(r *bytes.Reader) error {
	blockCount, err := binary.ReadUvarint(r)
	if err != nil {
		return fmt.Errorf("failed to read block count: %w", err)
	}

	if blockCount > MaxSpanBatchElementCount {
		return ErrTooBigBLSBatchSize
	}
	if blockCount == 0 {
		return ErrEmptyBLSBatch
	}
	bp.blockCount = blockCount
	return nil
}

// decodeBlockTxCounts parses data into bp.blockTxCounts
// and sets bp.txs.totalBlockTxCount as sum(bp.blockTxCounts)
func (bp *blsBatchPayload) decodeBlockTxCounts(r *bytes.Reader) error {
	var blockTxCounts []uint64
	for i := 0; i < int(bp.blockCount); i++ {
		blockTxCount, err := binary.ReadUvarint(r)
		if err != nil {
			return fmt.Errorf("failed to read block tx count: %w", err)
		}

		if blockTxCount > MaxSpanBatchElementCount {
			return ErrTooBigBLSBatchSize
		}
		blockTxCounts = append(blockTxCounts, blockTxCount)
	}
	bp.blockTxCounts = blockTxCounts
	return nil
}

// decodeTxs parses data into bp.txs
func (bp *blsBatchPayload) decodeTxs(r *bytes.Reader) error {
	if bp.txs == nil {
		bp.txs = &blsBatchTxs{}
	}
	if bp.blockTxCounts == nil {
		return errors.New("failed to read txs: blockTxCounts not set")
	}
	totalBlockTxCount := uint64(0)
	for i := 0; i < len(bp.blockTxCounts); i++ {
		total, overflow := math.SafeAdd(totalBlockTxCount, bp.blockTxCounts[i])
		if overflow {
			return ErrTooBigBLSBatchSize
		}
		totalBlockTxCount = total
	}

	if totalBlockTxCount > MaxSpanBatchElementCount {
		return ErrTooBigBLSBatchSize
	}
	bp.txs.totalBlockTxCount = totalBlockTxCount
	if err := bp.txs.decode(r); err != nil {
		return err
	}
	return nil
}

func (bp *blsBatchPayload) decodeAggregatedSig(r *bytes.Reader) error {
	aggSig, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read aggregated signature: %w", err)
	}
	bp.aggregatedSig = aggSig
	if len(aggSig) == 0 {
		bp.aggregatedSig = nil
	}
	return nil
}

// decodePayload parses data into bp.blsBatchPayload
func (bp *blsBatchPayload) decodePayload(r *bytes.Reader) error {
	if err := bp.decodeBlockCount(r); err != nil {
		return err
	}
	if err := bp.decodeOriginBits(r); err != nil {
		return err
	}
	if err := bp.decodeBlockTxCounts(r); err != nil {
		return err
	}
	if err := bp.decodeTxs(r); err != nil {
		return err
	}
	if err := bp.decodeAggregatedSig(r); err != nil {
		return err
	}
	return nil
}

// decode reads the byte encoding of BLSBatch from Reader stream
func (b *RawBLSBatch) decode(r *bytes.Reader) error {
	if err := b.decodePrefix(r); err != nil {
		return fmt.Errorf("failed to decode bls batch prefix: %w", err)
	}
	if err := b.decodePayload(r); err != nil {
		return fmt.Errorf("failed to decode bls batch payload: %w", err)
	}
	return nil
}

// encodeRelTimestamp encodes bp.relTimestamp
func (bp *blsBatchPrefix) encodeRelTimestamp(w io.Writer) error {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], bp.relTimestamp)
	if _, err := w.Write(buf[:n]); err != nil {
		return fmt.Errorf("cannot write rel timestamp: %w", err)
	}
	return nil
}

// encodeL1OriginNum encodes bp.l1OriginNum
func (bp *blsBatchPrefix) encodeL1OriginNum(w io.Writer) error {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], bp.l1OriginNum)
	if _, err := w.Write(buf[:n]); err != nil {
		return fmt.Errorf("cannot write l1 origin number: %w", err)
	}
	return nil
}

// encodeParentCheck encodes bp.parentCheck
func (bp *blsBatchPrefix) encodeParentCheck(w io.Writer) error {
	if _, err := w.Write(bp.parentCheck[:]); err != nil {
		return fmt.Errorf("cannot write parent check: %w", err)
	}
	return nil
}

// encodeL1OriginCheck encodes bp.l1OriginCheck
func (bp *blsBatchPrefix) encodeL1OriginCheck(w io.Writer) error {
	if _, err := w.Write(bp.l1OriginCheck[:]); err != nil {
		return fmt.Errorf("cannot write l1 origin check: %w", err)
	}
	return nil
}

// encodePrefix encodes blsBatchPrefix
func (bp *blsBatchPrefix) encodePrefix(w io.Writer) error {
	if err := bp.encodeRelTimestamp(w); err != nil {
		return err
	}
	if err := bp.encodeL1OriginNum(w); err != nil {
		return err
	}
	if err := bp.encodeParentCheck(w); err != nil {
		return err
	}
	if err := bp.encodeL1OriginCheck(w); err != nil {
		return err
	}
	return nil
}

// encodeOriginBits encodes bp.originBits
func (bp *blsBatchPayload) encodeOriginBits(w io.Writer) error {
	if err := encodeSpanBatchBits(w, bp.blockCount, bp.originBits); err != nil {
		return fmt.Errorf("failed to encode origin bits: %w", err)
	}
	return nil
}

// encodeBlockCount encodes bp.blockCount
func (bp *blsBatchPayload) encodeBlockCount(w io.Writer) error {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], bp.blockCount)
	if _, err := w.Write(buf[:n]); err != nil {
		return fmt.Errorf("cannot write block count: %w", err)
	}
	return nil
}

// encodeBlockTxCounts encodes bp.blockTxCounts
func (bp *blsBatchPayload) encodeBlockTxCounts(w io.Writer) error {
	var buf [binary.MaxVarintLen64]byte
	for _, blockTxCount := range bp.blockTxCounts {
		n := binary.PutUvarint(buf[:], blockTxCount)
		if _, err := w.Write(buf[:n]); err != nil {
			return fmt.Errorf("cannot write block tx count: %w", err)
		}
	}
	return nil
}

// encodeTxs encodes bp.txs
func (bp *blsBatchPayload) encodeTxs(w io.Writer) error {
	if bp.txs == nil {
		return errors.New("cannot write txs: txs not set")
	}
	if err := bp.txs.encode(w); err != nil {
		return err
	}
	return nil
}

func (bp *blsBatchPayload) encodeAggregatedSig(w io.Writer) error {
	aggSig := bp.aggregatedSig
	if _, err := w.Write(aggSig); err != nil {
		return fmt.Errorf("cannot write aggregated sig: %w", err)
	}
	return nil
}

// encodePayload encodes blsBatchPayload
func (bp *blsBatchPayload) encodePayload(w io.Writer) error {
	if err := bp.encodeBlockCount(w); err != nil {
		return err
	}
	if err := bp.encodeOriginBits(w); err != nil {
		return err
	}
	if err := bp.encodeBlockTxCounts(w); err != nil {
		return err
	}
	if err := bp.encodeTxs(w); err != nil {
		return err
	}
	if err := bp.encodeAggregatedSig(w); err != nil {
		return err
	}
	return nil
}

// encode writes the byte encoding of BLSBatch to Writer stream
func (b *RawBLSBatch) encode(w io.Writer) error {
	if err := b.encodePrefix(w); err != nil {
		return err
	}
	if err := b.encodePayload(w); err != nil {
		return err
	}
	return nil
}

// derive converts RawBLSBatch into BLSBatch, which has a list of BLSBatchElement.
// We need chain config constants to derive values for making payload attributes.
func (b *RawBLSBatch) derive(blockTime, genesisTimestamp uint64, chainID *big.Int) (*BLSBatch, error) {
	if b.blockCount == 0 {
		return nil, ErrEmptyBLSBatch
	}
	blockOriginNums := make([]uint64, b.blockCount)
	l1OriginBlockNumber := b.l1OriginNum
	for i := int(b.blockCount) - 1; i >= 0; i-- {
		blockOriginNums[i] = l1OriginBlockNumber
		if b.originBits.Bit(i) == 1 && i > 0 {
			l1OriginBlockNumber--
		}
	}

	fullTxs, err := b.txs.fullTxs(chainID)
	if err != nil {
		return nil, err
	}

	blsBatch := BLSBatch{
		ParentCheck:   b.parentCheck,
		L1OriginCheck: b.l1OriginCheck,
	}
	txIdx := 0
	for i := 0; i < int(b.blockCount); i++ {
		batch := BLSBatchElement{}
		batch.Timestamp = genesisTimestamp + b.relTimestamp + blockTime*uint64(i)
		batch.EpochNum = rollup.Epoch(blockOriginNums[i])
		for j := 0; j < int(b.blockTxCounts[i]); j++ {
			batch.Transactions = append(batch.Transactions, fullTxs[txIdx])
			txIdx++
		}
		batch.AggregatedSig = b.aggregatedSig
		blsBatch.Batches = append(blsBatch.Batches, &batch)
	}
	return &blsBatch, nil
}

// ToBLSBatch converts RawBLSBatch to BLSBatch,
// which implements a wrapper of derive method of RawBLSBatch
func (b *RawBLSBatch) ToBLSBatch(blockTime, genesisTimestamp uint64, chainID *big.Int) (*BLSBatch, error) {
	blsBatch, err := b.derive(blockTime, genesisTimestamp, chainID)
	if err != nil {
		return nil, err
	}
	return blsBatch, nil
}

// BLSBatchElement is a derived form of input to build a L2 block.
// similar to SingularBatch, but does not have ParentHash and EpochHash
// because BLS batch spec does not contain parent hash and epoch hash of every block in the .
type BLSBatchElement struct {
	EpochNum      rollup.Epoch // aka l1 num
	Timestamp     uint64
	Transactions  []hexutil.Bytes
	AggregatedSig []byte
}

// singularBatchToBLSElement converts a SingularBatch to a BLSBatchElement
func singularBatchToBLSElement(singularBatch *SingularBatch) *BLSBatchElement {
	return &BLSBatchElement{
		EpochNum:     singularBatch.EpochNum,
		Timestamp:    singularBatch.Timestamp,
		Transactions: singularBatch.Transactions,
	}
}

// BLSBatch is an implementation of Batch interface,
// containing the input to build a span of L2 blocks in derived form (BLSBatchElement)
type BLSBatch struct {
	ParentCheck      [20]byte // First 20 bytes of the first block's parent hash
	L1OriginCheck    [20]byte // First 20 bytes of the last block's L1 origin hash
	GenesisTimestamp uint64
	ChainID          *big.Int
	Batches          []*BLSBatchElement // List of block input in derived form

	// caching
	originBits    *big.Int
	blockTxCounts []uint64
	blstxs        *blsBatchTxs
}

func (b *BLSBatch) AsSingularBatch() (*SingularBatch, bool) { return nil, false }
func (b *BLSBatch) AsSpanBatch() (*SpanBatch, bool)         { return nil, false }
func (b *BLSBatch) AsBLSBatch() (*BLSBatch, bool)           { return b, true }

// blsBatchMarshaling is a helper type used for JSON marshaling.
type blsBatchMarshaling struct {
	ParentCheck   []hexutil.Bytes    `json:"parent_check"`
	L1OriginCheck []hexutil.Bytes    `json:"l1_origin_check"`
	Batches       []*BLSBatchElement `json:"bls_batch_elements"`
}

func (b *BLSBatch) MarshalJSON() ([]byte, error) {
	blsBatch := blsBatchMarshaling{
		ParentCheck:   []hexutil.Bytes{b.ParentCheck[:]},
		L1OriginCheck: []hexutil.Bytes{b.L1OriginCheck[:]},
		Batches:       b.Batches,
	}
	return json.Marshal(blsBatch)
}

// GetBatchType returns its batch type (batch_version)
func (b *BLSBatch) GetBatchType() int {
	return BLSBatchType
}

// GetTimestamp returns timestamp of the first block in the span
func (b *BLSBatch) GetTimestamp() uint64 {
	return b.Batches[0].Timestamp
}

// TxCount returns the tx count for the batch
func (b *BLSBatch) TxCount() (count uint64) {
	for _, txCount := range b.blockTxCounts {
		count += txCount
	}
	return
}

// LogContext creates a new log context that contains information of the batch
func (b *BLSBatch) LogContext(log log.Logger) log.Logger {
	if len(b.Batches) == 0 {
		return log.New("block_count", 0)
	}
	return log.New(
		"batch_type", "BLSBatch",
		"batch_timestamp", b.Batches[0].Timestamp,
		"parent_check", hexutil.Encode(b.ParentCheck[:]),
		"origin_check", hexutil.Encode(b.L1OriginCheck[:]),
		"start_epoch_number", b.GetStartEpochNum(),
		"end_epoch_number", b.GetBlockEpochNum(len(b.Batches)-1),
		"block_count", len(b.Batches),
		"txs", b.TxCount(),
	)
}

// GetStartEpochNum returns epoch number(L1 origin block number) of the first block in the span
func (b *BLSBatch) GetStartEpochNum() rollup.Epoch {
	return b.Batches[0].EpochNum
}

// CheckOriginHash checks if the l1OriginCheck matches the first 20 bytes of given hash, probably L1 block hash from the current canonical L1 chain.
func (b *BLSBatch) CheckOriginHash(hash common.Hash) bool {
	return bytes.Equal(b.L1OriginCheck[:], hash.Bytes()[:20])
}

// CheckParentHash checks if the parentCheck matches the first 20 bytes of given hash, probably the current L2 safe head.
func (b *BLSBatch) CheckParentHash(hash common.Hash) bool {
	return bytes.Equal(b.ParentCheck[:], hash.Bytes()[:20])
}

// GetBlockEpochNum returns the epoch number(L1 origin block number) of the block at the given index in the span.
func (b *BLSBatch) GetBlockEpochNum(i int) uint64 {
	return uint64(b.Batches[i].EpochNum)
}

// GetBlockTimestamp returns the timestamp of the block at the given index in the span.
func (b *BLSBatch) GetBlockTimestamp(i int) uint64 {
	return b.Batches[i].Timestamp
}

// GetBlockTransactions returns the encoded transactions of the block at the given index in the span.
func (b *BLSBatch) GetBlockTransactions(i int) []hexutil.Bytes {
	return b.Batches[i].Transactions
}

// GetBlockCount returns the number of blocks in the span
func (b *BLSBatch) GetBlockCount() int {
	return len(b.Batches)
}

// GetAggregatedSignature returns the BLS Aggregated Signature of the block at a given index in the span.
func (b *BLSBatch) GetAggregatedSignature(i int) []byte {
	return b.Batches[i].AggregatedSig
}

func (b *BLSBatch) peek(n int) *BLSBatchElement { return b.Batches[len(b.Batches)-1-n] }

// AppendSingularBatch appends a SingularBatch into the bls batch
// updates l1OriginCheck or parentCheck if needed.
func (b *BLSBatch) AppendSingularBatch(singularBatch *SingularBatch, seqNum uint64) error {
	// if this new element is not ordered with respect to the last element, panic
	if len(b.Batches) > 0 && b.peek(0).Timestamp > singularBatch.Timestamp {
		panic("bls batch is not ordered")
	}

	// always append the new batch and set the L1 origin check
	b.Batches = append(b.Batches, singularBatchToBLSElement(singularBatch))

	// always update the L1 origin check
	copy(b.L1OriginCheck[:], singularBatch.EpochHash.Bytes()[:20])
	// if there is only one batch, initialize the ParentCheck
	// and set the epochBit based on the seqNum
	epochBit := uint(0)
	if len(b.Batches) == 1 {
		if seqNum == 0 {
			epochBit = 1
		}
		copy(b.ParentCheck[:], singularBatch.ParentHash.Bytes()[:20])
	} else {
		// if there is more than one batch, set the epochBit based on the last two batches
		if b.peek(1).EpochNum < b.peek(0).EpochNum {
			epochBit = 1
		}
	}
	// set the respective bit in the originBits
	b.originBits.SetBit(b.originBits, len(b.Batches)-1, epochBit)

	// update the blockTxCounts cache with the latest batch's tx count
	b.blockTxCounts = append(b.blockTxCounts, uint64(len(b.peek(0).Transactions)))

	// add the new txs to the blstxs
	newTxs := make([][]byte, 0, len(b.peek(0).Transactions))
	for i := 0; i < len(b.peek(0).Transactions); i++ {
		newTxs = append(newTxs, b.peek(0).Transactions[i])
	}
	// add the new txs to the blstxs
	// this is the only place where we can get an error
	return b.blstxs.AddTxs(newTxs, b.ChainID)
}

// ToRawBLSBatch merges SingularBatch List and initialize single RawBLSBatch
func (b *BLSBatch) ToRawBLSBatch() (*RawBLSBatch, error) {
	if len(b.Batches) == 0 {
		return nil, errors.New("cannot merge empty singularBatch list")
	}
	bls_start := b.Batches[0]
	bls_end := b.Batches[len(b.Batches)-1]

	return &RawBLSBatch{
		blsBatchPrefix: blsBatchPrefix{
			relTimestamp:  bls_start.Timestamp - b.GenesisTimestamp,
			l1OriginNum:   uint64(bls_end.EpochNum),
			parentCheck:   b.ParentCheck,
			l1OriginCheck: b.L1OriginCheck,
		},
		blsBatchPayload: blsBatchPayload{
			blockCount:    uint64(len(b.Batches)),
			originBits:    b.originBits,
			blockTxCounts: b.blockTxCounts,
			txs:           b.blstxs,
		},
	}, nil
}

// GetSingularBatches converts BLSBatchElements after L2 safe head to SingularBatches.
// Since BLSBatchElement does not contain EpochHash, set EpochHash from the given L1 blocks.
// The result SingularBatches do not contain ParentHash yet. It must be set by BatchQueue.
func (b *BLSBatch) GetSingularBatches(l1Origins []eth.L1BlockRef, l2SafeHead eth.L2BlockRef) ([]*SingularBatch, error) {
	var singularBatches []*SingularBatch
	originIdx := 0
	for _, batch := range b.Batches {
		if batch.Timestamp <= l2SafeHead.Time {
			continue
		}
		singularBatch := SingularBatch{
			EpochNum:     batch.EpochNum,
			Timestamp:    batch.Timestamp,
			Transactions: batch.Transactions,
		}
		originFound := false
		for i := originIdx; i < len(l1Origins); i++ {
			if l1Origins[i].Number == uint64(batch.EpochNum) {
				originIdx = i
				singularBatch.EpochHash = l1Origins[i].Hash
				originFound = true
				break
			}
		}
		if !originFound {
			return nil, fmt.Errorf("unable to find L1 origin for the epoch number: %d", batch.EpochNum)
		}
		singularBatches = append(singularBatches, &singularBatch)
	}
	return singularBatches, nil
}

// NewBLSBatch converts given singularBatches into BLSBatchElements, and creates a new BLSBatch.
func NewBLSBatch(genesisTimestamp uint64, chainID *big.Int) *BLSBatch {
	// newBLSBatchTxs can't fail with empty txs
	blstxs, _ := newBLSBatchTxs([][]byte{}, chainID)
	return &BLSBatch{
		GenesisTimestamp: genesisTimestamp,
		ChainID:          chainID,
		originBits:       big.NewInt(0),
		blstxs:           blstxs,
	}
}

// DeriveBLSBatch derives BLSBatch from BatchData.
func DeriveBLSBatch(batchData *BatchData, blockTime, genesisTimestamp uint64, chainID *big.Int) (*BLSBatch, error) {
	RawBLSBatch, ok := batchData.inner.(*RawBLSBatch)
	if !ok {
		return nil, NewCriticalError(errors.New("failed type assertion to BLSBatch"))
	}
	// If the batch type is BLS batch, derive block inputs from RawBLSBatch.
	return RawBLSBatch.ToBLSBatch(blockTime, genesisTimestamp, chainID)
}
