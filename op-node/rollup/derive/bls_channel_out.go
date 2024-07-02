package derive

import (
	"bytes"

	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum-optimism/optimism/op-node/rollup"
)

type BLSChannelOut struct {
	id ChannelID
	// Frame ID of the next frame to emit. Increment after emitting
	frame uint64
	// rlp is the encoded, uncompressed data of the channel. length must be less than MAX_RLP_BYTES_PER_CHANNEL
	// it is a double buffer to allow us to "undo" the last change to the RLP structure when the target size is exceeded
	rlp [2]*bytes.Buffer
	// rlpIndex is the index of the current rlp buffer
	rlpIndex int
	// lastCompressedRLPSize tracks the *uncompressed* size of the last RLP buffer that was compressed
	// it is used to measure the growth of the RLP buffer when adding a new batch to optimize compression
	lastCompressedRLPSize int
	// the compressor for the channel
	compressor ChannelCompressor
	// target is the target size of the compressed data
	target uint64
	// closed indicates if the channel is closed
	closed bool
	// full indicates if the channel is full
	full error
	// blsBatch is the batch being built, which immutably holds genesis timestamp and chain ID, but otherwise can be reset
	blsBatch *BLSBatch
}

func (co *BLSChannelOut) ID() ChannelID {
	return co.id
}

func (co *BLSChannelOut) setRandomID() error {
	_, err := rand.Read(co.id[:])
	return err
}

func NewBLSChannelOut(genesisTimestamp uint64, chainID *big.Int, targetOutputSize uint64, compressionAlgo CompressionAlgo) (*BLSChannelOut, error) {
	c := &BLSChannelOut{
		id:       ChannelID{},
		frame:    0,
		blsBatch: NewBLSBatch(genesisTimestamp, chainID),
		rlp:      [2]*bytes.Buffer{{}, {}},
		target:   targetOutputSize,
	}
	var err error
	if err = c.setRandomID(); err != nil {
		return nil, err
	}

	if c.compressor, err = NewChannelCompressor(compressionAlgo); err != nil {
		return nil, err
	}

	return c, nil
}

func (co *BLSChannelOut) Reset() error {
	co.closed = false
	co.full = nil
	co.frame = 0
	co.rlp[0].Reset()
	co.rlp[1].Reset()
	co.lastCompressedRLPSize = 0
	co.compressor.Reset()
	co.blsBatch = NewBLSBatch(co.blsBatch.GenesisTimestamp, co.blsBatch.ChainID)
	// setting the new randomID is the only part of the reset that can fail
	return co.setRandomID()
}

// activeRLP returns the active RLP buffer using the current rlpIndex
func (co *BLSChannelOut) activeRLP() *bytes.Buffer {
	return co.rlp[co.rlpIndex]
}

// inactiveRLP returns the inactive RLP buffer using the current rlpIndex
func (co *BLSChannelOut) inactiveRLP() *bytes.Buffer {
	return co.rlp[(co.rlpIndex+1)%2]
}

// swapRLP switches the active and inactive RLP buffers by modifying the rlpIndex
func (co *BLSChannelOut) swapRLP() {
	co.rlpIndex = (co.rlpIndex + 1) % 2
}

// AddBlock adds a block to the channel.
// returns an error if there is a problem adding the block. The only sentinel error
// that it returns is ErrTooManyRLPBytes. If this error is returned, the channel
// should be closed and a new one should be made.
func (co *BLSChannelOut) AddBlock(rollupCfg *rollup.Config, block *types.Block) error {
	if co.closed {
		return ErrChannelOutAlreadyClosed
	}

	batch, l1Info, err := BlockToSingularBatch(rollupCfg, block)
	if err != nil {
		return err
	}
	return co.AddSingularBatch(batch, l1Info.SequenceNumber)
}

// AddSingularBatch adds a SingularBatch to the channel, compressing the data if necessary.
// if the new batch would make the channel exceed the target size, the last batch is reverted,
// and the compression happens on the previous RLP buffer instead
// if the input is too small to need compression, data is accumulated but not compressed
func (co *BLSChannelOut) AddSingularBatch(batch *SingularBatch, seqNum uint64) error {
	// sentinel error for closed or full channel
	if co.closed {
		return ErrChannelOutAlreadyClosed
	}
	if err := co.FullErr(); err != nil {
		return err
	}

	if err := co.blsBatch.AppendSingularBatch(batch, seqNum); err != nil {
		return fmt.Errorf("failed to append SingularBatch to BLSBatch: %w", err)
	}
	rawBLSBatch, err := co.blsBatch.ToRawBLSBatch()
	if err != nil {
		return fmt.Errorf("failed to convert BLSBatch into RawBLSBatch: %w", err)
	}

	co.swapRLP()
	co.activeRLP().Reset()
	if err = rlp.Encode(co.activeRLP(), NewBatchData(rawBLSBatch)); err != nil {
		return fmt.Errorf("failed to encode RawBLSBatch into bytes: %w", err)
	}

	// check the RLP length against the max
	if co.activeRLP().Len() > rollup.SafeMaxRLPBytesPerChannel {
		return fmt.Errorf("could not take %d bytes as replacement of channel of %d bytes, max is %d. err: %w",
			co.activeRLP().Len(), co.inactiveRLP().Len(), rollup.SafeMaxRLPBytesPerChannel, ErrTooManyRLPBytes)
	}

	// if the compressed data *plus* the new rlp data is under the target size, return early
	// this optimizes out cases where the compressor will obviously come in under the target size
	rlpGrowth := co.activeRLP().Len() - co.lastCompressedRLPSize
	if uint64(co.compressor.Len()+rlpGrowth) < co.target {
		return nil
	}

	// we must compress the data to check if we've met or exceeded the target size
	if err = co.compress(); err != nil {
		return err
	}
	co.lastCompressedRLPSize = co.activeRLP().Len()

	// if the channel is now full, either return the compressed data, or the compressed previous data
	if err := co.FullErr(); err != nil {
		// if there is only one batch in the channel, it *must* be returned
		if len(co.blsBatch.Batches) == 1 {
			return nil
		}

		// if there is more than one batch in the channel, we revert the last batch
		// by switching the RLP buffer and doing a fresh compression
		co.swapRLP()
		if err := co.compress(); err != nil {
			return err
		}
		// return the full error
		return err
	}

	return nil
}

// compress compresses the active RLP buffer and checks if the compressed data is over the target size.
// it resets all the compression buffers because BLS Batches aren't meant to be compressed incrementally.
func (co *BLSChannelOut) compress() error {
	co.compressor.Reset()
	if _, err := co.compressor.Write(co.activeRLP().Bytes()); err != nil {
		return err
	}
	if err := co.compressor.Close(); err != nil {
		return err
	}
	co.checkFull()
	return nil
}

// InputBytes returns the total amount of RLP-encoded input bytes.
func (co *BLSChannelOut) InputBytes() int {
	return co.activeRLP().Len()
}

// ReadyBytes returns the total amount of compressed bytes that are ready to be output.
// BLS Channel Out does not provide early output, so this will always be 0 until the channel is closed or full
func (co *BLSChannelOut) ReadyBytes() int {
	if co.closed || co.FullErr() != nil {
		return co.compressor.Len()
	}
	return 0
}

// Flush implements the Channel Out
// BLS Channel Out manages the flushing of the compressor internally, so this is a no-op
func (co *BLSChannelOut) Flush() error {
	return nil
}

// checkFull sets the full error if the compressed data is over the target size.
// the error is only set once, and the channel is considered full from that point on
func (co *BLSChannelOut) checkFull() {
	// if the channel is already full, don't update further
	if co.full != nil {
		return
	}
	if uint64(co.compressor.Len()) >= co.target {
		co.full = ErrCompressorFull
	}
}

func (co *BLSChannelOut) FullErr() error {
	return co.full
}

func (co *BLSChannelOut) Close() error {
	if co.closed {
		return ErrChannelOutAlreadyClosed
	}
	co.closed = true
	// if the channel was already full,
	// the compressor is already flushed and closed
	if co.FullErr() != nil {
		return nil
	}
	// if this channel is not full, we need to compress the last batch
	// this also flushes/closes the compressor
	return co.compress()
}

// OutputFrame writes a frame to w with a given max size and returns the frame
// number.
// Use `ReadyBytes`, `Flush`, and `Close` to modify the ready buffer.
// Returns an error if the `maxSize` < FrameV0OverHeadSize.
// Returns io.EOF when the channel is closed & there are no more frames.
// Returns nil if there is still more buffered data.
// Returns an error if it ran into an error during processing.
func (co *BLSChannelOut) OutputFrame(w *bytes.Buffer, maxSize uint64) (uint16, error) {
	// Check that the maxSize is large enough for the frame overhead size.
	if maxSize < FrameV0OverHeadSize {
		return 0, ErrMaxFrameSizeTooSmall
	}

	f := createEmptyFrame(co.id, co.frame, co.ReadyBytes(), co.closed, maxSize)

	if _, err := io.ReadFull(co.compressor.GetCompressed(), f.Data); err != nil {
		return 0, err
	}

	if err := f.MarshalBinary(w); err != nil {
		return 0, err
	}

	co.frame += 1
	fn := f.FrameNumber
	if f.IsLast {
		return fn, io.EOF
	} else {
		return fn, nil
	}
}
