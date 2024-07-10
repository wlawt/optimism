package derive

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

type blsBatchTxData interface {
	txType() byte // returns the type ID
}

type blsBatchTx struct {
	inner blsBatchTxData
}

type blsBatchBLSTxData struct {
	Value      *big.Int
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Data       []byte
	AccessList types.AccessList
	PublicKey  []byte
}

func (txData *blsBatchBLSTxData) txType() byte { return types.BLSTxType }

// Type returns the transaction type.
func (tx *blsBatchTx) Type() uint8 {
	return tx.inner.txType()
}

// encodeTyped writes the canonical encoding of a typed transaction to w.
func (tx *blsBatchTx) encodeTyped(w *bytes.Buffer) error {
	w.WriteByte(tx.Type())
	return rlp.Encode(w, tx.inner)
}

// MarshalBinary returns the canonical encoding of the transaction.
// For legacy transactions, it returns the RLP encoding. For EIP-2718 typed
// transactions, it returns the type and payload.
func (tx *blsBatchTx) MarshalBinary() ([]byte, error) {
	if tx.Type() == types.LegacyTxType {
		return rlp.EncodeToBytes(tx.inner)
	}
	var buf bytes.Buffer
	err := tx.encodeTyped(&buf)
	return buf.Bytes(), err
}

// setDecoded sets the inner transaction after decoding.
func (tx *blsBatchTx) setDecoded(inner blsBatchTxData, size uint64) {
	tx.inner = inner
}

// decodeTyped decodes a typed transaction from the canonical format.
func (tx *blsBatchTx) decodeTyped(b []byte) (blsBatchTxData, error) {
	if len(b) <= 1 {
		return nil, fmt.Errorf("failed to decode span batch: %w", ErrTypedTxTooShort)
	}
	switch b[0] {
	case types.BLSTxType:
		var inner blsBatchBLSTxData
		err := rlp.DecodeBytes(b[1:], &inner)
		if err != nil {
			return nil, fmt.Errorf("failed to decode blsBatchBLSTxData: %w", err)
		}
		return &inner, nil
	default:
		return nil, types.ErrTxTypeNotSupported
	}
}

// UnmarshalBinary decodes the canonical encoding of transactions.
// It supports legacy RLP transactions and EIP2718 typed transactions.
func (tx *blsBatchTx) UnmarshalBinary(b []byte) error {
	// It's an EIP2718 typed transaction envelope.
	inner, err := tx.decodeTyped(b)
	if err != nil {
		return err
	}
	tx.setDecoded(inner, uint64(len(b)))
	return nil
}

// convertToFullTx takes values and convert blsBatchTx to types.Transaction
func (tx *blsBatchTx) convertToFullTx(nonce, gas uint64, to *common.Address, chainID *big.Int) (*types.Transaction, error) {
	var inner types.TxData
	switch tx.Type() {
	case types.BLSTxType:
		batchTxInner := tx.inner.(*blsBatchBLSTxData)
		inner = &types.BLSTx{
			ChainID:    chainID,
			Nonce:      nonce,
			GasTipCap:  batchTxInner.GasTipCap,
			GasFeeCap:  batchTxInner.GasFeeCap,
			Gas:        gas,
			To:         to,
			Value:      batchTxInner.Value,
			Data:       batchTxInner.Data,
			AccessList: batchTxInner.AccessList,
			PublicKey:  batchTxInner.PublicKey,
		}
	case types.LegacyTxType:
		batchTxInner := tx.inner.(*spanBatchLegacyTxData)
		inner = &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: batchTxInner.GasPrice,
			Gas:      gas,
			To:       to,
			Value:    batchTxInner.Value,
			Data:     batchTxInner.Data,
		}
	case types.AccessListTxType:
		batchTxInner := tx.inner.(*spanBatchAccessListTxData)
		inner = &types.AccessListTx{
			ChainID:    chainID,
			Nonce:      nonce,
			GasPrice:   batchTxInner.GasPrice,
			Gas:        gas,
			To:         to,
			Value:      batchTxInner.Value,
			Data:       batchTxInner.Data,
			AccessList: batchTxInner.AccessList,
		}
	case types.DynamicFeeTxType:
		batchTxInner := tx.inner.(*spanBatchDynamicFeeTxData)
		inner = &types.DynamicFeeTx{
			ChainID:    chainID,
			Nonce:      nonce,
			GasTipCap:  batchTxInner.GasTipCap,
			GasFeeCap:  batchTxInner.GasFeeCap,
			Gas:        gas,
			To:         to,
			Value:      batchTxInner.Value,
			Data:       batchTxInner.Data,
			AccessList: batchTxInner.AccessList,
		}
	default:
		return nil, fmt.Errorf("invalid tx type: %d", tx.Type())
	}
	return types.NewTx(inner), nil
}

// newBLSBatchTx converts types.Transaction to blsBatchTx
func newBLSBatchTx(tx types.Transaction) (*blsBatchTx, error) {
	var inner blsBatchTxData
	switch tx.Type() {
	case types.BLSTxType:
		inner = &blsBatchBLSTxData{
			GasTipCap:  tx.GasTipCap(),
			GasFeeCap:  tx.GasFeeCap(),
			Value:      tx.Value(),
			Data:       tx.Data(),
			AccessList: tx.AccessList(),
			PublicKey:  tx.PublicKey(),
		}
	case types.LegacyTxType:
		inner = &spanBatchLegacyTxData{
			GasPrice: tx.GasPrice(),
			Value:    tx.Value(),
			Data:     tx.Data(),
		}
	case types.AccessListTxType:
		inner = &spanBatchAccessListTxData{
			GasPrice:   tx.GasPrice(),
			Value:      tx.Value(),
			Data:       tx.Data(),
			AccessList: tx.AccessList(),
		}
	case types.DynamicFeeTxType:
		inner = &spanBatchDynamicFeeTxData{
			GasTipCap:  tx.GasTipCap(),
			GasFeeCap:  tx.GasFeeCap(),
			Value:      tx.Value(),
			Data:       tx.Data(),
			AccessList: tx.AccessList(),
		}
	default:
		return nil, fmt.Errorf("invalid tx type: %d", tx.Type())
	}
	return &blsBatchTx{inner: inner}, nil
}
