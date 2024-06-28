package derive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

type blsBatchTxs struct {
	// this field must be manually set
	totalBlockTxCount uint64

	// 8 fields
	contractCreationBits *big.Int
	txNonces             []uint64
	txGases              []uint64
	txTos                []common.Address
	txDatas              []hexutil.Bytes

	// intermediate variables which can be recovered
	txTypes            []int
	totalLegacyTxCount uint64
}

func (btx *blsBatchTxs) encodeContractCreationBits(w io.Writer) error {
	if err := encodeSpanBatchBits(w, btx.totalBlockTxCount, btx.contractCreationBits); err != nil {
		return fmt.Errorf("failed to encode contract creation bits: %w", err)
	}
	return nil
}

func (btx *blsBatchTxs) decodeContractCreationBits(r *bytes.Reader) error {
	if btx.totalBlockTxCount > MaxSpanBatchElementCount {
		return ErrTooBigBLSBatchSize
	}
	bits, err := decodeSpanBatchBits(r, btx.totalBlockTxCount)
	if err != nil {
		return fmt.Errorf("failed to decode contract creation bits: %w", err)
	}
	btx.contractCreationBits = bits
	return nil
}

func (btx *blsBatchTxs) contractCreationCount() (uint64, error) {
	if btx.contractCreationBits == nil {
		return 0, errors.New("dev error: contract creation bits not set")
	}
	var result uint64 = 0
	for i := 0; i < int(btx.totalBlockTxCount); i++ {
		bit := btx.contractCreationBits.Bit(i)
		if bit == 1 {
			result++
		}
	}
	return result, nil
}

func (btx *blsBatchTxs) encodeTxNonces(w io.Writer) error {
	var buf [binary.MaxVarintLen64]byte
	for _, txNonce := range btx.txNonces {
		n := binary.PutUvarint(buf[:], txNonce)
		if _, err := w.Write(buf[:n]); err != nil {
			return fmt.Errorf("cannot write tx nonce: %w", err)
		}
	}
	return nil
}

func (btx *blsBatchTxs) encodeTxGases(w io.Writer) error {
	var buf [binary.MaxVarintLen64]byte
	for _, txGas := range btx.txGases {
		n := binary.PutUvarint(buf[:], txGas)
		if _, err := w.Write(buf[:n]); err != nil {
			return fmt.Errorf("cannot write tx gas: %w", err)
		}
	}
	return nil
}

func (btx *blsBatchTxs) encodeTxTos(w io.Writer) error {
	for _, txTo := range btx.txTos {
		if _, err := w.Write(txTo.Bytes()); err != nil {
			return fmt.Errorf("cannot write tx to address: %w", err)
		}
	}
	return nil
}

func (btx *blsBatchTxs) encodeTxDatas(w io.Writer) error {
	for _, txData := range btx.txDatas {
		if _, err := w.Write(txData); err != nil {
			return fmt.Errorf("cannot write tx data: %w", err)
		}
	}
	return nil
}

func (btx *blsBatchTxs) decodeTxNonces(r *bytes.Reader) error {
	var txNonces []uint64
	for i := 0; i < int(btx.totalBlockTxCount); i++ {
		txNonce, err := binary.ReadUvarint(r)
		if err != nil {
			return fmt.Errorf("failed to read tx nonce: %w", err)
		}
		txNonces = append(txNonces, txNonce)
	}
	btx.txNonces = txNonces
	return nil
}

func (btx *blsBatchTxs) decodeTxGases(r *bytes.Reader) error {
	var txGases []uint64
	for i := 0; i < int(btx.totalBlockTxCount); i++ {
		txGas, err := binary.ReadUvarint(r)
		if err != nil {
			return fmt.Errorf("failed to read tx gas: %w", err)
		}
		txGases = append(txGases, txGas)
	}
	btx.txGases = txGases
	return nil
}

func (btx *blsBatchTxs) decodeTxTos(r *bytes.Reader) error {
	var txTos []common.Address
	txToBuffer := make([]byte, common.AddressLength)
	contractCreationCount, err := btx.contractCreationCount()
	if err != nil {
		return err
	}
	for i := 0; i < int(btx.totalBlockTxCount-contractCreationCount); i++ {
		_, err := io.ReadFull(r, txToBuffer)
		if err != nil {
			return fmt.Errorf("failed to read tx to address: %w", err)
		}
		txTos = append(txTos, common.BytesToAddress(txToBuffer))
	}
	btx.txTos = txTos
	return nil
}

func (btx *blsBatchTxs) decodeTxDatas(r *bytes.Reader) error {
	var txDatas []hexutil.Bytes
	var txTypes []int
	// Do not need txDataHeader because RLP byte stream already includes length info
	for i := 0; i < int(btx.totalBlockTxCount); i++ {
		txData, txType, err := ReadTxData(r)
		if err != nil {
			return err
		}
		txDatas = append(txDatas, txData)
		txTypes = append(txTypes, txType)
		if txType == types.LegacyTxType {
			btx.totalLegacyTxCount++
		}
	}
	btx.txDatas = txDatas
	btx.txTypes = txTypes
	return nil
}

func (btx *blsBatchTxs) encode(w io.Writer) error {
	if err := btx.encodeContractCreationBits(w); err != nil {
		return err
	}
	if err := btx.encodeTxTos(w); err != nil {
		return err
	}
	if err := btx.encodeTxDatas(w); err != nil {
		return err
	}
	if err := btx.encodeTxNonces(w); err != nil {
		return err
	}
	if err := btx.encodeTxGases(w); err != nil {
		return err
	}
	return nil
}

func (btx *blsBatchTxs) decode(r *bytes.Reader) error {
	if err := btx.decodeContractCreationBits(r); err != nil {
		return err
	}
	if err := btx.decodeTxTos(r); err != nil {
		return err
	}
	if err := btx.decodeTxDatas(r); err != nil {
		return err
	}
	if err := btx.decodeTxNonces(r); err != nil {
		return err
	}
	if err := btx.decodeTxGases(r); err != nil {
		return err
	}
	return nil
}

func (btx *blsBatchTxs) fullTxs(chainID *big.Int) ([][]byte, error) {
	var txs [][]byte
	toIdx := 0
	for idx := 0; idx < int(btx.totalBlockTxCount); idx++ {
		var blstx blsBatchTx
		if err := blstx.UnmarshalBinary(btx.txDatas[idx]); err != nil {
			return nil, err
		}
		nonce := btx.txNonces[idx]
		gas := btx.txGases[idx]
		var to *common.Address = nil
		bit := btx.contractCreationBits.Bit(idx)
		if bit == 0 {
			if len(btx.txTos) <= toIdx {
				return nil, errors.New("tx to not enough")
			}
			to = &btx.txTos[toIdx]
			toIdx++
		}
		tx, err := blstx.convertToFullTx(nonce, gas, to, chainID)
		if err != nil {
			return nil, err
		}
		encodedTx, err := tx.MarshalBinary()
		if err != nil {
			return nil, err
		}
		txs = append(txs, encodedTx)
	}
	return txs, nil
}

func newBLSBatchTxs(txs [][]byte, chainID *big.Int) (*blsBatchTxs, error) {
	sbtxs := &blsBatchTxs{
		contractCreationBits: big.NewInt(0),
		txNonces:             []uint64{},
		txGases:              []uint64{},
		txTos:                []common.Address{},
		txDatas:              []hexutil.Bytes{},
		txTypes:              []int{},
	}

	if err := sbtxs.AddTxs(txs, chainID); err != nil {
		return nil, err
	}
	return sbtxs, nil
}

func (sbtx *blsBatchTxs) AddTxs(txs [][]byte, chainID *big.Int) error {
	totalBlockTxCount := uint64(len(txs))
	offset := sbtx.totalBlockTxCount
	for idx := 0; idx < int(totalBlockTxCount); idx++ {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(txs[idx]); err != nil {
			return errors.New("failed to decode tx")
		}
		contractCreationBit := uint(1)
		if tx.To() != nil {
			sbtx.txTos = append(sbtx.txTos, *tx.To())
			contractCreationBit = uint(0)
		}
		sbtx.contractCreationBits.SetBit(sbtx.contractCreationBits, idx+int(offset), contractCreationBit)
		sbtx.txNonces = append(sbtx.txNonces, tx.Nonce())
		sbtx.txGases = append(sbtx.txGases, tx.Gas())
		stx, err := newBLSBatchTx(tx)
		if err != nil {
			return err
		}
		txData, err := stx.MarshalBinary()
		if err != nil {
			return err
		}
		sbtx.txDatas = append(sbtx.txDatas, txData)
		sbtx.txTypes = append(sbtx.txTypes, int(tx.Type()))
	}
	sbtx.totalBlockTxCount += totalBlockTxCount
	return nil
}
