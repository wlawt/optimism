package op_e2e

import (
	"context"
	"math/big"
	"math/rand"
	"testing"
	"time"

	batcherFlags "github.com/ethereum-optimism/optimism/op-batcher/flags"
	"github.com/ethereum-optimism/optimism/op-e2e/e2eutils/wait"
	"github.com/ethereum-optimism/optimism/op-service/client"
	"github.com/ethereum-optimism/optimism/op-service/sources"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
	"github.com/ethereum-optimism/optimism/op-service/testutils"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"
)

func TestSystem7591E2E(t *testing.T) {
	cfg := DefaultSystemConfig(t)
	cfg.DataAvailabilityType = batcherFlags.BlobsType

	genesisActivation := hexutil.Uint64(0)
	cfg.DeployConfig.L1CancunTimeOffset = &genesisActivation
	cfg.DeployConfig.L2GenesisDeltaTimeOffset = &genesisActivation
	cfg.DeployConfig.L2GenesisEcotoneTimeOffset = &genesisActivation

	sys, err := cfg.Start(t)
	require.Nil(t, err, "Error starting up system")
	defer sys.Close()

	log := testlog.Logger(t, log.LevelInfo)
	log.Info("genesis", "l2", sys.RollupConfig.Genesis.L2, "l1", sys.RollupConfig.Genesis.L1, "l2_time", sys.RollupConfig.Genesis.L2Time)

	l1Client := sys.Clients["l1"]
	l2Seq := sys.Clients["sequencer"]
	l2Verif := sys.Clients["verifier"]

	alicePriv := cfg.Secrets.Alice
	aliceAddr := cfg.Secrets.Addresses().Alice
	log.Info("alice", "addr", aliceAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	startBalanceAlice, err := l2Verif.BalanceAt(ctx, aliceAddr, nil)
	require.NoError(t, err)

	aliceOpts, err := bind.NewKeyedTransactorWithChainID(alicePriv, cfg.L1ChainIDBig())
	require.NoError(t, err)
	mintAmount := big.NewInt(1_000_000_000_000)
	aliceOpts.Value = mintAmount
	SendDepositTx(t, cfg, l1Client, l2Verif, aliceOpts, func(l2Opts *DepositTxOpts) {})

	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	endBalanceAlice, err := wait.ForBalanceChange(ctx, l2Verif, aliceAddr, startBalanceAlice)
	require.NoError(t, err)
	require.Equal(t, mintAmount, new(big.Int).Sub(endBalanceAlice, startBalanceAlice), "Did not get expected balance change")

	_ = SendL2Tx(t, cfg, l2Seq, alicePriv, func(opts *TxOpts) {
		opts.Value = big.NewInt(1_000_000_000)
		opts.Nonce = 1 // Already have deposit
		opts.ToAddr = &cfg.Secrets.Addresses().John
		// put some random data in the tx to make it fill up 6 blobs (multi-blob case)
		opts.Data = testutils.RandomData(rand.New(rand.NewSource(420)), 400)
		opts.Gas, err = core.IntrinsicGas(opts.Data, nil, false, true, true, false)
		require.NoError(t, err)
		opts.VerifyOnClients(l2Verif)
	})

	johnBLS := cfg.Secrets.JohnBLS
	johnPriv := cfg.Secrets.John
	johnAddr := cfg.Secrets.Addresses().John
	log.Info("john", "addr", johnAddr)

	// Submit TX to L2 sequencer node
	receipt := SendL2TxBLS(t, cfg, l2Seq, johnPriv, func(opts *BLSTxOpts) {
		opts.Value = big.NewInt(1_000_000_000)
		opts.Nonce = 1 // Already have deposit
		opts.ToAddr = &common.Address{0xff, 0xff}
		opts.Data = nil
		opts.Gas, err = core.IntrinsicGas(opts.Data, nil, false, true, true, false)
		require.NoError(t, err)
		opts.VerifyOnClients(l2Verif)
		opts.PublicKey = johnBLS.PublicKey().Marshal()
	})

	// Verify blocks match after batch submission on verifiers and sequencers
	verifBlock, err := l2Verif.BlockByNumber(context.Background(), receipt.BlockNumber)
	require.NoError(t, err)
	require.Equal(t, verifBlock.Hash(), receipt.BlockHash, "must be same block")
	seqBlock, err := l2Seq.BlockByNumber(context.Background(), receipt.BlockNumber)
	require.NoError(t, err)
	require.Equal(t, seqBlock.Hash(), receipt.BlockHash, "must be same block")
	require.Equal(t, verifBlock.NumberU64(), seqBlock.NumberU64(), "Verifier and sequencer blocks not the same after including a batch tx")
	require.Equal(t, verifBlock.ParentHash(), seqBlock.ParentHash(), "Verifier and sequencer blocks parent hashes not the same after including a batch tx")
	require.Equal(t, verifBlock.Hash(), seqBlock.Hash(), "Verifier and sequencer blocks not the same after including a batch tx")

	// BLS checks
	require.Equal(t, verifBlock.AggregatedSig(), seqBlock.AggregatedSig(), "Verifier and sequencer blocks not the same after including a BLS Batch tx")

	rollupRPCClient, err := rpc.DialContext(context.Background(), sys.RollupNodes["sequencer"].HTTPEndpoint())
	require.NoError(t, err)
	rollupClient := sources.NewRollupClient(client.NewBaseRPCClient(rollupRPCClient))
	// basic check that sync status works
	seqStatus, err := rollupClient.SyncStatus(context.Background())
	require.NoError(t, err)
	require.LessOrEqual(t, seqBlock.NumberU64(), seqStatus.UnsafeL2.Number)
	// basic check that version endpoint works
	seqVersion, err := rollupClient.Version(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, "", seqVersion)

	// quick check that the batch submitter works
	require.Eventually(t, func() bool {
		// wait for chain to be marked as "safe" (i.e. confirm batch-submission works)
		stat, err := rollupClient.SyncStatus(context.Background())
		require.NoError(t, err)
		return stat.SafeL2.Number >= receipt.BlockNumber.Uint64()
	}, time.Second*20, time.Second, "expected L2 to be batch-submitted and labeled as safe")

	// check that the L2 tx is still canonical
	/*seqBlock, err = l2Seq.BlockByNumber(context.Background(), receipt.BlockNumber)
	require.NoError(t, err)
	require.Equal(t, seqBlock.Hash(), receipt.BlockHash, "receipt block must match canonical block at tx inclusion height")

	// find L1 block that contained the BLS(s) batch tx
	tip, err := l1Client.HeaderByNumber(context.Background(), nil)
	require.NoError(t, err)
	var blsTx *types.Transaction
	_, err = gethutils.FindBlock(l1Client, int(tip.Number.Int64()), 0, 5*time.Second,
		func(b *types.Block) (bool, error) {
			for _, tx := range b.Transactions() {
				if tx.Type() != types.BLSTxType {
					continue
				}
				// expect to find at least one tx with multiple blobs in multi-blob case
				if !multiBlob || len(tx.BlobHashes()) > 1 {
					blobTx = tx
					return true, nil
				}
			}
			return false, nil
		})
	require.NoError(t, err)*/
}
