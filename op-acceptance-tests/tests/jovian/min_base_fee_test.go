package jovian

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum-optimism/optimism/op-devstack/devtest"
	"github.com/ethereum-optimism/optimism/op-devstack/dsl"
	"github.com/ethereum-optimism/optimism/op-devstack/presets"
	"github.com/ethereum-optimism/optimism/op-node/rollup"
	"github.com/ethereum-optimism/optimism/op-service/eth"

	"encoding/binary"
	"time"

	"github.com/ethereum-optimism/optimism/op-chain-ops/devkeys"
	"github.com/ethereum-optimism/optimism/op-service/apis"
	"github.com/ethereum-optimism/optimism/op-service/testreq"
	"github.com/ethereum-optimism/optimism/op-service/txintent/bindings"
	"github.com/ethereum-optimism/optimism/op-service/txintent/contractio"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/log"
)

type MinBaseFee struct {
	// Ctx is the context for test execution.
	ctx context.Context
	// log is the component-specific logger instance.
	log log.Logger
	// T is a minimal test interface for panic-checks / assertions.
	t devtest.T
	// Require is a helper around the above T, ready to assert against.
	require *testreq.Assertions

	l1Client     *dsl.L1ELNode
	l2Network    *dsl.L2Network
	l2EL         *dsl.L2ELNode
	systemConfig minBaseFeeSystemConfig

	originalMinBaseFee uint64
}

type minBaseFeeSystemConfig struct {
	SetMinBaseFee func(minBaseFee uint64) bindings.TypedCall[any] `sol:"setMinBaseFee"`
	MinBaseFee    func() bindings.TypedCall[uint64]               `sol:"minBaseFee"`
}

func NewMinBaseFee(t devtest.T, l2Network *dsl.L2Network, l1EL *dsl.L1ELNode, l2EL *dsl.L2ELNode) *MinBaseFee {
	systemConfig := bindings.NewBindings[minBaseFeeSystemConfig](
		bindings.WithClient(l1EL.EthClient()),
		bindings.WithTo(l2Network.Escape().Deployment().SystemConfigProxyAddr()),
		bindings.WithTest(t))

	originalMinBaseFee, err := contractio.Read(systemConfig.MinBaseFee(), t.Ctx())
	t.Require().NoError(err, "reading original minBaseFee")

	return &MinBaseFee{
		ctx:                t.Ctx(),
		log:                t.Logger(),
		t:                  t,
		require:            t.Require(),
		l1Client:           l1EL,
		l2Network:          l2Network,
		l2EL:               l2EL,
		systemConfig:       systemConfig,
		originalMinBaseFee: originalMinBaseFee,
	}
}

func (mbf *MinBaseFee) CheckCompatibility() bool {
	_, err := contractio.Read(mbf.systemConfig.MinBaseFee(), mbf.ctx)
	if err != nil {
		mbf.t.Fail()
		return false
	}
	return true
}

func (mbf *MinBaseFee) GetSystemOwner() *dsl.EOA {
	priv := mbf.l2Network.Escape().Keys().Secret(devkeys.SystemConfigOwner.Key(mbf.l2Network.ChainID().ToBig()))
	return dsl.NewKey(mbf.t, priv).User(mbf.l1Client)
}

func (mbf *MinBaseFee) SetMinBaseFee(minBaseFee uint64) {
	owner := mbf.GetSystemOwner()

	_, err := contractio.Write(mbf.systemConfig.SetMinBaseFee(minBaseFee), mbf.ctx, owner.Plan())
	mbf.require.NoError(err, "SetMinBaseFee transaction failed")

	mbf.t.Logf("Set min base fee on L1: minBaseFee=%d", minBaseFee)
}

func (mbf *MinBaseFee) VerifyMinBaseFee(minBase *big.Int) {
	var prevBlockNum uint64
	// Give the sequencer one more block, then check 5 consecutive blocks
	_ = mbf.l2EL.WaitForBlock()
	el := mbf.l2EL.Escape().EthClient()
	info, err := el.InfoByLabel(mbf.ctx, "latest")
	mbf.require.NoError(err)
	prevBlockNum = info.NumberU64()

	// Check 5 consecutive blocks to ensure min base fee is consistently applied
	for i := 1; i <= 5; i++ {
		_ = mbf.l2EL.WaitForBlock()
		info, err := el.InfoByLabel(mbf.ctx, "latest")
		mbf.require.NoError(err)
		mbf.require.True(info.NumberU64() > prevBlockNum, "block number should increase")
		prevBlockNum = info.NumberU64()
		mbf.require.True(info.BaseFee().Cmp(minBase) >= 0, "block %d base-fee %s should be >= %s", info.NumberU64(), info.BaseFee(), minBase)
	}
}

// WaitForMinBaseFee waits until the L2 latest payload extra-data encodes the expected min base fee.
func (mbf *MinBaseFee) WaitForMinBaseFee(expected uint64) {
	client := mbf.l2EL.Escape().L2EthClient()
	ext, ok := client.(apis.L2EthExtendedClient)
	mbf.require.True(ok, "L2 client does not support extended payload API")

	expectedExtraData := eth.BytesMax32(eip1559.EncodeJovianExtraData(250, 6, expected))

	var actualPayload eth.BytesMax32
	mbf.require.Eventually(func() bool {
		payload, err := ext.PayloadByLabel(mbf.ctx, "latest")
		if err != nil {
			return false
		}
		if len(payload.ExecutionPayload.ExtraData) != 17 {
			return false
		}

		got := binary.BigEndian.Uint64(payload.ExecutionPayload.ExtraData[9:])
		actualPayload = payload.ExecutionPayload.ExtraData
		return got == expected
	}, 2*time.Minute, 5*time.Second, "L2 min base fee did not sync within timeout")

	mbf.require.Equal(expectedExtraData, actualPayload, "extradata doesnt match")
}

// TestMinBaseFee verifies configurable minimum base fee using devstack presets.
func TestMinBaseFee(gt *testing.T) {
	t := devtest.SerialT(gt)
	sys := presets.NewMinimal(t)
	require := t.Require()

	err := dsl.RequiresL2Fork(t.Ctx(), sys, 0, rollup.Jovian)
	require.NoError(err, "Jovian fork must be active for this test")

	minBaseFee := NewMinBaseFee(t, sys.L2Chain, sys.L1EL, sys.L2EL)

	minBaseFee.CheckCompatibility()
	systemOwner := minBaseFee.GetSystemOwner()
	sys.FunderL1.FundAtLeast(systemOwner, eth.OneTenthEther)

	testCases := []struct {
		name       string
		minBaseFee uint64
	}{
		{"MinBaseFeeOff", 0},
		{"MinBaseFeeOn", 1_000_000_000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t devtest.T) {
			minBaseFee.SetMinBaseFee(tc.minBaseFee)
			minBaseFee.WaitForMinBaseFee(tc.minBaseFee)

			minBaseFee.VerifyMinBaseFee(big.NewInt(int64(tc.minBaseFee)))

			t.Log("Test completed successfully:",
				"testCase", tc.name,
				"minBaseFee", tc.minBaseFee)
		})
	}
}
