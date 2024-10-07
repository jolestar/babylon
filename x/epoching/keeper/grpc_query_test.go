package keeper_test

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"cosmossdk.io/core/header"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/stretchr/testify/require"

	"github.com/babylonlabs-io/babylon/testutil/datagen"
	testhelper "github.com/babylonlabs-io/babylon/testutil/helper"
	"github.com/babylonlabs-io/babylon/x/epoching/types"
)

// FuzzParamsQuery fuzzes queryClient.Params
// 1. Generate random param
// 2. When EpochInterval is 0, ensure `Validate` returns an error
// 3. Randomly set the param via query and check if the param has been updated
func FuzzParamsQuery(f *testing.F) {
	datagen.AddRandomSeedsToFuzzer(f, 10)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))

		// params generated by fuzzer
		params := types.DefaultParams()
		epochInterval := datagen.RandomInt(r, 20)
		params.EpochInterval = epochInterval

		// test the case of EpochInterval < 2
		// after that, change EpochInterval to a random value until >=2
		if epochInterval < 2 {
			// validation should not pass with EpochInterval < 2
			require.Error(t, params.Validate())
			params.EpochInterval = uint64(r.Int())
		}

		helper := testhelper.NewHelper(t)
		ctx, keeper, queryClient := helper.Ctx, helper.App.EpochingKeeper, helper.QueryClient
		// if setParamsFlag == 0, set params
		setParamsFlag := r.Intn(2)
		if setParamsFlag == 0 {
			if err := keeper.SetParams(ctx, params); err != nil {
				panic(err)
			}
		}
		req := types.QueryParamsRequest{}
		resp, err := queryClient.Params(ctx, &req)
		require.NoError(t, err)
		// if setParamsFlag == 0, resp.Params should be changed, otherwise default
		if setParamsFlag == 0 {
			require.Equal(t, params, resp.Params)
		} else {
			require.Equal(t, types.DefaultParams(), resp.Params)
		}
	})
}

// FuzzCurrentEpoch fuzzes queryClient.CurrentEpoch
// 1. generate a random number of epochs to increment
// 2. query the current epoch and boundary
// 3. compare them with the correctly calculated ones
func FuzzCurrentEpoch(f *testing.F) {
	datagen.AddRandomSeedsToFuzzer(f, 10)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))

		increment := datagen.RandomInt(r, 100) + 1

		helper := testhelper.NewHelper(t)
		ctx, keeper, queryClient := helper.Ctx, helper.App.EpochingKeeper, helper.QueryClient

		epochInterval := keeper.GetParams(ctx).EpochInterval
		// starting from epoch 1
		for i := uint64(1); i < increment; i++ {
			// this ensures that IncEpoch is invoked only at the first header of each epoch
			randomHeader := datagen.GenRandomTMHeader(r, "chain-test", i*epochInterval+1)
			headerInfo := header.Info{
				AppHash: randomHeader.AppHash,
				Height:  randomHeader.Height,
				Time:    randomHeader.Time,
				ChainID: randomHeader.ChainID,
			}
			ctx = ctx.WithHeaderInfo(headerInfo)
			keeper.IncEpoch(ctx)
		}
		req := types.QueryCurrentEpochRequest{}
		resp, err := queryClient.CurrentEpoch(ctx, &req)
		require.NoError(t, err)
		require.Equal(t, increment, resp.CurrentEpoch)
		require.Equal(t, increment*epochInterval, resp.EpochBoundary)
	})
}

func FuzzEpochsInfo(f *testing.F) {
	datagen.AddRandomSeedsToFuzzer(f, 10)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		var err error
		numEpochs := datagen.RandomInt(r, 10) + 2
		limit := datagen.RandomInt(r, 10) + 1

		helper := testhelper.NewHelper(t)
		ctx, keeper, queryClient := helper.Ctx, helper.App.EpochingKeeper, helper.QueryClient

		// enqueue the 1st block of the numEpochs'th epoch
		epochInterval := keeper.GetParams(ctx).EpochInterval
		for i := uint64(0); i < (numEpochs - 2); i++ { // exclude the existing epoch 0 and 1
			for j := uint64(0); j < epochInterval; j++ {
				ctx, err = helper.ApplyEmptyBlockWithVoteExtension(r)
				require.NoError(t, err)
			}
		}

		// get epoch msgs
		req := types.QueryEpochsInfoRequest{
			Pagination: &query.PageRequest{
				Limit: limit,
			},
		}
		resp, err := queryClient.EpochsInfo(ctx, &req)
		require.NoError(t, err)

		require.Equal(t, min(numEpochs, limit), uint64(len(resp.Epochs)))
		for i, epoch := range resp.Epochs {
			require.Equal(t, uint64(i), epoch.EpochNumber)
		}
	})
}

// FuzzEpochMsgsQuery fuzzes queryClient.EpochMsgs
// 1. randomly generate msgs and limit in pagination
// 2. check the returned msg was previously enqueued
// NOTE: Msgs in QueryEpochMsgsResponse are out-of-order
func FuzzEpochMsgsQuery(f *testing.F) {
	datagen.AddRandomSeedsToFuzzer(f, 10)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		numMsgs := uint64(r.Int() % 100)
		limit := uint64(r.Int()%100) + 1

		txidsMap := map[string]bool{}
		helper := testhelper.NewHelper(t)
		ctx, keeper, queryClient := helper.Ctx, helper.App.EpochingKeeper, helper.QueryClient
		// enqueue a random number of msgs with random txids
		for i := uint64(0); i < numMsgs; i++ {
			txid := datagen.GenRandomByteArray(r, 32)
			txidsMap[hex.EncodeToString(txid)] = true
			queuedMsg := types.QueuedMessage{
				TxId: txid,
				Msg:  &types.QueuedMessage_MsgDelegate{MsgDelegate: &stakingtypes.MsgDelegate{}},
			}
			keeper.EnqueueMsg(ctx, queuedMsg)
		}
		// get epoch msgs
		req := types.QueryEpochMsgsRequest{
			EpochNum: 1,
			Pagination: &query.PageRequest{
				Limit: limit,
			},
		}
		resp, err := queryClient.EpochMsgs(ctx, &req)
		require.NoError(t, err)

		require.Equal(t, min(uint64(len(txidsMap)), limit), uint64(len(resp.Msgs)))
		for idx := range resp.Msgs {
			_, ok := txidsMap[resp.Msgs[idx].TxId]
			require.True(t, ok)
		}

		// epoch 1 is out of scope
		req = types.QueryEpochMsgsRequest{
			EpochNum: 2,
			Pagination: &query.PageRequest{
				Limit: limit,
			},
		}
		_, err = queryClient.EpochMsgs(ctx, &req)
		require.Error(t, err)
	})
}

// FuzzEpochMsgs fuzzes queryClient.EpochValSet
// TODO (stateful tests): create some random validators and check if the resulting validator set is consistent or not (require mocking MsgWrappedCreateValidator)
func FuzzEpochValSetQuery(f *testing.F) {
	datagen.AddRandomSeedsToFuzzer(f, 10)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))

		// generate the validator set with 10 validators as genesis
		genesisValSet, privSigner, err := datagen.GenesisValidatorSetWithPrivSigner(10)
		require.NoError(t, err)
		helper := testhelper.NewHelperWithValSet(t, genesisValSet, privSigner)
		ctx, queryClient := helper.Ctx, helper.QueryClient

		limit := uint64(r.Int() % 100)
		req := &types.QueryEpochValSetRequest{
			EpochNum: 1,
			Pagination: &query.PageRequest{
				Limit: limit,
			},
		}

		resp, err := queryClient.EpochValSet(ctx, req)
		require.NoError(t, err)

		params := helper.App.EpochingKeeper.GetParams(ctx)

		// generate a random number of new blocks
		for i := uint64(0); i < params.EpochInterval; i++ {
			ctx, err = helper.ApplyEmptyBlockWithVoteExtension(r)
			require.NoError(t, err)
		}

		// check whether the validator set remains the same or not
		resp2, err := queryClient.EpochValSet(ctx, req)
		require.NoError(t, err)
		require.Equal(t, len(resp.Validators), len(resp2.Validators))
		for i := range resp2.Validators {
			require.Equal(t, resp.Validators[i].Addr, resp2.Validators[i].Addr)
		}
	})
}
