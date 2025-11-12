#include "chainparams.h"
#include "consensus/params.h"
#include "util/test.h"

#include <gtest/gtest.h>

TEST(FoundersRewardTest, FoundersRewardDisabled) {
    SelectParams(CBaseChainParams::MAIN);
    const auto& params = Params().GetConsensus();
    EXPECT_EQ(0, params.GetLastFoundersRewardBlockHeight(0));
    EXPECT_TRUE(params.GetActiveFundingStreams(1).empty());
    EXPECT_TRUE(params.GetActiveFundingStreamElements(1).empty());
    EXPECT_TRUE(params.GetLockboxDisbursementsForHeight(1).empty());
}

TEST(FoundersRewardTest, TestnetAndRegtestAlsoDisabled) {
    SelectParams(CBaseChainParams::TESTNET);
    const auto& testParams = Params().GetConsensus();
    EXPECT_EQ(0, testParams.GetLastFoundersRewardBlockHeight(0));
    EXPECT_TRUE(testParams.GetActiveFundingStreams(1).empty());
    EXPECT_TRUE(testParams.GetActiveFundingStreamElements(1).empty());
    EXPECT_TRUE(testParams.GetLockboxDisbursementsForHeight(1).empty());

    SelectParams(CBaseChainParams::REGTEST);
    const auto& regParams = Params().GetConsensus();
    EXPECT_EQ(0, regParams.GetLastFoundersRewardBlockHeight(0));
    EXPECT_TRUE(regParams.GetActiveFundingStreams(1).empty());
    EXPECT_TRUE(regParams.GetActiveFundingStreamElements(1).empty());
    EXPECT_TRUE(regParams.GetLockboxDisbursementsForHeight(1).empty());
}
