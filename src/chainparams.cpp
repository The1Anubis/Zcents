// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2015-2025 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "chainparams.h"
#include "consensus/merkle.h"
#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "tinyformat.h"
#include "util/system.h"
#include "util/strencodings.h"

#include <assert.h>
#include <optional>
#include <variant>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from hashlib import blake2s
 * >>> 'Zcents' + blake2s(b'Zcents launches with a clean ledger and a fresh start. 2024-01-01').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1477641360, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Zcents 2024-01-01 Financial freedom starts with every cent";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        keyConstants.strNetworkID = "main";
        strCurrencyUnits = "ZCT";
        keyConstants.bip44CoinType = 840; // Placeholder BIP44 coin type for Zcents
        consensus.fCoinbaseMustBeShielded = true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = POST_BLOSSOM_HALVING_INTERVAL(Consensus::PRE_BLOSSOM_HALVING_INTERVAL);
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        const size_t N = 200, K = 9;
        static_assert(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = std::nullopt;
        consensus.fPowNoRetargeting = false;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170009;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].nProtocolVersion = 170011;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nProtocolVersion = 170013;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].nProtocolVersion = 170100;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_NU6].nProtocolVersion = 170120;
        consensus.vUpgrades[Consensus::UPGRADE_NU6].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nProtocolVersion = 170140;
        consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_ZFUTURE].nProtocolVersion = 0x7FFFFFFF;
        consensus.vUpgrades[Consensus::UPGRADE_ZFUTURE].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.nFundingPeriodLength = consensus.nPostBlossomSubsidyHalvingInterval / 48;

        // guarantees the first 2 characters, when base58 encoded, are "Zc"
        keyConstants.base58Prefixes[PUBKEY_ADDRESS]     = {0x12,0x5C};
        // guarantees the first 2 characters, when base58 encoded, are "Zs"
        keyConstants.base58Prefixes[SCRIPT_ADDRESS]     = {0x12,0x81};
        // guarantees the first character, when base58 encoded, is "S"
        keyConstants.base58Prefixes[SECRET_KEY]         = {0x0D};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        keyConstants.base58Prefixes[EXT_PUBLIC_KEY]     = {0x03,0x5A,0x3C,0x2F};
        keyConstants.base58Prefixes[EXT_SECRET_KEY]     = {0x03,0x5A,0x31,0x2B};
        // guarantees the first 2 characters, when base58 encoded, are "Za"
        keyConstants.base58Prefixes[ZCPAYMENT_ADDRESS]  = {0x0C,0xC8};
        // guarantees the first 4 characters, when base58 encoded, are "ZViZ"
        keyConstants.base58Prefixes[ZCVIEWING_KEY]      = {0x02,0xE3,0x78};
        // guarantees the first 2 characters, when base58 encoded, are "ZS"
        keyConstants.base58Prefixes[ZCSPENDING_KEY]     = {0x03,0xC8};

        keyConstants.bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        keyConstants.bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        keyConstants.bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        keyConstants.bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";
        keyConstants.bech32HRPs[SAPLING_EXTENDED_FVK]         = "zxviews";

        keyConstants.bech32mHRPs[TEX_ADDRESS]                 = "tex";
        {
            auto canopyActivation = consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nActivationHeight;
            auto nu6Activation = consensus.vUpgrades[Consensus::UPGRADE_NU6].nActivationHeight;
            auto nu6_1Activation = consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nActivationHeight;

            // ZIP 214 Revision 0
            std::vector<std::string> bp_addresses = {
                "t3LmX1cxWPPPqL4TZHx42HU3U5ghbFjRiif",
                "t3Toxk1vJQ6UjWQ42tUJz2rV2feUWkpbTDs",
                "t3ZBdBe4iokmsjdhMuwkxEdqMCFN16YxKe6",
                "t3ZuaJziLM8xZ32rjDUzVjVtyYdDSz8GLWB",
                "t3bAtYWa4bi8VrtvqySxnbr5uqcG9czQGTZ",
                "t3dktADfb5Rmxncpe1HS5BRS5Gcj7MZWYBi",
                "t3hgskquvKKoCtvxw86yN7q8bzwRxNgUZmc",
                "t3R1VrLzwcxAZzkX4mX3KGbWpNsgtYtMntj",
                "t3ff6fhemqPMVujD3AQurxRxTdvS1pPSaa2",
                "t3cEUQFG3KYnFG6qYhPxSNgGi3HDjUPwC3J",
                "t3WR9F5U4QvUFqqx9zFmwT6xFqduqRRXnaa",
                "t3PYc1LWngrdUrJJbHkYPCKvJuvJjcm85Ch",
                "t3bgkjiUeatWNkhxY3cWyLbTxKksAfk561R",
                "t3Z5rrR8zahxUpZ8itmCKhMSfxiKjUp5Dk5",
                "t3PU1j7YW3fJ67jUbkGhSRto8qK2qXCUiW3",
                "t3S3yaT7EwNLaFZCamfsxxKwamQW2aRGEkh",
                "t3eutXKJ9tEaPSxZpmowhzKhPfJvmtwTEZK",
                "t3gbTb7brxLdVVghSPSd3ycGxzHbUpukeDm",
                "t3UCKW2LrHFqPMQFEbZn6FpjqnhAAbfpMYR",
                "t3NyHsrnYbqaySoQqEQRyTWkjvM2PLkU7Uu",
                "t3QEFL6acxuZwiXtW3YvV6njDVGjJ1qeaRo",
                "t3PdBRr2S1XTDzrV8bnZkXF3SJcrzHWe1wj",
                "t3ZWyRPpWRo23pKxTLtWsnfEKeq9T4XPxKM",
                "t3he6QytKCTydhpztykFsSsb9PmBT5JBZLi",
                "t3VWxWDsLb2TURNEP6tA1ZSeQzUmPKFNxRY",
                "t3NmWLvZkbciNAipauzsFRMxoZGqmtJksbz",
                "t3cKr4YxVPvPBG1mCvzaoTTdBNokohsRJ8n",
                "t3T3smGZn6BoSFXWWXa1RaoQdcyaFjMfuYK",
                "t3gkDUe9Gm4GGpjMk86TiJZqhztBVMiUSSA",
                "t3eretuBeBXFHe5jAqeSpUS1cpxVh51fAeb",
                "t3dN8g9zi2UGJdixGe9txeSxeofLS9t3yFQ",
                "t3S799pq9sYBFwccRecoTJ3SvQXRHPrHqvx",
                "t3fhYnv1S5dXwau7GED3c1XErzt4n4vDxmf",
                "t3cmE3vsBc5xfDJKXXZdpydCPSdZqt6AcNi",
                "t3h5fPdjJVHaH4HwynYDM5BB3J7uQaoUwKi",
                "t3Ma35c68BgRX8sdLDJ6WR1PCrKiWHG4Da9",
                "t3LokMKPL1J8rkJZvVpfuH7dLu6oUWqZKQK",
                "t3WFFGbEbhJWnASZxVLw2iTJBZfJGGX73mM",
                "t3L8GLEsUn4QHNaRYcX3EGyXmQ8kjpT1zTa",
                "t3PgfByBhaBSkH8uq4nYJ9ZBX4NhGCJBVYm",
                "t3WecsqKDhWXD4JAgBVcnaCC2itzyNZhJrv",
                "t3ZG9cSfopnsMQupKW5v9sTotjcP5P6RTbn",
                "t3hC1Ywb5zDwUYYV8LwhvF5rZ6m49jxXSG5",
                "t3VgMqDL15ZcyQDeqBsBW3W6rzfftrWP2yB",
                "t3LC94Y6BwLoDtBoK2NuewaEbnko1zvR9rm",
                "t3cWCUZJR3GtALaTcatrrpNJ3MGbMFVLRwQ",
                "t3YYF4rPLVxDcF9hHFsXyc5Yq1TFfbojCY6",
                "t3XHAGxRP2FNfhAjxGjxbrQPYtQQjc3RCQD",
            };

            // ZF and MG each use a single address repeated 48 times,
            // once for each funding period.
            std::vector<std::string> zf_addresses(48, "t3dvVE3SQEi7kqNzwrfNePxZ1d4hUyztBA1");
            std::vector<std::string> mg_addresses(48, "t3XyYW8yBFRuMnfvm5KLGFbEVz25kckZXym");

            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_ZIP214_BP,
                canopyActivation,
                nu6Activation,
                bp_addresses);
            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_ZIP214_ZF,
                canopyActivation,
                nu6Activation,
                zf_addresses);
            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_ZIP214_MG,
                canopyActivation,
                nu6Activation,
                mg_addresses);

            // ZIP 214 Revision 1
            // FPF uses a single address repeated 12 times, once for each funding period.
            std::vector<std::string> fpf_addresses(12, "t3cFfPt1Bcvgez9ZbMBFWeZsskxTkPzGCow");

            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_FPF_ZCG,
                nu6Activation,
                nu6_1Activation,
                fpf_addresses);
            consensus.AddZIP207LockboxStream(
                keyConstants,
                Consensus::FS_DEFERRED,
                nu6Activation,
                nu6_1Activation);

            // ZIP 214 Revision 2
            // FPF uses a single address repeated 36 times, once for each funding period.
            std::vector<std::string> fpf_addresses_h3(36, "t3cFfPt1Bcvgez9ZbMBFWeZsskxTkPzGCow");
            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_FPF_ZCG_H3,
                nu6_1Activation,
                4406400,
                fpf_addresses_h3);
            consensus.AddZIP207LockboxStream(
                keyConstants,
                Consensus::FS_CCF_H3,
                nu6_1Activation,
                4406400);

            // ZIP 271
            // For convenience of distribution, we split the lockbox contents into 10 equal chunks.
            std::string nu6_1_kho_address = "t3ev37Q2uL1sfTsiJQJiWJoFzQpDhmnUwYo";
            static const CAmount nu6_1_disbursement_amount = 78750 * COIN;
            static const CAmount nu6_1_chunk_amount = 7875 * COIN;
            static constexpr auto nu6_1_chunks = {
                Consensus::LD_ZIP271_NU6_1_CHUNK_1,
                Consensus::LD_ZIP271_NU6_1_CHUNK_2,
                Consensus::LD_ZIP271_NU6_1_CHUNK_3,
                Consensus::LD_ZIP271_NU6_1_CHUNK_4,
                Consensus::LD_ZIP271_NU6_1_CHUNK_5,
                Consensus::LD_ZIP271_NU6_1_CHUNK_6,
                Consensus::LD_ZIP271_NU6_1_CHUNK_7,
                Consensus::LD_ZIP271_NU6_1_CHUNK_8,
                Consensus::LD_ZIP271_NU6_1_CHUNK_9,
                Consensus::LD_ZIP271_NU6_1_CHUNK_10,
            };
            static_assert(nu6_1_chunk_amount * nu6_1_chunks.size() == nu6_1_disbursement_amount);
            for (auto idx : nu6_1_chunks) {
                consensus.AddZIP271LockboxDisbursement(
                    keyConstants,
                    idx,
                    Consensus::UPGRADE_NU6_1,
                    nu6_1_chunk_amount,
                    nu6_1_kho_address);
            }
        }

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0xa3;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xc7;
        pchMessageStart[3] = 0x2d;
        vAlertPubKey.clear();
        nDefaultPort = 19333;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(
            1704067200,
            uint256(),
            ParseHex(""),
            0x207fffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();


        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1704067200,
            0,
            0
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 0;
        nSproutValuePoolCheckpointBalance = 0;
        fZIP209Enabled = false;
        hashSproutValuePoolCheckpointBlock.SetNull();

        // Founders reward disabled for Zcents genesis.
        vFoundersRewardAddress.clear();

        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        keyConstants.strNetworkID = "test";
        strCurrencyUnits = "TZCT";
        keyConstants.bip44CoinType = 1;
        consensus.fCoinbaseMustBeShielded = true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = POST_BLOSSOM_HALVING_INTERVAL(Consensus::PRE_BLOSSOM_HALVING_INTERVAL);
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        const size_t N = 200, K = 9;
        static_assert(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.fPowNoRetargeting = false;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].nProtocolVersion = 170010;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].nProtocolVersion = 170050;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].hashActivationBlock = std::nullopt;
        consensus.vUpgrades[Consensus::UPGRADE_NU6].nProtocolVersion = 170110;
        consensus.vUpgrades[Consensus::UPGRADE_NU6].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nProtocolVersion = 170130;
        consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_ZFUTURE].nProtocolVersion = 0x7FFFFFFF;
        consensus.vUpgrades[Consensus::UPGRADE_ZFUTURE].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.nFundingPeriodLength = consensus.nPostBlossomSubsidyHalvingInterval / 48;

        // guarantees the first 2 characters, when base58 encoded, are "Rc"
        keyConstants.base58Prefixes[PUBKEY_ADDRESS]     = {0x0D,0xDB};
        // guarantees the first 2 characters, when base58 encoded, are "Rs"
        keyConstants.base58Prefixes[SCRIPT_ADDRESS]     = {0x0E,0x00};
        // guarantees the first character, when base58 encoded, is "2"
        keyConstants.base58Prefixes[SECRET_KEY]         = {0x01};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        keyConstants.base58Prefixes[EXT_PUBLIC_KEY]     = {0x05,0x62,0xA3,0x1F};
        keyConstants.base58Prefixes[EXT_SECRET_KEY]     = {0x05,0x62,0x98,0x19};
        // guarantees the first 2 characters, when base58 encoded, are "ta"
        keyConstants.base58Prefixes[ZCPAYMENT_ADDRESS]  = {0x14,0x3C};
        // guarantees the first 4 characters, when base58 encoded, are "tViA"
        keyConstants.base58Prefixes[ZCVIEWING_KEY]      = {0x04,0x93,0xD6};
        // guarantees the first 2 characters, when base58 encoded, are "tS"
        keyConstants.base58Prefixes[ZCSPENDING_KEY]     = {0x05,0xFF};

        keyConstants.bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        keyConstants.bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        keyConstants.bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        keyConstants.bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";
        keyConstants.bech32HRPs[SAPLING_EXTENDED_FVK]         = "zxviewtestsapling";

        keyConstants.bech32mHRPs[TEX_ADDRESS]                 = "textest";

        // Testnet funding streams
        {
            auto canopyActivation = consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nActivationHeight;
            auto nu6Activation = consensus.vUpgrades[Consensus::UPGRADE_NU6].nActivationHeight;
            auto nu6_1Activation = consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nActivationHeight;

            // ZIP 214 Revision 0
            std::vector<std::string> bp_addresses = {
                "t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz",
                "t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz",
                "t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz",
                "t26ovBdKAJLtrvBsE2QGF4nqBkEuptuPFZz",
                "t2NNHrgPpE388atmWSF4DxAb3xAoW5Yp45M",
                "t2VMN28itPyMeMHBEd9Z1hm6YLkQcGA1Wwe",
                "t2CHa1TtdfUV8UYhNm7oxbzRyfr8616BYh2",
                "t2F77xtr28U96Z2bC53ZEdTnQSUAyDuoa67",
                "t2ARrzhbgcpoVBDPivUuj6PzXzDkTBPqfcT",
                "t278aQ8XbvFR15mecRguiJDQQVRNnkU8kJw",
                "t2Dp1BGnZsrTXZoEWLyjHmg3EPvmwBnPDGB",
                "t2KzeqXgf4ju33hiSqCuKDb8iHjPCjMq9iL",
                "t2Nyxqv1BiWY1eUSiuxVw36oveawYuo18tr",
                "t2DKFk5JRsVoiuinK8Ti6eM4Yp7v8BbfTyH",
                "t2CUaBca4k1x36SC4q8Nc8eBoqkMpF3CaLg",
                "t296SiKL7L5wvFmEdMxVLz1oYgd6fTfcbZj",
                "t29fBCFbhgsjL3XYEZ1yk1TUh7eTusB6dPg",
                "t2FGofLJXa419A76Gpf5ncxQB4gQXiQMXjK",
                "t2ExfrnRVnRiXDvxerQ8nZbcUQvNvAJA6Qu",
                "t28JUffLp47eKPRHKvwSPzX27i9ow8LSXHx",
                "t2JXWPtrtyL861rFWMZVtm3yfgxAf4H7uPA",
                "t2QdgbJoWfYHgyvEDEZBjHmgkr9yNJff3Hi",
                "t2QW43nkco8r32ZGRN6iw6eSzyDjkMwCV3n",
                "t2DgYDXMJTYLwNcxighQ9RCgPxMVATRcUdC",
                "t2Bop7dg33HGZx3wunnQzi2R2ntfpjuti3M",
                "t2HVeEwovcLq9RstAbYkqngXNEsCe2vjJh9",
                "t2HxbP5keQSx7p592zWQ5bJ5GrMmGDsV2Xa",
                "t2TJzUg2matao3mztBRJoWnJY6ekUau6tPD",
                "t29pMzxmo6wod25YhswcjKv3AFRNiBZHuhj",
                "t2QBQMRiJKYjshJpE6RhbF7GLo51yE6d4wZ",
                "t2F5RqnqguzZeiLtYHFx4yYfy6pDnut7tw5",
                "t2CHvyZANE7XCtg8AhZnrcHCC7Ys1jJhK13",
                "t2BRzpMdrGWZJ2upsaNQv6fSbkbTy7EitLo",
                "t2BFixHGQMAWDY67LyTN514xRAB94iEjXp3",
                "t2Uvz1iVPzBEWfQBH1p7NZJsFhD74tKaG8V",
                "t2CmFDj5q6rJSRZeHf1SdrowinyMNcj438n",
                "t2ErNvWEReTfPDBaNizjMPVssz66aVZh1hZ",
                "t2GeJQ8wBUiHKDVzVM5ZtKfY5reCg7CnASs",
                "t2L2eFtkKv1G6j55kLytKXTGuir4raAy3yr",
                "t2EK2b87dpPazb7VvmEGc8iR6SJ289RywGL",
                "t2DJ7RKeZJxdA4nZn8hRGXE8NUyTzjujph9",
                "t2K1pXo4eByuWpKLkssyMLe8QKUbxnfFC3H",
                "t2TB4mbSpuAcCWkH94Leb27FnRxo16AEHDg",
                "t2Phx4gVL4YRnNsH3jM1M7jE4Fo329E66Na",
                "t2VQZGmeNomN8c3USefeLL9nmU6M8x8CVzC",
                "t2RicCvTVTY5y9JkreSRv3Xs8q2K67YxHLi",
                "t2JrSLxTGc8wtPDe9hwbaeUjCrCfc4iZnDD",
                "t2Uh9Au1PDDSw117sAbGivKREkmMxVC5tZo",
                "t2FDwoJKLeEBMTy3oP7RLQ1Fihhvz49a3Bv",
                "t2FY18mrgtb7QLeHA8ShnxLXuW8cNQ2n1v8",
                "t2L15TkDYum7dnQRBqfvWdRe8Yw3jVy9z7g",
            };

            // ZF and MG use the same address for each funding period
            std::vector<std::string> zf_addresses(51, "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v");
            std::vector<std::string> mg_addresses(51, "t2Gvxv2uNM7hbbACjNox4H6DjByoKZ2Fa3P");

            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_ZIP214_BP,
                canopyActivation,
                2796000, // *not* the NU6 activation height
                bp_addresses);
            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_ZIP214_ZF,
                canopyActivation,
                2796000, // *not* the NU6 activation height
                zf_addresses);
            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_ZIP214_MG,
                canopyActivation,
                2796000, // *not* the NU6 activation height
                mg_addresses);

            // ZIP 214 Revision 1
            // FPF uses a single address repeated 13 times, once for each funding period.
            // There are 13 periods because the start height does not align with a period boundary.
            std::vector<std::string> fpf_addresses(13, "t2HifwjUj9uyxr9bknR8LFuQbc98c3vkXtu");
            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_FPF_ZCG,
                nu6Activation,
                3396000,
                fpf_addresses);
            consensus.AddZIP207LockboxStream(
                keyConstants,
                Consensus::FS_DEFERRED,
                nu6Activation,
                3396000);

            // ZIP 214 Revision 2
            // FPF uses a single address repeated 27 times, once for each funding period.
            // There are 27 periods because the start height is after the second halving
            // on testnet and does not align with a period boundary.
            std::vector<std::string> fpf_addresses_h3(27, "t2HifwjUj9uyxr9bknR8LFuQbc98c3vkXtu");
            consensus.AddZIP207FundingStream(
                keyConstants,
                Consensus::FS_FPF_ZCG_H3,
                nu6_1Activation,
                4476000,
                fpf_addresses_h3);
            consensus.AddZIP207LockboxStream(
                keyConstants,
                Consensus::FS_CCF_H3,
                nu6_1Activation,
                4476000);

            // ZIP 271
            // For testing purposes, we split the lockbox contents into 10 equal chunks.
            std::string nu6_1_kho_address = "t2RnBRiqrN1nW4ecZs1Fj3WWjNdnSs4kiX8";
            static const CAmount nu6_1_disbursement_amount = 78750 * COIN;
            static const CAmount nu6_1_chunk_amount = 7875 * COIN;
            static constexpr auto nu6_1_chunks = {
                Consensus::LD_ZIP271_NU6_1_CHUNK_1,
                Consensus::LD_ZIP271_NU6_1_CHUNK_2,
                Consensus::LD_ZIP271_NU6_1_CHUNK_3,
                Consensus::LD_ZIP271_NU6_1_CHUNK_4,
                Consensus::LD_ZIP271_NU6_1_CHUNK_5,
                Consensus::LD_ZIP271_NU6_1_CHUNK_6,
                Consensus::LD_ZIP271_NU6_1_CHUNK_7,
                Consensus::LD_ZIP271_NU6_1_CHUNK_8,
                Consensus::LD_ZIP271_NU6_1_CHUNK_9,
                Consensus::LD_ZIP271_NU6_1_CHUNK_10,
            };
            static_assert(nu6_1_chunk_amount * nu6_1_chunks.size() == nu6_1_disbursement_amount);
            for (auto idx : nu6_1_chunks) {
                consensus.AddZIP271LockboxDisbursement(
                    keyConstants,
                    idx,
                    Consensus::UPGRADE_NU6_1,
                    nu6_1_chunk_amount,
                    nu6_1_kho_address);
            }
        }

        // On testnet we activate this rule 6 blocks after Blossom activation. From block 299188 and
        // prior to Blossom activation, the testnet minimum-difficulty threshold was 15 minutes (i.e.
        // a minimum difficulty block can be mined if no block is mined normally within 15 minutes):
        // <https://zips.z.cash/zip-0205#change-to-difficulty-adjustment-on-testnet>
        // However the median-time-past is 6 blocks behind, and the worst-case time for 7 blocks at a
        // 15-minute spacing is ~105 minutes, which exceeds the limit imposed by the soft fork of
        // 90 minutes.
        //
        // After Blossom, the minimum difficulty threshold time is changed to 6 times the block target
        // spacing, which is 7.5 minutes:
        // <https://zips.z.cash/zip-0208#minimum-difficulty-blocks-on-the-test-network>
        // 7 times that is 52.5 minutes which is well within the limit imposed by the soft fork.

        static_assert(6 * Consensus::POST_BLOSSOM_POW_TARGET_SPACING * 7 < MAX_FUTURE_BLOCK_TIME_MTP - 60,
                      "MAX_FUTURE_BLOCK_TIME_MTP is too low given block target spacing");
        consensus.nFutureTimestampSoftForkHeight = consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight + 6;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0x52;
        pchMessageStart[1] = 0xc9;
        pchMessageStart[2] = 0x81;
        pchMessageStart[3] = 0x4a;
        vAlertPubKey.clear();
        nDefaultPort = 29333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1704067201,
            uint256(),
            ParseHex(""),
            0x207fffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();


        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1704067201,
            0,
            0
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        nSproutValuePoolCheckpointHeight = 0;
        nSproutValuePoolCheckpointBalance = 0;
        fZIP209Enabled = false;
        hashSproutValuePoolCheckpointBlock.SetNull();

        // Founders reward disabled for Zcents genesis.
        vFoundersRewardAddress.clear();
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight(0));
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        keyConstants.strNetworkID = "regtest";
        strCurrencyUnits = "RZCT";
        keyConstants.bip44CoinType = 1;
        consensus.fCoinbaseMustBeShielded = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nPreBlossomSubsidyHalvingInterval = Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL;
        consensus.nPostBlossomSubsidyHalvingInterval = POST_BLOSSOM_HALVING_INTERVAL(Consensus::PRE_BLOSSOM_REGTEST_HALVING_INTERVAL);
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        const size_t N = 48, K = 5;
        static_assert(equihash_parameters_acceptable(N, K));
        consensus.nEquihashN = N;
        consensus.nEquihashK = K;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"); // if this is any larger, the for loop in GetNextWorkRequired can overflow bnTot
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPreBlossomPowTargetSpacing = Consensus::PRE_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPostBlossomPowTargetSpacing = Consensus::POST_BLOSSOM_POW_TARGET_SPACING;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.fPowNoRetargeting = true;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].nProtocolVersion = 170010;
        consensus.vUpgrades[Consensus::UPGRADE_HEARTWOOD].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_CANOPY].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].nProtocolVersion = 170050;
        consensus.vUpgrades[Consensus::UPGRADE_NU5].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_NU6].nProtocolVersion = 170110;
        consensus.vUpgrades[Consensus::UPGRADE_NU6].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nProtocolVersion = 170130;
        consensus.vUpgrades[Consensus::UPGRADE_NU6_1].nActivationHeight = 1;
        consensus.vUpgrades[Consensus::UPGRADE_ZFUTURE].nProtocolVersion = 0x7FFFFFFF;
        consensus.vUpgrades[Consensus::UPGRADE_ZFUTURE].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.nFundingPeriodLength = consensus.nPostBlossomSubsidyHalvingInterval / 48;
        // Defined funding streams can be enabled with node config flags.

        // These prefixes are the same as the testnet prefixes
        keyConstants.base58Prefixes[PUBKEY_ADDRESS]     = {0x0D,0xDB};
        keyConstants.base58Prefixes[SCRIPT_ADDRESS]     = {0x0E,0x00};
        keyConstants.base58Prefixes[SECRET_KEY]         = {0x01};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        keyConstants.base58Prefixes[EXT_PUBLIC_KEY]     = {0x05,0x62,0xA3,0x1F};
        keyConstants.base58Prefixes[EXT_SECRET_KEY]     = {0x05,0x62,0x98,0x19};
        keyConstants.base58Prefixes[ZCPAYMENT_ADDRESS]  = {0x14,0x3C};
        keyConstants.base58Prefixes[ZCVIEWING_KEY]      = {0x04,0x93,0xD6};
        keyConstants.base58Prefixes[ZCSPENDING_KEY]     = {0x05,0xFF};

        keyConstants.bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        keyConstants.bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        keyConstants.bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        keyConstants.bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
        keyConstants.bech32HRPs[SAPLING_EXTENDED_FVK]         = "zxviewregtestsapling";

        keyConstants.bech32mHRPs[TEX_ADDRESS]                 = "texregtest";

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xc5;
        pchMessageStart[1] = 0x9e;
        pchMessageStart[2] = 0x4b;
        pchMessageStart[3] = 0x2f;
        vAlertPubKey.clear();
        nDefaultPort = 39333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1704067202,
            uint256(),
            ParseHex(""),
            0x207fffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1704067202,
            0,
            0
        };

        // Founders reward disabled for Zcents genesis.
        vFoundersRewardAddress.clear();
static CRegTestParams regTestParams;

static const CChainParams* pCurrentParams = nullptr;

const CChainParams& Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

const CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestshieldcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeShielded();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int preBlossomMaxHeight = consensus.GetLastFoundersRewardBlockHeight(0);
    // zip208
    // FounderAddressAdjustedHeight(height) :=
    // height, if not IsBlossomActivated(height)
    // BlossomActivationHeight + floor((height - BlossomActivationHeight) / BlossomPoWTargetSpacingRatio), otherwise
    bool blossomActive = consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BLOSSOM);
    if (blossomActive) {
        int blossomActivationHeight = consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight;
        nHeight = blossomActivationHeight + ((nHeight - blossomActivationHeight) / Consensus::BLOSSOM_POW_TARGET_SPACING_RATIO);
    }
    assert(nHeight > 0 && nHeight <= preBlossomMaxHeight);
    size_t addressChangeInterval = (preBlossomMaxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight(nHeight));

    KeyIO keyIO(*this);
    auto address = keyIO.DecodePaymentAddress(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.has_value());
    assert(std::holds_alternative<CScriptID>(address.value()));
    CScriptID scriptID = std::get<CScriptID>(address.value());
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

void UpdateFundingStreamParameters(Consensus::FundingStreamIndex idx, Consensus::FundingStream fs)
{
    regTestParams.UpdateFundingStreamParameters(idx, fs);
}

void UpdateOnetimeLockboxDisbursementParameters(
    Consensus::OnetimeLockboxDisbursementIndex idx,
    Consensus::OnetimeLockboxDisbursement ld)
{
    regTestParams.UpdateOnetimeLockboxDisbursementParameters(idx, ld);
}

void UpdateRegtestPow(
    int64_t nPowMaxAdjustDown,
    int64_t nPowMaxAdjustUp,
    uint256 powLimit,
    bool noRetargeting)
{
    regTestParams.UpdateRegtestPow(nPowMaxAdjustDown, nPowMaxAdjustUp, powLimit, noRetargeting);
}
