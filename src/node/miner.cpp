// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <validation.h>

#include <algorithm>
#include <utility>

namespace node {
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(pindexPrev->GetMedianTimePast() + 1, TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

BlockAssembler::Options::Options()
{
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool(mempool),
      m_chainstate(chainstate)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions()
{
    // Block resource limits
    // If -blockmaxweight is not given, limit to DEFAULT_BLOCK_MAX_WEIGHT
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetIntArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    if (gArgs.IsArgSet("-blockmintxfee")) {
        std::optional<CAmount> parsed = ParseMoney(gArgs.GetArg("-blockmintxfee", ""));
        options.blockMinFeeRate = CFeeRate{parsed.value_or(DEFAULT_BLOCK_MIN_TX_FEE)};
    } else {
        options.blockMinFeeRate = CFeeRate{DEFAULT_BLOCK_MIN_TX_FEE};
    }
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool)
    : BlockAssembler(chainstate, mempool, DefaultOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn)
{
    bool fAddedBMM = false;
    return CreateNewBlock(scriptPubKeyIn, fAddedBMM);
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, , bool& fAddedBMM)
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if (!pblocktemplate.get()) {
        return nullptr;
    }
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    bool fDrivechainEnabled = IsDrivechainEnabled(pindexPrev, chainparams.GetConsensus());
#ifdef ENABLE_WALLET
    if (fDrivechainEnabled) {
        // Make sure that the mempool has only valid deposits to choose from
        m_mempool.UpdateCTIPFromBlock(scdb.GetCTIP(), false /* fDisconnect */);

        // Remove expired BMM requests from our memory pool
        std::vector<uint256> vHashRemoved;
        m_mempool.RemoveExpiredCriticalRequests(vHashRemoved);
        // Select which BMM requests (if any) to include
        m_mempool.SelectBMMRequests(vHashRemoved);

        // Track what was removed from the mempool so that we can abandon later
        for (const uint256& u : vHashRemoved)
            scdb.AddRemovedBMM(u);
    }
#endif

    // Collect active sidechains
    std::vector<Sidechain> vActiveSidechain;
    if (fDrivechainEnabled)
        vActiveSidechain = scdb.GetActiveSidechains();

    // Generate payout transactions for any approved withdrawals
    //
    // Keep track of which sidechains will have a Withdrawal in this block. We will
    // need this when deciding what transactions to add from the mempool.
    std::set<uint8_t> setSidechainsWithWithdrawal;
    // Keep track of the created Withdrawal(s) to be added to the block later
    std::vector<CMutableTransaction> vWithdrawal;
    // Keep track of mainchain fees
    CAmount nWithdrawalFees = 0;
    if (fDrivechainEnabled) {
        for (const Sidechain& s : vActiveSidechain) {
            CMutableTransaction wtx;
            CAmount nFee = 0;
            bool fCreated = CreateWithdrawalPayout(s.nSidechain, wtx, nFee);
            if (fCreated && wtx.vout.size() && wtx.vin.size()) {
                LogPrintf("%s: Created Withdrawal payout for sidechain: %u with: %u outputs!\ntxid: %s.\n",
                        __func__, s.nSidechain, wtx.vout.size(), wtx.GetHash().ToString());
                vWithdrawal.push_back(wtx);
                setSidechainsWithWithdrawal.insert(s.nSidechain);

                nWithdrawalFees += nFee;
            }
        }
    }


    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    bool fNeedCriticalFeeTx = false;
    if (m_mempool) {
        LOCK(m_mempool->cs);
        addPackageTxs(*m_mempool, nPackagesSelected, nDescendantsUpdated);
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));


    // Commit new withdrawals which we have received locally
    std::map<uint8_t /* nSidechain */, uint256 /* hash withdrawal */> mapNewWithdrawal;
    for (const Sidechain& s : vActiveSidechain) {
        std::vector<uint256> vHash = scdb.GetUncommittedWithdrawalCache(s.nSidechain);

        if (vHash.empty())
            continue;

        const uint256& hash = vHash.back();

        // Make sure that the Withdrawal hasn't previously been spent or failed.
        if (scdb.HaveFailedWithdrawal(hash, s.nSidechain))
            continue;
        if (scdb.HaveSpentWithdrawal(hash, s.nSidechain))
            continue;

        // For now, if there are fresh (uncommitted, unknown to SCDB) Withdrawal(s)
        // we will commit the most recent in the block we are generating.
        GenerateWithdrawalHashCommitment(*pblock, hash, s.nSidechain);

        // Keep track of new Withdrawal(s) by nSidechain for later
        mapNewWithdrawal[s.nSidechain] = hash;

        LogPrintf("%s: Miner found new withdrawal: %u : %s at height %u.\n", __func__, s.nSidechain, hash.ToString(), nHeight);
    }


    if (fDrivechainEnabled && scdb.HasState()) {
        // Get withdrawal vote settings
        std::vector<std::string> vVote = scdb.GetVotes();

        std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
        for (const Sidechain& s : vActiveSidechain) {
            std::vector<SidechainWithdrawalState> vWithdrawal = scdb.GetState(s.nSidechain);
            if (vWithdrawal.size())
                vOldScores.push_back(vWithdrawal);
        }

        LogPrintf("%s: Miner generating scdb bytes at height %u.\n", __func__, nHeight);
        CScript script;
        if (!GenerateSCDBByteCommitment(*pblock, script, vOldScores, vVote)) {
            LogPrintf("%s: Miner failed to generate scdb bytes at height %u.\n", __func__, nHeight);
            throw std::runtime_error(strprintf("%s: Miner failed to generate scdb bytes at height %u.\n",
                                               __func__, nHeight));
        }

        // Make sure that we can read the update bytes
        std::vector<std::string> vVoteParsed;
        if (!ParseSCDBBytes(script, vOldScores, vVoteParsed)) {
            LogPrintf("%s: Miner failed to parse its own scdb bytes at height %u.\n", __func__, nHeight);
            throw std::runtime_error(strprintf("%s: Miner failed to parse its own update bytes at height %u.\n",
                                               __func__, nHeight));
        }
    }

    if (fDrivechainEnabled) {
        // Generate critical hash commitments (usually for BMM commitments)
        GenerateCriticalHashCommitments(*pblock);

        // Scan through our sidechain proposals and commit the first one we find
        // that hasn't already been committed and is tracked by SCDB.
        //
        // If we commit a proposal, save the hash to easily ACK it later
        uint256 hashProposal;
        std::vector<Sidechain> vProposal = scdb.GetSidechainProposals();
        if (!vProposal.empty()) {
            std::vector<SidechainActivationStatus> vActivation = scdb.GetSidechainActivationStatus();
            for (const Sidechain& p : vProposal) {
                // Check if this proposal is unique
                bool fFound = false;
                for (const SidechainActivationStatus& s : vActivation) {
                    if (s.proposal == p) {
                        fFound = true;
                        break;
                    }
                }
                if (fFound)
                    continue;

                GenerateSidechainProposalCommitment(*pblock, p);
                hashProposal = p.GetSerHash();
                LogPrintf("%s: Generated sidechain proposal commitment for:\n%s\n", __func__, p.ToString());
                break;
            }
        }

        // TODO rename param to make function more clear
        // If this is set activate any sidechain which has been proposed.
        bool fAnySidechain = gArgs.GetBoolArg("-activatesidechains", false);

        // Commit sidechain activation for proposals in activation status cache
        // which we have configured to ACK
        std::vector<SidechainActivationStatus> vActivationStatus;
        vActivationStatus = scdb.GetSidechainActivationStatus();
        std::map<uint8_t, bool> mapCommit;
        for (const SidechainActivationStatus& s : vActivationStatus) {
            if (fAnySidechain || scdb.GetAckSidechain(s.proposal.GetSerHash())) {
                // Don't generate more than one commit for the same SC #
                if (mapCommit.find(s.proposal.nSidechain) == mapCommit.end()) {
                    GenerateSidechainActivationCommitment(*pblock, s.proposal.GetSerHash());
                    mapCommit[s.proposal.nSidechain] = true;
                }
            }
        }
    }

    for (const CMutableTransaction& mtx : vWithdrawal) {
        pblock->vtx.push_back(MakeTransactionRef(std::move(mtx)));
    }


    // Handle / create critical fee tx (collects bmm / critical data fees)
    if (fDrivechainEnabled && fNeedCriticalFeeTx) {
        fAddedBMM = true;
        // Create critical fee tx
        CMutableTransaction feeTx;
        feeTx.vout.resize(1);
        // Pay the fees to the same script as the coinbase
        feeTx.vout[0].scriptPubKey = scriptPubKeyIn;
        feeTx.vout[0].nValue = CAmount(0);

        // Find all of the critical data transactions included in the block
        // and take their input and total amount
        for (const CTransactionRef& tx : pblock->vtx) {
            if (tx && !tx->criticalData.IsNull()) {
                // Try to find the critical data fee output and take it
                for (uint32_t i = 0; i < tx->vout.size(); i++) {
                    if (tx->vout[i].scriptPubKey == CScript() << OP_TRUE) {
                        feeTx.vin.push_back(CTxIn(tx->GetHash(), i));
                        feeTx.vout[0].nValue += tx->vout[i].nValue;
                    }
                }
            }
        }

        // TODO calculate the fee tx as part of the block's txn package so that
        // we always make room for it.
        //
        // Add the fee tx to the block if we can
        if (CTransaction(feeTx).GetValueOut()) {
            // Check if block weight after adding transaction would be too large
            if ((nBlockWeight + GetTransactionWeight(feeTx)) < MAX_BLOCK_WEIGHT) {
                pblock->vtx.push_back(MakeTransactionRef(std::move(feeTx)));
                pblocktemplate->vTxSigOpsCost.push_back(WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx.back()));
                pblocktemplate->vTxFees.push_back(0);
            } else {
                LogPrintf("%s: Miner could not add BMM fee tx, block size > MAX_BLOCK_WEIGHT ", __func__);
            }
        }
    }


    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    BlockValidationState state;
    if (!TestBlockValidity(state, chainparams, m_chainstate, *pblock, pindexPrev, GetAdjustedTime, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
    }
    const auto time_2{SteadyClock::now()};

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start), nPackagesSelected, nDescendantsUpdated,
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    return std::move(pblocktemplate);
}


bool BlockAssembler::CreateWithdrawalPayout(uint8_t nSidechain, CMutableTransaction& tx, CAmount& nFees)
{
    // TODO log all false returns

    // The Withdrawal that will be created
    CMutableTransaction mtx;
    mtx.nVersion = 2;

    if (!IsDrivechainEnabled(chainActive.Tip(), chainparams.GetConsensus()))
        return false;

#ifdef ENABLE_WALLET
    if (!scdb.HasState())
        return false;
    if (!scdb.IsSidechainActive(nSidechain))
        return false;

    Sidechain sidechain;
    if (!scdb.GetSidechain(nSidechain, sidechain))
        return false;

    // Select the highest scoring withdrawal for sidechain
    uint256 hashBest = uint256();
    uint16_t scoreBest = 0;
    std::vector<SidechainWithdrawalState> vState = scdb.GetState(nSidechain);
    for (const SidechainWithdrawalState& state : vState) {
        if (state.nWorkScore > scoreBest || scoreBest == 0) {
            hashBest = state.hash;
            scoreBest = state.nWorkScore;
        }
    }
    if (hashBest == uint256())
        return false;

    // Does the selected withdrawal have sufficient work score?
    if (scoreBest < SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE)
        return false;

    // Copy outputs from withdrawal tx
    std::vector<std::pair<uint8_t, CMutableTransaction>> vTx = scdb.GetWithdrawalTxCache();
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vTx) {
        if (pair.second.GetHash() == hashBest) {
            for (const CTxOut& out : pair.second.vout)
                mtx.vout.push_back(out);
            break;
        }
    }
    // Withdrawal should have at least the encoded dest output, encoded fee output,
    // and change return output.
    if (mtx.vout.size() < 3)
        return false;

    // Get the mainchain fee amount from the second Withdrawal output which encodes the
    // sum of withdrawal fees.
    CAmount amountRead = 0;
    if (!DecodeWithdrawalFees(mtx.vout[1].scriptPubKey, amountRead)) {
        LogPrintf("%s: Failed to decode withdrawal fees!\n", __func__);
        return false;
    }
    nFees = amountRead;

    // Calculate the amount to be withdrawn by Withdrawal
    CAmount amountWithdrawn = CAmount(0);
    for (const CTxOut& out : mtx.vout) {
        uint8_t nSidechain;
        if (!out.scriptPubKey.IsDrivechain(nSidechain))
            amountWithdrawn += out.nValue;
    }

    // Add mainchain fees from withdrawal
    amountWithdrawn += nFees;

    // Get sidechain change return script. We will pay the sidechain the change
    // left over from this Withdrawal. This Withdrawal transaction will look like a normal
    // sidechain deposit but with more outputs and the destination string will
    // be SIDECHAIN_WITHDRAWAL_RETURN_DEST.
    CScript sidechainScript;
    if (!scdb.GetSidechainScript(nSidechain, sidechainScript))
        return false;

    // Note: Withdrawal change return must be the final output
    // Add placeholder change return as the final output.
    mtx.vout.push_back(CTxOut(0, sidechainScript));

    // Get sidechain's CTIP
    SidechainCTIP ctip;
    if (!scdb.GetCTIP(nSidechain, ctip))
        return false;

    mtx.vin.push_back(CTxIn(ctip.out));

    LogPrintf("%s: Withdrawal will spend CTIP: %s : %u.\n", __func__,
            ctip.out.hash.ToString(), ctip.out.n);

    // Start calculating amount returning to sidechain
    CAmount returnAmount = ctip.amount;
    mtx.vout.back().nValue += returnAmount;

    // Subtract payout amount from sidechain change return
    mtx.vout.back().nValue -= amountWithdrawn;

    if (mtx.vout.back().nValue < 0)
        return false;
    if (!mtx.vin.size())
        return false;

    // Check to make sure that all of the outputs in this Withdrawal are unknown / new
    for (size_t o = 0; o < mtx.vout.size(); o++) {
        if (pcoinsTip->HaveCoin(COutPoint(mtx.GetHash(), o))) {
            return false;
        }
    }
#endif

    tx = mtx;

    return true;
}


void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        } else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package) const
{
    for (CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee rate %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

/** Add descendants of given transactions to mapModifiedTx with ancestor
 * state updated assuming given transactions are inBlock. Returns number
 * of updated descendants. */
static int UpdatePackagesForAdded(const CTxMemPool& mempool,
                                  const CTxMemPool::setEntries& alreadyAdded,
                                  indexed_modified_transaction_set& mapModifiedTx) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    AssertLockHeld(mempool.cs);

    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc)) {
                continue;
            }
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                mit = mapModifiedTx.insert(modEntry).first;
            }
            mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(const CTxMemPool& mempool, int& nPackagesSelected, int& nDescendantsUpdated)
{
    AssertLockHeld(mempool.cs);

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty()) {
        // First try to find a new transaction in mapTx to evaluate.
        //
        // Skip entries in mapTx that are already in a block or are present
        // in mapModifiedTx (which implies that the mapTx ancestor state is
        // stale due to ancestor inclusion in the block)
        // Also skip transactions that we've already failed to add. This can happen if
        // we consider a transaction in mapModifiedTx and it fails: we can then
        // potentially consider it again while walking mapTx.  It's currently
        // guaranteed to fail again, but as a belt-and-suspenders check we put it in
        // failedTx and avoid re-evaluation, since the re-evaluation would be using
        // cached size/sigops/fee values that are not actually correct.
        /** Return true if given transaction from mapTx has already been evaluated,
         * or if the transaction's cached data in mapTx is incorrect. */
        if (mi != mempool.mapTx.get<ancestor_score>().end()) {
            auto it = mempool.mapTx.project<0>(mi);
            assert(it != mempool.mapTx.end());
            if (mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it)) {
                ++mi;
                continue;
            }
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        auto ancestors{mempool.AssumeCalculateMemPoolAncestors(__func__, *iter, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false)};

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i = 0; i < sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(mempool, ancestors, mapModifiedTx);
    }
}
} // namespace node
