#include <rpc/sidechainrpc.h>
#include <rpc/util.h>
#include <rpc/server.h>
#include <sidechain.h>
#include <sidechaindb.h>

static RPCHelpMan createsidechainproposal()
{
    return RPCHelpMan{
        "createsidechainproposal",
        "Generates a sidechain proposal to be included in the next block mined by this node",
        {
            {"nsidechain", RPCArg::Type::NUM, RPCArg::Optional::NO, "sidechain slot number"},
            {"title", RPCArg::Type::STR, RPCArg::Optional::NO, "sidechain title"},
            {"description", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "sidechain description"},
            {"version", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "sidechain / proposal version"},
            {"hashid1", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "256 bits used to identify sidechain"},
            {"hashid2", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "160 bits used to identify sidechain"}
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "status", "response status"},
                {RPCResult::Type::STR, "message", "response message"},
                {RPCResult::Type::OBJ, "result", "response result",
                    {
                        {RPCResult::Type::NUM, "nsidechain", "sidechain number"},
                        {RPCResult::Type::STR, "title", "sidechain title"},
                        {RPCResult::Type::STR, "description", "sidechain description"},
                        {RPCResult::Type::NUM, "version", "sidechain version"},
                    }
                },
                {RPCResult::Type::STR, "error", "response error"},
            },
        },
        RPCExamples{
            HelpExampleCli("createsidechainproposal", "1 \"Namecoin\" \"Namecoin as a Bitcoin sidechain\" 0 78b140259d5626e17c4bf339c23cb4fa8d16d138f71d9803ec394bb01c051f0b 90869d013db27608c7428251c6755e5a1d9e9313")
            + "\n" + 
            HelpExampleRpc("createsidechainproposal", "1 \"Namecoin\" \"Namecoin as a Bitcoin sidechain\" 0 78b140259d5626e17c4bf339c23cb4fa8d16d138f71d9803ec394bb01c051f0b 90869d013db27608c7428251c6755e5a1d9e9313")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            int nSidechain = request.params[0].getInt<int>();
            if (nSidechain < 0 || nSidechain > 255)
                throw JSONRPCError(RPC_MISC_ERROR, "Invalid sidechain number!");

            std::string strTitle = request.params[1].get_str();

            std::string strDescription = "";
            if (request.params.size() >= 3)
                strDescription = request.params[2].get_str();

            std::string strHashID1 = "";
            std::string strHashID2 = "";
            if (request.params.size() >= 5) {
                strHashID1 = request.params[4].get_str();
                if (strHashID1.size() != 64)
                    throw JSONRPCError(RPC_MISC_ERROR, "HashID1 size invalid!");
            }
            if (request.params.size() == 6) {
                strHashID2 = request.params[5].get_str();
                if (strHashID2.size() != 40)
                    throw JSONRPCError(RPC_MISC_ERROR, "HashID2 size invalid!");
            }

            const uint8_t nSC = nSidechain;
            const unsigned char vchSC[1] = { nSC };

            std::vector<unsigned char> vch256;
            vch256.resize(CSHA256::OUTPUT_SIZE);
            CSHA256().Write(&vchSC[0], 1).Finalize(&vch256[0]);

            CKey key;
            key.Set(vch256.begin(), vch256.end(), false);
            if (!key.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

            CPubKey pubkey = key.GetPubKey();
            if (!key.VerifyPubKey(pubkey))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Failed to verify pubkey");

            CKeyID vchAddress = pubkey.GetID();

            CScript sidechainScript = CScript() << OP_DUP << OP_HASH160 << ToByteVector(vchAddress) << OP_EQUALVERIFY << OP_CHECKSIG;



            UniValue obj(UniValue::VOBJ);
            obj.pushKV("status", true);
            obj.pushKV("message", "sidechain proposal created successfully");
            obj.pushKV("error", "");
            UniValue result(UniValue::VOBJ);
            result.pushKV("nsidechain", request.params[0]);
            result.pushKV("title", request.params[1]);
            result.pushKV("description", request.params[2]);
            result.pushKV("version", request.params[3]);
            obj.pushKV("result", result);
            return obj;
        }
    };
}


static RPCHelpMan listsidechainproposals() {
    return RPCHelpMan{
        "listsidechainproposals",
        "List your own cached sidechain proposals\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "title", "sidechain title"},
                    {RPCResult::Type::STR, "description", "sidechain description"},
                    {RPCResult::Type::NUM, "version", "sidechain version"},
                    {RPCResult::Type::STR, "hashid1", "sidechain hashid1"},
                    {RPCResult::Type::STR, "hashid2", "sidechain hashid2"},
                }}
            }
        },
        RPCExamples{
            HelpExampleCli("listsidechainproposals", "")
            + HelpExampleRpc("listsidechainproposals", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            //  std::vector<Sidechain> vProposal = scdb.GetSidechainProposals();
            return NullUniValue;
        }
    };
}


void RegisterSidechainRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"sidechain", &createsidechainproposal},
        {"sidechain", &listsidechainproposals},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
