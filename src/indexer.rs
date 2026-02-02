use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use codec::Decode;
use futures::TryStreamExt;
use mongodb::{bson::{doc, Bson}, options::ClientOptions, Client};
use subxt::utils::AccountId32;
use crate::chain_helpers::decode_hex;
use crate::primitives::{Commitment, CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1, CorevoVote, PrefixedCorevoRemark, PublicKeyForEncryption, Salt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextConfig {
    pub proposer: AccountId32,
    pub voters: HashSet<HashableAccountId>,
    pub maybe_common_salt: Option<Salt>
}

/// Holds the last known status of one participant's vote, whether we can decipher it or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoteStatus {
    Committed(Commitment),
    Revealed(Result<CorevoVote, &'static str>),
    RevealedWithoutCommitment
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashableAccountId(AccountId32);

impl std::hash::Hash for HashableAccountId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0 .0.hash(state);
    }
}

impl From<AccountId32> for HashableAccountId {
    fn from(account_id: AccountId32) -> Self {
        HashableAccountId(account_id)
    }
}


pub async fn get_history() -> Result<(), Box<dyn std::error::Error>> {
    let mut voter_pubkeys: HashMap<HashableAccountId, PublicKeyForEncryption> = HashMap::new();
    let mut context_configs: HashMap<CorevoContext, ContextConfig> = HashMap::new();
    let mut context_votes: HashMap<CorevoContext, HashMap<HashableAccountId, VoteStatus>> = HashMap::new();

    // Adjust the URI, database, and collection as needed.
    let uri = "mongodb://readonly:123456@62.84.182.186:27017/?directConnection=true";
    let db_name = "litescan_kusama_assethub";
    let coll_name = "extrinsics";

    let mut client_options = ClientOptions::parse(uri).await?;
    client_options.app_name = Some("corevo-print-remarks".to_string());
    let client = Client::with_options(client_options)?;

    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>(coll_name);

    // Query: { method: "remark", "args.remark": { $regex: /^0xcc00ee/i } }
    let filter = doc! {
        "method": "remark",
        "args.remark": { "$regex": "^0xcc00ee", "$options": "i" }
    };
    let count = coll.count_documents(filter.clone()).await?;
    println!("⛓🗄️ Found {} corevo-prefixed remarks", count);

    let mut cursor = coll.find(filter).await?;
    while let Some(doc) = cursor.try_next().await? {
        // Safely navigate to args.remark
        let remark = doc.get_document("args")
            .ok()
            .and_then(|args| args.get("remark"))
            .and_then(|v| match v {
                Bson::String(s) => Some(s.as_str()),
                _ => None,
            });
        let Some(sender) = doc.get_document("signer")
            .ok()
            .and_then(|signer_doc| signer_doc.get_str("Id").ok())
            .and_then(|s| AccountId32::from_str(s).ok())
        else {
            log::warn!("ignoring remark with no signer");
            continue;
        };

        if let Some(r) = remark {
            let result = decode_hex(r)
                .and_then(|remark_bytes| Ok(PrefixedCorevoRemark::decode(&mut remark_bytes.as_slice())
                    .and_then(|pcr| {
                        #[allow(irrefutable_let_patterns)]
                        if let CorevoRemark::V1(cr) = pcr.0 {
                            log::debug!("corevo remark: {}", cr);
                            let CorevoRemarkV1 { context, msg }  = cr;
                            match msg {
                                CorevoMessage::AnnounceOwnPubKey(pubkey) => {
                                    let _ = voter_pubkeys.insert(sender.into(), pubkey);
                                },
                                CorevoMessage::InviteVoter(voter, _encrypted_common_salt) => {
                                    context_configs.entry(context.clone())
                                        .or_insert_with(|| ContextConfig {
                                            proposer: sender.clone(),
                                            voters: HashSet::new(),
                                            maybe_common_salt: None,
                                        }).voters.insert(HashableAccountId(voter.clone()));
                                },
                                CorevoMessage::Commit(commitment, _encrypted_vote_and_salt) => {
                                    context_votes.entry(context.clone())
                                            .or_insert_with(HashMap::new)
                                            .insert(HashableAccountId(sender.clone()), VoteStatus::Committed(commitment));
                                },
                                CorevoMessage::RevealOneTimeSalt(_onetime_salt) => {
                                    let votes = context_votes.entry(context.clone())
                                        .or_insert_with(HashMap::new);
                                    match votes.get(&HashableAccountId(sender.clone())) {
                                        Some(VoteStatus::Committed(_)) => {
                                            votes.insert(HashableAccountId(sender.clone()), VoteStatus::Revealed(Err("Deciphering not implemented")));
                                        },
                                        None => {
                                            log::warn!("Vote for {} in context {:?} was revealed but we don't know of any commitment", sender, context);
                                            votes.insert(HashableAccountId(sender.clone()), VoteStatus::RevealedWithoutCommitment);
                                        },
                                        Some(VoteStatus::Revealed(_)) | Some(VoteStatus::RevealedWithoutCommitment) => {
                                            log::warn!("Vote for {} in context {:?} was already revealed. ignoring subsequent commitments or reveals", sender, context);
                                        },
                                    }
                                },
                            }
                        }
                        Ok(())
                    })));
            if result == Ok(Ok(())) {
                continue;
            };
            log::warn!("failed on remark: {:?}", result);
        }
    }
    println!("⛓🗄️ ======== TURNOUT FOR ALL CONTEXTS ========");
    for (context, config) in context_configs.iter() {
        println!("⛓🗄️ Context: {}", context);
        println!("⛓🗄️   Proposer: {}", config.proposer);
        println!("⛓🗄️   Invited Voters:");
        for voter in config.voters.iter() {
            println!("⛓🗄️     {}", voter.0);
        }
        if let Some(votes) = context_votes.get(context) {
            println!("⛓🗄️   Votes:");
            for voter in config.voters.iter() {
                match votes.get(voter) {
                    None => {
                        println!("⛓🗄️     {}: Uncast", voter.0);
                    },
                    Some(VoteStatus::Committed(_)) => {
                        println!("⛓🗄️     {}: Committed (not revealed yet)", voter.0);
                    },
                    Some(VoteStatus::Revealed(Ok(vote))) => {
                        println!("⛓🗄️     {}: Revealed vote {:?}", voter.0, vote);
                    },
                    Some(VoteStatus::Revealed(Err(e))) => {
                        println!("⛓🗄️     {}: Revealed but could not decipher vote: {}", voter.0, e);
                    },
                    Some(VoteStatus::RevealedWithoutCommitment) => {
                        println!("⛓🗄️     {}: Revealed without prior commitment", voter.0);
                    },
                }
            }
        } else {
            println!("⛓🗄️   No votes recorded for this context.");
        }
    }
    println!("⛓🗄️ ========");
    Ok(())
}