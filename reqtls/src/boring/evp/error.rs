
#[derive(Debug)]
pub enum EvpError {
    InitEvpPKeyCtx,
    InitKeygen,
    KeyGen,
    GetPubKey,
    InitDerive,
    SetPeerDerive,
    NewPublicKey,
    Derive,
}