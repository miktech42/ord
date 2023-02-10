use {
  anyhow::{anyhow, Result},
  bitcoin::{consensus::encode::Decodable, Transaction, Txid},
  bitcoincore_rpc::bitcoincore_rpc_json::GetBlockchainInfoResult,
  oxhttp::{
    model::{Method, Request, Status},
    Client,
  },
};

pub(crate) struct Rest {
  client: Client,
  url: String,
}

impl Rest {
  pub(crate) fn new(url: String) -> Self {
    let client = Client::new();
    let url = if !url.starts_with("http://") {
      "http://".to_string() + &url
    } else {
      url
    };
    Rest { client, url }
  }

  pub(crate) fn get_chain_info(&self) -> Result<GetBlockchainInfoResult> {
    let url = format!("{}/rest/chaininfo.json", self.url);
    let response = self
      .client
      .request(Request::builder(Method::GET, url.parse()?).build())?;
    if response.status() != Status::OK {
      return Err(anyhow!("Error fetching blockchain info from REST endpoint"));
    }
    let str = response.into_body().to_string()?;
    let info = serde_json::from_str(&str)?;
    Ok(info)
  }

  pub(crate) fn get_raw_transaction(&self, txid: &Txid) -> Result<Option<Transaction>> {
    let url = format!("{}/rest/tx/{txid:x}.bin", self.url);
    let response = self
      .client
      .request(Request::builder(Method::GET, url.parse()?).build())?;
    if response.status() == Status::NOT_FOUND {
      return Ok(None);
    }
    if response.status() != Status::OK {
      return Err(anyhow!("Error fetching {txid:x} bin from REST endpoint"));
    }
    let tx = Transaction::consensus_decode(&mut response.into_body())?;
    Ok(Some(tx))
  }
}
