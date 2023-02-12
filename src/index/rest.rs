use {
  super::simplehttp::SimpleHttpTransport,
  anyhow::Result,
  bitcoin::{BlockHash, Transaction, Txid},
};

pub(crate) struct Rest {
  client: SimpleHttpTransport,
}

impl Rest {
  pub(crate) fn new(url: &str) -> Self {
    let client = SimpleHttpTransport::new(url).unwrap();
    Rest { client }
  }

  pub(crate) fn get_block_hash(&mut self, height: u32) -> Result<BlockHash> {
    let url = format!("/rest/blockhashbyheight/{height}.bin");
    let info = self.client.request(&url)?;
    Ok(info)
  }

  pub(crate) fn get_raw_transaction(&mut self, txid: &Txid) -> Result<Transaction> {
    let url = format!("/rest/tx/{txid:x}.bin");
    let tx = self.client.request(&url)?;
    Ok(tx)
  }
}
