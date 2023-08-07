use super::*;

#[derive(Debug, Parser)]
pub(crate) struct CheckIndex {}

impl CheckIndex {
  pub(crate) fn run(self, options: Options) -> Result {
    let path = if let Some(path) = &options.index {
      path.clone()
    } else {
      options.data_dir()?.join("index.redb")
    };

    if let Ok(file) = fs::OpenOptions::new().read(true).open(&path) {
      if Index::is_index_file_corrupted(file) {
        println!("Index file {:?} needs recovery.", path);
      } else {
        println!("Index file {:?} doesn't need recovery.", path);
      }
    } else {
      println!("Can't open {:?} for reading", path);
    }

    Ok(())
  }
}
