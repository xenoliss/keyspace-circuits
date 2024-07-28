use serde::{Deserialize, Serialize};

use super::{insert::IMTInsert, update::IMTUpdate};

#[derive(Debug, Deserialize, Serialize)]
pub enum IMTMutate {
    Insert(IMTInsert),
    Update(IMTUpdate),
}

impl IMTMutate {
    /// Apply the IMT mutation and return the new updated root.
    ///
    /// Before performong the mutation, the state is checked to make sure it is coherent.
    /// In case of any inconsistency, `None` is returned.
    pub fn apply(&self) -> Option<[u8; 32]> {
        match &self {
            IMTMutate::Insert(insert) => insert.apply(),
            IMTMutate::Update(update) => update.apply(),
        }
    }
}
