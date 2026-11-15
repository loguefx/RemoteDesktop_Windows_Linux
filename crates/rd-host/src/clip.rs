//! Clipboard sync (text, images and copied files) inside the desktop session, built on the shared
//! worker in `rd_core::clipboard`.

use rd_core::clipboard::Worker;
use rd_core::proto::AgentEvent;

use crate::agent::EventTx;

/// Start syncing: local changes become `AgentEvent::Clipboard`; data from viewers is
/// applied with [`Worker::set`]. Stops when the worker is dropped.
pub fn spawn(tx: EventTx) -> Worker {
    Worker::spawn(false, move |data| tx.send(AgentEvent::Clipboard(data)).is_ok())
}
