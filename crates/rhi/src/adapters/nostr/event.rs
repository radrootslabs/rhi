use nostr::event::Event;
use radroots_events_codec::job::traits::{JobEventBorrow, JobEventLike};

#[derive(Clone, Debug)]
pub struct NostrEventAdapter<'a> {
    evt: &'a Event,
    id_hex: String,
    author_hex: String,
}

impl<'a> NostrEventAdapter<'a> {
    #[inline]
    pub fn new(evt: &'a Event) -> Self {
        Self {
            evt,
            id_hex: evt.id.to_hex(),
            author_hex: evt.pubkey.to_string(),
        }
    }

    #[inline]
    fn tags_as_slices(&self) -> Vec<Vec<String>> {
        self.evt
            .tags
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect()
    }
}

impl<'a> JobEventBorrow<'a> for NostrEventAdapter<'a> {
    #[inline]
    fn raw_id(&'a self) -> &'a str {
        &self.id_hex
    }
    #[inline]
    fn raw_author(&'a self) -> &'a str {
        &self.author_hex
    }
    #[inline]
    fn raw_content(&'a self) -> &'a str {
        &self.evt.content
    }
    #[inline]
    fn raw_kind(&'a self) -> u32 {
        match self.evt.kind {
            nostr::event::Kind::Custom(v) => v as u32,
            _ => 0,
        }
    }
}

impl JobEventLike for NostrEventAdapter<'_> {
    fn raw_id(&self) -> String {
        self.id_hex.clone()
    }
    fn raw_author(&self) -> String {
        self.author_hex.clone()
    }
    fn raw_published_at(&self) -> u32 {
        self.evt.created_at.as_u64() as u32
    }
    fn raw_kind(&self) -> u32 {
        match self.evt.kind {
            nostr::event::Kind::Custom(v) => v as u32,
            _ => 0,
        }
    }
    fn raw_content(&self) -> String {
        self.evt.content.clone()
    }
    fn raw_tags(&self) -> Vec<Vec<String>> {
        self.tags_as_slices()
    }
    fn raw_sig(&self) -> String {
        self.evt.sig.to_string()
    }
}
