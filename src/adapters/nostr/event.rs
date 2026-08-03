use crate::host_nostr::{Event, Kind};
use radroots_event_codec::job::traits::{JobEventBorrow, JobEventLike};

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
    fn raw_id(&'a self) -> String {
        self.id_hex.clone()
    }
    #[inline]
    fn raw_author(&'a self) -> String {
        self.author_hex.clone()
    }
    #[inline]
    fn raw_content(&'a self) -> &'a str {
        &self.evt.content
    }
    #[inline]
    fn raw_kind(&'a self) -> u32 {
        match self.evt.kind {
            Kind::Custom(v) => v as u32,
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
    fn raw_published_at(&self) -> u64 {
        self.evt.created_at.as_secs()
    }
    fn raw_kind(&self) -> u32 {
        match self.evt.kind {
            Kind::Custom(v) => v as u32,
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::NostrEventAdapter;
    use crate::host_nostr::{Event, GenericBuilder, Keys, Kind, Tag, TagKind};
    use radroots_event_codec::job::traits::{JobEventBorrow, JobEventLike};

    fn build_event(keys: &Keys, kind: Kind, tags: Vec<Tag>) -> Event {
        GenericBuilder::new(kind, "content")
            .tags(tags)
            .sign_with_keys(keys)
            .expect("event must sign")
    }

    #[test]
    fn adapter_exposes_borrow_and_owned_fields_for_custom_kind() {
        let keys = Keys::generate();
        let recipient = Keys::generate();
        let recipient_hex = recipient.public_key().to_hex();
        let tags = vec![Tag::custom(TagKind::p(), vec![recipient_hex.clone()])];
        let event = build_event(&keys, Kind::Custom(5322), tags);
        let adapter = NostrEventAdapter::new(&event);

        assert_eq!(JobEventBorrow::raw_id(&adapter), event.id.to_hex());
        assert_eq!(
            JobEventBorrow::raw_author(&adapter),
            event.pubkey.to_string()
        );
        assert_eq!(JobEventBorrow::raw_content(&adapter), "content");
        assert_eq!(JobEventBorrow::raw_kind(&adapter), 5322);

        assert_eq!(JobEventLike::raw_id(&adapter), event.id.to_hex());
        assert_eq!(JobEventLike::raw_author(&adapter), event.pubkey.to_string());
        assert_eq!(JobEventLike::raw_content(&adapter), "content".to_string());
        assert_eq!(JobEventLike::raw_kind(&adapter), 5322);
        assert_eq!(
            JobEventLike::raw_tags(&adapter),
            vec![vec!["p".to_string(), recipient_hex]]
        );
        assert_eq!(JobEventLike::raw_sig(&adapter), event.sig.to_string());
    }

    #[test]
    fn adapter_maps_non_custom_kind_to_zero() {
        let keys = Keys::generate();
        let event = build_event(&keys, Kind::Repost, Vec::new());
        let adapter = NostrEventAdapter::new(&event);

        assert_eq!(JobEventBorrow::raw_kind(&adapter), 0);
        assert_eq!(JobEventLike::raw_kind(&adapter), 0);
        assert_eq!(
            JobEventLike::raw_published_at(&adapter),
            event.created_at.as_secs()
        );
    }
}
