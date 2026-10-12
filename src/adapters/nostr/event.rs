use core::fmt;

use nostr::Event;
use radroots_event_codec::decode::job::{JobEventBorrow, JobEventLike};

#[derive(Clone)]
pub struct NostrEventAdapter<'a> {
    evt: &'a Event,
    id_hex: String,
    author_hex: String,
}

impl fmt::Debug for NostrEventAdapter<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NostrEventAdapter([redacted])")
    }
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
        u32::from(self.evt.kind.as_u16())
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
        u32::from(self.evt.kind.as_u16())
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
    use nostr::{Event, EventBuilder, Keys, Kind, Tag, TagKind, Timestamp};
    use radroots_event_codec::decode::job::{
        BorrowedEventAdapter, JobEventBorrow, JobEventLike, JobParseError,
    };
    use radroots_nostr::event::GenericBuilder;

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
        assert_eq!(format!("{adapter:?}"), "NostrEventAdapter([redacted])");

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
    fn adapter_preserves_named_and_custom_wire_kinds() {
        let keys = Keys::generate();
        for wire_kind in [0_u16, 1, 6, 5_001, 6_001, 7_000, u16::MAX] {
            let event = EventBuilder::new(Kind::from(wire_kind), "synthetic kind fixture")
                .custom_created_at(Timestamp::from(1_700_000_000))
                .sign_with_keys(&keys)
                .expect("signed synthetic event");
            let adapter = NostrEventAdapter::new(&event);
            assert_eq!(JobEventBorrow::raw_kind(&adapter), u32::from(wire_kind));
            assert_eq!(JobEventLike::raw_kind(&adapter), u32::from(wire_kind));
            assert_eq!(
                JobEventLike::raw_published_at(&adapter),
                event.created_at.as_secs()
            );
            if wire_kind != 7_000 {
                assert!(matches!(
                    adapter.to_job_feedback_metadata(),
                    Err(JobParseError::InvalidTag("kind (expected 7000)"))
                ));
            }
        }
    }

    #[test]
    fn adapter_decodes_signed_named_feedback_through_both_traits() {
        let keys = Keys::generate();
        let customer = Keys::generate();
        let request = build_event(&customer, Kind::Custom(5_001), Vec::new());
        let feedback = build_event(
            &keys,
            Kind::JobFeedback,
            vec![
                Tag::custom(TagKind::e(), vec![request.id.to_hex()]),
                Tag::custom(TagKind::p(), vec![request.pubkey.to_hex()]),
                Tag::parse(["status", "processing"]).expect("synthetic status tag"),
            ],
        );
        feedback.verify().expect("valid signed synthetic feedback");
        assert_eq!(feedback.kind, Kind::JobFeedback);
        let adapter = NostrEventAdapter::new(&feedback);
        let tags = JobEventLike::raw_tags(&adapter);
        let borrowed = BorrowedEventAdapter::new(
            &adapter,
            feedback.created_at.as_secs(),
            &tags,
            feedback.sig.to_string(),
        );

        for metadata in [
            adapter.to_job_feedback_metadata().expect("owned feedback"),
            borrowed
                .to_job_feedback_metadata()
                .expect("borrowed feedback"),
        ] {
            assert_eq!(metadata.kind, 7_000);
            assert_eq!(metadata.data.kind, 7_000);
            assert_eq!(metadata.data.request_event.id, request.id.to_hex());
            assert_eq!(metadata.data.customer_pubkey, Some(request.pubkey.to_hex()));
            assert_eq!(metadata.id, feedback.id.to_hex());
        }
        for parsed in [
            adapter.to_job_feedback_event_index().expect("owned index"),
            borrowed
                .to_job_feedback_event_index()
                .expect("borrowed index"),
        ] {
            assert_eq!(parsed.data.kind, 7_000);
            assert_eq!(parsed.data.data.request_event.id, request.id.to_hex());
            assert_eq!(parsed.event.kind_u32(), 7_000);
            assert_eq!(parsed.event.id_hex(), feedback.id.to_hex());
        }
    }
}
