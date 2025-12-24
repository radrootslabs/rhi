#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use radroots_trade::listing::order::TradeOrderStatus;

#[derive(Clone, Debug)]
pub struct TradeOrderState {
    pub order_id: String,
    pub listing_addr: String,
    pub buyer_pubkey: String,
    pub seller_pubkey: String,
    pub status: TradeOrderStatus,
    pub seen_event_ids: HashSet<String>,
}

#[derive(Debug, Default)]
pub struct TradeListingState {
    validated_listings: HashSet<String>,
    orders: HashMap<String, TradeOrderState>,
}

impl TradeListingState {
    pub fn mark_listing_validated(&mut self, listing_addr: &str) {
        self.validated_listings.insert(listing_addr.to_string());
    }

    pub fn is_listing_validated(&self, listing_addr: &str) -> bool {
        self.validated_listings.contains(listing_addr)
    }

    pub fn order_exists(&self, order_id: &str) -> bool {
        self.orders.contains_key(order_id)
    }

    pub fn get_order_mut(&mut self, order_id: &str) -> Option<&mut TradeOrderState> {
        self.orders.get_mut(order_id)
    }

    pub fn insert_order(&mut self, order: TradeOrderState) {
        self.orders.insert(order.order_id.clone(), order);
    }

    pub fn mark_event_seen(&mut self, order_id: &str, event_id: &str) -> bool {
        if let Some(state) = self.orders.get_mut(order_id) {
            state.seen_event_ids.insert(event_id.to_string())
        } else {
            false
        }
    }

    pub fn is_event_seen(&self, order_id: &str, event_id: &str) -> bool {
        self.orders
            .get(order_id)
            .map(|state| state.seen_event_ids.contains(event_id))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TradeListingStateError {
    MissingOrder,
    InvalidTransition { from: TradeOrderStatus, to: TradeOrderStatus },
}

impl core::fmt::Display for TradeListingStateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TradeListingStateError::MissingOrder => write!(f, "missing order state"),
            TradeListingStateError::InvalidTransition { from, to } => {
                write!(f, "invalid order transition: {from:?} -> {to:?}")
            }
        }
    }
}

impl std::error::Error for TradeListingStateError {}

#[cfg(test)]
mod tests {
    use super::{TradeListingState, TradeOrderState};
    use radroots_trade::listing::order::TradeOrderStatus;

    #[test]
    fn state_tracks_listings_and_events() {
        let mut state = TradeListingState::default();
        assert!(!state.is_listing_validated("addr"));
        state.mark_listing_validated("addr");
        assert!(state.is_listing_validated("addr"));

        let order = TradeOrderState {
            order_id: "order-1".into(),
            listing_addr: "addr".into(),
            buyer_pubkey: "buyer".into(),
            seller_pubkey: "seller".into(),
            status: TradeOrderStatus::Requested,
            seen_event_ids: Default::default(),
        };
        state.insert_order(order);
        assert!(!state.is_event_seen("order-1", "evt"));
        assert!(state.mark_event_seen("order-1", "evt"));
        assert!(state.is_event_seen("order-1", "evt"));
    }
}
