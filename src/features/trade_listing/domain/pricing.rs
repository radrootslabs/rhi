use radroots_events::listing::RadrootsListing;
use radroots_trade::prelude::price_ext::BinPricingTryExt;
use radroots_trade::prelude::stage::order::{
    TradeListingOrderRequestPayload, TradeListingOrderResult,
};

use crate::features::trade_listing::handlers::order::JobRequestOrderError;

pub trait ListingOrderCalculator {
    fn calculate_order(
        &self,
        order: &TradeListingOrderRequestPayload,
    ) -> Result<TradeListingOrderResult, JobRequestOrderError>;
}

impl ListingOrderCalculator for RadrootsListing {
    fn calculate_order(
        &self,
        order: &TradeListingOrderRequestPayload,
    ) -> Result<TradeListingOrderResult, JobRequestOrderError> {
        if order.bin_id.trim().is_empty() {
            return Err(JobRequestOrderError::Unsatisfiable(format!(
                "requested bin id is empty"
            )));
        }

        if order.bin_count == 0 {
            return Err(JobRequestOrderError::Unsatisfiable(
                "requested bin count must be greater than 0".to_string(),
            ));
        }

        let bin = self
            .bins
            .iter()
            .find(|bin| bin.bin_id == order.bin_id)
            .ok_or_else(|| {
                JobRequestOrderError::Unsatisfiable(format!(
                    "requested bin {} not available",
                    order.bin_id
                ))
            })?;

        let out_price = bin.price_per_canonical_unit.clone();
        let out_subtotal = bin
            .try_subtotal_for_count(order.bin_count)
            .map_err(|err| {
                JobRequestOrderError::Unsatisfiable(format!(
                    "failed to price requested bin: {err}"
                ))
            })?;
        let out_total = bin
            .try_total_for_count(order.bin_count)
            .map_err(|err| {
                JobRequestOrderError::Unsatisfiable(format!(
                    "failed to total requested bin: {err}"
                ))
            })?;

        let discounts_out = self.discounts.clone().unwrap_or_default();

        Ok(TradeListingOrderResult {
            bin_id: order.bin_id.clone(),
            bin_count: order.bin_count,
            price: out_price,
            discounts: discounts_out,
            subtotal: out_subtotal,
            total: out_total,
        })
    }
}
