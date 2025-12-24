use radroots_core::{RadrootsCoreQuantity, RadrootsCoreQuantityPrice};
use radroots_events::listing::{
    RadrootsListing, RadrootsListingDiscount, RadrootsListingQuantity,
};
use radroots_trade::prelude::price_ext::ListingPricingExt;
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
        let req_qty: &RadrootsListingQuantity = &order.quantity;
        let req_qty_amount = req_qty.value.amount;
        let req_qty_unit = req_qty.value.unit;
        let req_qty_label_opt = req_qty.label.as_deref();

        let matched_packaging = self.quantities.iter().any(|q| {
            let same_amount = q.value.amount.normalize() == req_qty_amount.normalize();
            let same_unit = q.value.unit == req_qty_unit;
            let label_ok = match (q.label.as_deref(), req_qty_label_opt) {
                (Some(l), Some(r)) => l == r,
                (None, None) => true,
                _ => false,
            };
            same_amount && same_unit && label_ok
        });

        if !matched_packaging {
            return Err(JobRequestOrderError::Unsatisfiable(format!(
                "requested packaging {} {} {} not available",
                req_qty_amount,
                req_qty_unit,
                req_qty_label_opt.unwrap_or("")
            )));
        }

        let req_money = order.price.amount.clone().quantize_to_currency();

        let matched_tier: &RadrootsCoreQuantityPrice = self
            .prices
            .iter()
            .find(|p| {
                let money_ok = p.amount.currency == req_money.currency
                    && p.amount.amount.normalize() == req_money.amount.normalize();
                let per_amt_ok =
                    p.quantity.amount.normalize() == order.price.quantity.amount.normalize();
                let per_unit_ok = p.quantity.unit == order.price.quantity.unit;
                money_ok && per_amt_ok && per_unit_ok
            })
            .ok_or_else(|| {
                JobRequestOrderError::Unsatisfiable(format!(
                    "no matching price tier {} {} found",
                    order.price.quantity.amount, order.price.quantity.unit
                ))
            })?;

        let price_amount = matched_tier.amount.clone();
        let price_quantity = matched_tier.quantity.clone();

        let discounts_out: Vec<RadrootsListingDiscount> =
            self.discounts.clone().unwrap_or_default();

        let out_quantity = RadrootsListingQuantity {
            value: RadrootsCoreQuantity::new(req_qty_amount, req_qty_unit),
            label: req_qty.label.clone(),
            count: req_qty.count,
        };

        let out_price = RadrootsCoreQuantityPrice {
            amount: price_amount.clone(),
            quantity: price_quantity.clone(),
        };

        let out_subtotal = out_price.subtotal_for(&out_quantity);
        let out_total = out_price.total_for(&out_quantity);

        Ok(TradeListingOrderResult {
            quantity: out_quantity,
            price: out_price,
            discounts: discounts_out,
            subtotal: out_subtotal,
            total: out_total,
        })
    }
}
