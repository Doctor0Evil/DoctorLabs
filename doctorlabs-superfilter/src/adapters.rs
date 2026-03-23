// doctorlabs-superfilter/src/adapters.rs

use crate::{HarassmentFamily, SpanScore};
use crate::nih_psa::NihPsaSpan;

/// Convert an NIH/PSA span into a generic SpanScore for RogueScore.
pub fn nih_psa_span_to_span_score(span: &NihPsaSpan) -> SpanScore {
    // y,z,T,K,E are neutral here; threat mass is carried in familyweights.
    SpanScore {
        y_repetition: 0.0,
        z_drift: 0.0,
        t_toxicity: 0.0,
        k_kindness: 0.0,
        e_evidentiality: 0.0,
        familyweights: span.semantic.family_weight.clone(),
    }
}
