// doctor_labs_superfilter/src/wordmath.rs
use crate::{SpanScore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordMathAnalysis {
    pub y: f64,
    pub z: f64,
    pub t: f64,
    pub k: f64,
    pub e: f64,
}

pub trait AsSpanScore {
    fn to_span_score(self) -> SpanScore;
}

impl AsSpanScore for WordMathAnalysis {
    fn to_span_score(self) -> SpanScore {
        SpanScore {
            y_repetition: self.y,
            z_drift: self.z,
            t_toxicity: self.t,
            k_kindness: self.k,
            e_evidentiality: self.e,
            family_weights: HashMap::new(),
        }
    }
}
