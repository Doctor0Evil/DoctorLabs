// path: crates/cybernano-quiet-violence/src/lib.rs
#![forbid(unsafe_code)]

use core::fmt;
use alloc::vec::Vec;
use alloc::string::String;

/// Minimal view of a block from `cybernano-bci-codec`.
#[derive(Clone, Debug)]
pub struct HexBlock {
    pub key: &'static str,   // e.g. "motor-alpha", "somatosensory-beta"
    pub l1norm: u64,         // sum |code_i| in this block
    pub digitcount: usize,   // total hex digits
    pub nonzeronibbles: usize,
}

/// Snapshot at one decision window, mirrored from codec crate.
#[derive(Clone, Debug)]
pub struct EegCodeSnapshot {
    pub blocks: Vec<HexBlock>,
}

impl EegCodeSnapshot {
    pub fn totall1(&self) -> u64 {
        self.blocks.iter().map(|b| b.l1norm).sum()
    }
}

/// Fused session state: extend as needed for XR/pose/haptics.
#[derive(Clone, Debug)]
pub struct FusedState {
    pub eeg: EegCodeSnapshot,
    pub haptic_energy: f32,  // e.g. L1 norm over haptic actuators
    pub visual_flux: f32,    // flicker/brightness index
    pub session_minutes: f32,
    pub duty_cycle: f32,     // fraction of last hour "on"
    pub roh: f32,            // current Risk-of-Harm scalar
    pub limbic_activation: f32, // proxy from ROI/network metrics
}

/// Harassment scores at time t.
#[derive(Clone, Copy, Debug, Default)]
pub struct HarassmentScores {
    pub hta: f32,
    pub psa: f32,
    pub nhsp: f32,
    pub nih: f32,
}

impl fmt::Display for HarassmentScores {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "HTA={:.3}, PSA={:.3}, NHSP={:.3}, NIH={:.3}",
            self.hta, self.psa, self.nhsp, self.nih
        )
    }
}

/// Main detector preferences and thresholds; monotone-tuned, non-reversible.
pub struct QuietViolenceDetector {
    pub max_safe_haptic_l1: u64,
    pub max_safe_duty_cycle: f32,
    pub max_safe_session_minutes: f32,
    pub max_safe_roh: f32,
    pub max_safe_limbic: f32,
    pub nih_nullspace_floor: usize,
    pub nih_roh_ceiling: f32,
    pub weights: (f32, f32, f32, f32),
}

#[derive(Clone, Debug)]
pub enum QVError {
    RoHAboveCeiling { roh: f32, ceiling: f32 },
    NullspaceShrank { before: usize, after: usize, floor: usize },
}

/// Effective summary for court-admissible logs.
#[derive(Clone, Debug)]
pub struct QuietViolenceIndex {
    pub scores: HarassmentScores,
    pub qv_scalar: f32,
    pub roh: f32,
    pub nullspace_dim_before: usize,
    pub nullspace_dim_after: usize,
}

impl fmt::Display for QuietViolenceIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "QV={:.3} [{}], RoH={:.3}, nullspace {}->{}",
            self.qv_scalar,
            self.scores,
            self.roh,
            self.nullspace_dim_before,
            self.nullspace_dim_after
        )
    }
}

impl QuietViolenceDetector {
    pub fn new() -> Self {
        Self {
            max_safe_haptic_l1: 10_000,
            max_safe_duty_cycle: 0.5,
            max_safe_session_minutes: 60.0,
            max_safe_roh: 0.3,
            max_safe_limbic: 0.2,
            nih_nullspace_floor: 16,
            nih_roh_ceiling: 0.3,
            weights: (1.0, 1.0, 1.0, 1.0),
        }
    }

    /// Compute harassment scores from fused state and simple history deltas.
    pub fn scores(
        &self,
        state: &FusedState,
        prev_state: Option<&FusedState>,
    ) -> HarassmentScores {
        // HTA: excessive haptic load relative to EEG energy.
        let haptic_ratio = if state.eeg.totall1() > 0 {
            state.haptic_energy / (state.eeg.totall1() as f32 + 1.0)
        } else {
            0.0
        };
        let hta = if state.haptic_energy as u64 > self.max_safe_haptic_l1 {
            haptic_ratio
        } else {
            0.0
        };

        // PSA: duty cycle and session length beyond charter corridors.
        let psa_dc = if state.duty_cycle > self.max_safe_duty_cycle {
            (state.duty_cycle - self.max_safe_duty_cycle)
        } else {
            0.0
        };
        let psa_time = if state.session_minutes > self.max_safe_session_minutes {
            (state.session_minutes - self.max_safe_session_minutes) / self.max_safe_session_minutes
        } else {
            0.0
        };
        let psa = psa_dc + psa_time;

        // NHSP: spikes in RoH or limbic activation vs previous window, plus visual flux.
        let (delta_roh, delta_limbic) = match prev_state {
            Some(prev) => (state.roh - prev.roh, state.limbic_activation - prev.limbic_activation),
            None => (0.0, 0.0),
        };
        let nhsp = delta_roh.max(0.0) + delta_limbic.max(0.0) + state.visual_flux;

        // NIH: will be plugged with decoder/charter data from sovereignty crate.
        HarassmentScores {
            hta,
            psa,
            nhsp,
            nih: 0.0,
        }
    }

    /// Combine scores and check simple invariants related to NIH.
    pub fn index(
        &self,
        state: &FusedState,
        prev_state: Option<&FusedState>,
        nullspace_dim_before: usize,
        nullspace_dim_after: usize,
    ) -> Result<QuietViolenceIndex, QVError> {
        if state.roh > self.nih_roh_ceiling {
            return Err(QVError::RoHAboveCeiling {
                roh: state.roh,
                ceiling: self.nih_roh_ceiling,
            });
        }
        if nullspace_dim_after < self.nih_nullspace_floor || nullspace_dim_after < nullspace_dim_before {
            return Err(QVError::NullspaceShrank {
                before: nullspace_dim_before,
                after: nullspace_dim_after,
                floor: self.nih_nullspace_floor,
            });
        }

        let mut scores = self.scores(state, prev_state);
        // Simple NIH term: pressure on nullspace & RoH envelope.
        let nih_pressure = if nullspace_dim_after == nullspace_dim_before {
            0.0
        } else {
            (nullspace_dim_before as f32 - nullspace_dim_after as f32).max(0.0)
        };
        scores.nih = nih_pressure + (state.roh / self.max_safe_roh).max(0.0);

        let (w_hta, w_psa, w_nhsp, w_nih) = self.weights;
        let qv = w_hta * scores.hta + w_psa * scores.psa + w_nhsp * scores.nhsp + w_nih * scores.nih;

        Ok(QuietViolenceIndex {
            scores,
            qv_scalar: qv,
            roh: state.roh,
            nullspace_dim_before,
            nullspace_dim_after,
        })
    }
}
