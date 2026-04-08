use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FeatureVector {
    pub pkt_rate: f32,
    pub syn_rate: f32,
    pub ua_entropy: f32,
    pub req_burst: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMeta {
    pub name: String,
    pub version: String,
    pub decision_threshold: f32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct InferenceResult {
    pub risk_score: f32,
    pub is_anomaly: bool,
}

#[derive(Debug, Clone)]
pub struct Model {
    meta: ModelMeta,
}

impl Model {
    pub fn load(meta_path: impl AsRef<Path>) -> Result<Self> {
        let raw = fs::read_to_string(meta_path.as_ref())
            .with_context(|| format!("read model meta {}", meta_path.as_ref().display()))?;
        let meta: ModelMeta = serde_json::from_str(&raw).context("parse model meta json")?;
        Ok(Self { meta })
    }

    pub fn meta(&self) -> &ModelMeta {
        &self.meta
    }

    pub fn predict(&self, f: FeatureVector) -> InferenceResult {
        // Heuristic scoring until ONNX runtime is wired in.
        let z =
            0.012 * f.pkt_rate + 0.035 * f.syn_rate + 0.9 * f.ua_entropy + 0.08 * f.req_burst
                - 3.2;
        let score = 1.0 / (1.0 + (-z).exp());
        InferenceResult {
            risk_score: score,
            is_anomaly: score >= self.meta.decision_threshold,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct InferenceStats {
    pub decisions: u64,
    pub anomalies: u64,
    pub risk_ewma: f32,
}

impl InferenceStats {
    pub fn update(&mut self, out: InferenceResult) {
        self.decisions = self.decisions.saturating_add(1);
        if out.is_anomaly {
            self.anomalies = self.anomalies.saturating_add(1);
        }
        // Alpha=0.05 for low-noise short-term trend.
        let alpha = 0.05_f32;
        self.risk_ewma = if self.decisions == 1 {
            out.risk_score
        } else {
            self.risk_ewma * (1.0 - alpha) + out.risk_score * alpha
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_threshold_works() {
        let model = Model {
            meta: ModelMeta {
                name: "test".to_string(),
                version: "0.0.0".to_string(),
                decision_threshold: 0.7,
            },
        };

        let benign = model.predict(FeatureVector {
            pkt_rate: 20.0,
            syn_rate: 1.0,
            ua_entropy: 0.3,
            req_burst: 2.0,
        });
        assert!(!benign.is_anomaly);

        let suspicious = model.predict(FeatureVector {
            pkt_rate: 800.0,
            syn_rate: 110.0,
            ua_entropy: 2.1,
            req_burst: 40.0,
        });
        assert!(suspicious.is_anomaly);
    }
}
