use std::collections::BTreeMap;
use std::fmt;

use hartevo_domain_kernel::{KpiContract, KpiDirection, OperatingMode, ProjectId};
use rust_decimal::Decimal;

use crate::data_plane::DesktopCatalogMissionRequest;

const VM07_MANIFEST_ID: &str = "VM-07";
const GM01_MARKET: &str = "DE";
const GM01_LOCALE: &str = "de-DE";
const GM01_AUDIENCE: &str = "Germany market-entry decision stakeholders";
const GM01_TIMEZONE: &str = "Europe/Berlin";
const GM01_CURRENCY: &str = "EUR";
const GM01_KPI_ID: &str = "decision_ready_evidence_pack_count";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Gm01NaturalLanguageBlock {
    ExternalWriteRequested,
    ConflictingTargetMarket,
}

impl Gm01NaturalLanguageBlock {
    pub(crate) const fn user_message(self) -> &'static str {
        match self {
            Self::ExternalWriteRequested => {
                "这条目标同时要求外部写入；GM-01 只允许只读研究与本地决策，不会自动发布、发送、购买或付款。"
            }
            Self::ConflictingTargetMarket => {
                "目标同时包含另一个明确的进入市场；请只保留德国，或展开 Operating Contract 显式选择单一市场。"
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Gm01NaturalLanguageContract {
    goal: String,
}

impl fmt::Debug for Gm01NaturalLanguageContract {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gm01NaturalLanguageContract")
            .field("manifest_id", &VM07_MANIFEST_ID)
            .field("market", &GM01_MARKET)
            .field("locale", &GM01_LOCALE)
            .field("currency", &GM01_CURRENCY)
            .field("budget_minor", &0)
            .field("goal", &"[REDACTED]")
            .field("external_write_authority", &false)
            .finish()
    }
}

impl Gm01NaturalLanguageContract {
    pub(crate) const fn manifest_id(&self) -> &'static str {
        VM07_MANIFEST_ID
    }

    pub(crate) const fn market(&self) -> &'static str {
        GM01_MARKET
    }

    pub(crate) const fn locale(&self) -> &'static str {
        GM01_LOCALE
    }

    pub(crate) const fn currency(&self) -> &'static str {
        GM01_CURRENCY
    }

    pub(crate) fn into_request(self, project_id: ProjectId) -> DesktopCatalogMissionRequest {
        DesktopCatalogMissionRequest {
            project_id,
            manifest_id: VM07_MANIFEST_ID.into(),
            mode: OperatingMode::OneOffDecision,
            parent_mission_id: None,
            title: Some("Germany market entry decision".into()),
            goal: self.goal,
            market: GM01_MARKET.into(),
            language: GM01_LOCALE.into(),
            audience: GM01_AUDIENCE.into(),
            timezone: GM01_TIMEZONE.into(),
            kpis: BTreeMap::from([(
                GM01_KPI_ID.into(),
                KpiContract {
                    baseline: Some(Decimal::ZERO),
                    target: Decimal::ONE,
                    unit: "count".into(),
                    direction: KpiDirection::AtLeast,
                },
            )]),
            budget_minor: 0,
            currency: GM01_CURRENCY.into(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum Gm01NaturalLanguageMatch {
    NotApplicable,
    Blocked(Gm01NaturalLanguageBlock),
    Ready(Gm01NaturalLanguageContract),
}

pub(crate) fn compile_gm01_natural_language(goal: &str) -> Gm01NaturalLanguageMatch {
    let goal = goal.trim();
    if goal.is_empty() {
        return Gm01NaturalLanguageMatch::NotApplicable;
    }
    let normalized = goal.to_lowercase();
    if !contains_any(
        &normalized,
        &[
            "germany",
            "german market",
            "deutschland",
            "deutschen markt",
            "德国",
            "ドイツ",
        ],
    ) || !contains_any(
        &normalized,
        &[
            "evaluate",
            "assess",
            "whether",
            "should enter",
            "market decision",
            "market-entry decision",
            "go/no-go",
            "go no go",
            "评估",
            "是否",
            "决策",
            "評価",
        ],
    ) {
        return Gm01NaturalLanguageMatch::NotApplicable;
    }
    if contains_any(
        &normalized,
        &[
            "japanese market",
            "japan market",
            "enter japan",
            "us market",
            "american market",
            "enter the united states",
            "进入日本",
            "日本市场",
            "进入美国",
            "美国市场",
            "英国市场",
            "french market",
        ],
    ) {
        return Gm01NaturalLanguageMatch::Blocked(
            Gm01NaturalLanguageBlock::ConflictingTargetMarket,
        );
    }
    if contains_any(
        &normalized,
        &[
            "publish",
            "post to",
            "send email",
            "send messages",
            "outreach",
            "purchase",
            "pay creators",
            "launch ads",
            "发布",
            "发帖",
            "发送邮件",
            "发送消息",
            "外联",
            "购买",
            "付款",
            "投放广告",
        ],
    ) {
        return Gm01NaturalLanguageMatch::Blocked(Gm01NaturalLanguageBlock::ExternalWriteRequested);
    }
    Gm01NaturalLanguageMatch::Ready(Gm01NaturalLanguageContract { goal: goal.into() })
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NORTH_STAR: &str = "Evaluate whether our product should enter the German market. Show useful progress while researching, produce a source-bound decision-ready evidence pack, survive Desktop/runtime restart, and let me choose Continue, Stop, or Test without losing the Mission.";

    #[test]
    fn north_star_natural_language_compiles_exact_vm07_contract() {
        let Gm01NaturalLanguageMatch::Ready(contract) = compile_gm01_natural_language(NORTH_STAR)
        else {
            panic!("the frozen GM-01 prompt must compile");
        };
        let request = contract.into_request(ProjectId::from("gm01-project"));
        assert_eq!(request.manifest_id, "VM-07");
        assert_eq!(request.mode, OperatingMode::OneOffDecision);
        assert_eq!(request.market, "DE");
        assert_eq!(request.language, "de-DE");
        assert_eq!(request.timezone, "Europe/Berlin");
        assert_eq!(request.currency, "EUR");
        assert_eq!(request.budget_minor, 0);
        assert_eq!(request.goal, NORTH_STAR);
        assert!(request.parent_mission_id.is_none());
        assert_eq!(
            request.kpis.get(GM01_KPI_ID),
            Some(&KpiContract {
                baseline: Some(Decimal::ZERO),
                target: Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            })
        );
    }

    #[test]
    fn chinese_germany_decision_is_supported_without_generic_routing_claim() {
        assert!(matches!(
            compile_gm01_natural_language(
                "评估我们的产品是否应该进入德国市场，先做只读研究并给我可审阅证据。"
            ),
            Gm01NaturalLanguageMatch::Ready(_)
        ));
        assert!(matches!(
            compile_gm01_natural_language("帮我研究新品机会"),
            Gm01NaturalLanguageMatch::NotApplicable
        ));
        assert!(matches!(
            compile_gm01_natural_language("Evaluate whether we should enter the Japanese market"),
            Gm01NaturalLanguageMatch::NotApplicable
        ));
    }

    #[test]
    fn external_write_and_conflicting_market_requests_fail_closed() {
        assert!(matches!(
            compile_gm01_natural_language(
                "Evaluate the German market and publish the campaign immediately"
            ),
            Gm01NaturalLanguageMatch::Blocked(Gm01NaturalLanguageBlock::ExternalWriteRequested)
        ));
        assert!(matches!(
            compile_gm01_natural_language(
                "Evaluate whether we should enter Germany and the Japanese market"
            ),
            Gm01NaturalLanguageMatch::Blocked(Gm01NaturalLanguageBlock::ConflictingTargetMarket)
        ));
    }

    #[test]
    fn debug_redacts_the_user_goal_and_preserves_authority_boundary() {
        let Gm01NaturalLanguageMatch::Ready(contract) = compile_gm01_natural_language(NORTH_STAR)
        else {
            panic!("the frozen GM-01 prompt must compile");
        };
        let rendered = format!("{contract:?}");
        assert!(!rendered.contains("Evaluate whether"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("external_write_authority: false"));
    }
}
