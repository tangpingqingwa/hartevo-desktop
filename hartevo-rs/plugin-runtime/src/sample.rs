//! A small first-party-style plugin used by examples and adversarial tests.

use crate::{
    CompatibilityPolicy, ConsumerDefinition, Digest, EventContribution, EventKind, MissionId,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProjectId, ProviderCardinality, ProviderDefinition, ServiceDefinition, ServiceId, UiSurfaceId,
};

#[derive(Debug)]
pub struct SampleReadOnlyPlugin;

impl SampleReadOnlyPlugin {
    pub const PLUGIN_ID: &'static str = "sample.readonly";

    pub fn definition(
        scope: PluginScope,
        version: PluginVersion,
    ) -> Result<PluginDefinition, PluginError> {
        let service_id = ServiceId::new("sample.read")?;
        let service = ServiceDefinition::read_only(
            service_id.clone(),
            PluginVersion::new(1, 0, 0),
            Digest::from_text("sample.read.contract.v1"),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?;
        let provider = ProviderDefinition::new(
            crate::ProviderId::new("sample.read.provider")?,
            service_id.clone(),
            PluginVersion::new(1, 1, 0),
            Digest::from_text("sample.read.provider.implementation.v1"),
        )?;
        let consumer = ConsumerDefinition::tool(
            crate::ConsumerId::new("sample.read.tool")?,
            service_id,
            PluginVersion::new(1, 0, 0),
            Digest::from_text("sample.read.tool.descriptor.v1"),
        )?;
        let event = EventContribution::new(
            crate::EventId::new("sample.read.event")?,
            EventKind::Conversation,
            Digest::from_text("sample.read.event.descriptor.v1"),
        )?;
        let conversation = crate::UiSurfaceContribution::conversation_node(
            UiSurfaceId::new("sample.read.conversation")?,
            Digest::from_text("sample.read.conversation.descriptor.v1"),
        )?;
        let result = crate::UiSurfaceContribution::result_surface(
            UiSurfaceId::new("sample.read.result")?,
            Digest::from_text("sample.read.result.descriptor.v1"),
        )?;
        PluginDefinition::new(
            PluginId::new(Self::PLUGIN_ID)?,
            version,
            scope,
            PluginContributions {
                services: vec![service],
                providers: vec![provider],
                consumers: vec![consumer],
                events: vec![event],
                ui_surfaces: vec![conversation, result],
            },
        )
    }

    pub fn default_scope() -> Result<PluginScope, PluginError> {
        PluginScope::new(
            ProjectId::new("project.sample")?,
            MissionId::new("mission.sample")?,
            1,
        )
    }
}
