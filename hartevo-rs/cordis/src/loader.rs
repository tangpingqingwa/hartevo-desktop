//! Primer loader + environment overlay.
//!
//! An overlay *selects* plugins. `disabled` interpolates from the loader
//! context. Plugin `config` interpolates from the plugin context only after
//! `inject` is satisfied. Load order follows remaining inject keys, not a
//! hardcoded crate boot list.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::{ConfigValue, InterpolateError, coerce_disabled};
use crate::context::{Context, CordisError};
use crate::effect::{IntoLifecycleEffect, LifecycleEffect};

/// Conversion boundary for legacy unit-returning loader callbacks.
pub trait IntoPluginResult {
    fn into_plugin_result(self) -> Result<(), CordisError>;
}

impl IntoPluginResult for () {
    fn into_plugin_result(self) -> Result<(), CordisError> {
        Ok(())
    }
}

impl IntoPluginResult for Result<(), CordisError> {
    fn into_plugin_result(self) -> Result<(), CordisError> {
        self
    }
}

type StartFn =
    Arc<dyn Fn(ConfigValue, &mut Context) -> Result<LifecycleEffect, CordisError> + Send + Sync>;

static NEXT_FACTORY_ID: AtomicU64 = AtomicU64::new(1);

/// Opaque repeatable plugin-factory identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PluginFactoryId(u64);

impl fmt::Debug for PluginFactoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PluginFactoryId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for PluginFactoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Cloneable callback plus metadata for pending activation.
#[derive(Clone)]
pub struct PluginFactory {
    id: PluginFactoryId,
    plugin_id: PluginId,
    start: StartFn,
    inject: Vec<String>,
    config: ConfigValue,
}

impl fmt::Debug for PluginFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginFactory")
            .field("id", &self.id)
            .field("plugin_id", &self.plugin_id)
            .field("inject", &self.inject)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PluginFactory {
    pub fn new<F, R>(id: impl Into<PluginId>, start: F) -> Self
    where
        F: Fn(ConfigValue, &mut Context) -> R + Send + Sync + 'static,
        R: IntoLifecycleEffect + 'static,
    {
        let plugin_id: PluginId = id.into();
        let start: StartFn =
            Arc::new(move |config, ctx| start(config, ctx).into_lifecycle_effect());
        Self {
            id: PluginFactoryId(NEXT_FACTORY_ID.fetch_add(1, Ordering::Relaxed)),
            plugin_id,
            start,
            inject: Vec::new(),
            config: ConfigValue::default(),
        }
    }

    #[must_use]
    pub fn with_inject<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inject = keys.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_config(mut self, config: ConfigValue) -> Self {
        self.config = config;
        self
    }

    #[must_use]
    pub const fn id(&self) -> PluginFactoryId {
        self.id
    }

    /// Stable loader/catalog identity. This never substitutes for opaque
    /// callback identity when selecting a shared runtime.
    #[must_use]
    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    #[must_use]
    pub fn inject(&self) -> &[String] {
        &self.inject
    }

    #[must_use]
    pub fn config(&self) -> ConfigValue {
        self.config.clone()
    }

    pub(crate) fn start(&self, config: ConfigValue, ctx: &mut Context) -> Result<(), CordisError> {
        match self.start_effect(config, ctx)? {
            LifecycleEffect::None => Ok(()),
            LifecycleEffect::Disposer(_)
            | LifecycleEffect::DisposerCollection(_)
            | LifecycleEffect::DisposerFuture(_)
            | LifecycleEffect::DisposerStream(_) => Err(CordisError::AsyncEffectRequiresFiber),
        }
    }

    pub(crate) fn start_effect(
        &self,
        config: ConfigValue,
        ctx: &mut Context,
    ) -> Result<LifecycleEffect, CordisError> {
        (self.start)(config, ctx)
    }
}

/// Plugin identity selected by an overlay, independent of crate boot order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginId(String);

impl PluginId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for PluginId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for PluginId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One plugin row before environment overlay and interpolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginEntry {
    pub id: PluginId,
    pub inject: Vec<String>,
    pub disabled: Option<ConfigValue>,
    pub config: ConfigValue,
}

impl PluginEntry {
    #[must_use]
    pub fn new(id: impl Into<PluginId>) -> Self {
        Self {
            id: id.into(),
            inject: Vec::new(),
            disabled: None,
            config: ConfigValue::default(),
        }
    }

    #[must_use]
    pub fn with_inject<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inject = keys.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_disabled(mut self, disabled: impl Into<ConfigValue>) -> Self {
        self.disabled = Some(disabled.into());
        self
    }

    #[must_use]
    pub fn with_config(mut self, config: ConfigValue) -> Self {
        self.config = config;
        self
    }
}

/// Environment overlay that selects plugins rather than booting crates.
///
/// With no layers, the catalog is selected as-is. Later layers win: they can
/// re-enable, replace metadata, drop, or restrict the set with
/// [`OverlayAction::Only`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentOverlay {
    pub name: String,
    layers: Vec<OverlayLayer>,
}

impl EnvironmentOverlay {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            layers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_layer(mut self, layer: OverlayLayer) -> Self {
        self.layers.push(layer);
        self
    }

    #[must_use]
    pub fn layers(&self) -> &[OverlayLayer] {
        &self.layers
    }

    /// Apply overlay layers onto a catalog. Unselected plugins are omitted.
    ///
    /// No layers keeps the catalog as-is. Any layer starts from an empty
    /// selection: `enable` / `replace` add, `disable` drops, `only` replaces
    /// the set. This is a selection filter, not a crate boot sequence.
    #[must_use]
    pub fn select(&self, catalog: &[PluginEntry]) -> Vec<PluginEntry> {
        let mut known: BTreeMap<String, PluginEntry> = BTreeMap::new();
        for entry in catalog {
            known.insert(entry.id.as_str().to_string(), entry.clone());
        }
        if self.layers.is_empty() {
            return catalog.to_vec();
        }

        let mut selected: Vec<PluginEntry> = Vec::new();
        for layer in &self.layers {
            for action in &layer.actions {
                match action {
                    OverlayAction::Enable(id) => {
                        if let Some(entry) = known.get(id.as_str()) {
                            upsert_selected(&mut selected, entry.clone());
                        }
                    }
                    OverlayAction::Replace(entry) => {
                        known.insert(entry.id.as_str().to_string(), entry.clone());
                        upsert_selected(&mut selected, entry.clone());
                    }
                    OverlayAction::Disable(id) => {
                        selected.retain(|entry| entry.id.as_str() != id.as_str());
                    }
                    OverlayAction::Only(ids) => {
                        let mut next = Vec::new();
                        for id in ids {
                            if let Some(entry) = known.get(id.as_str()) {
                                next.push(entry.clone());
                            }
                        }
                        selected = next;
                    }
                }
            }
        }

        selected
    }
}

fn upsert_selected(selected: &mut Vec<PluginEntry>, entry: PluginEntry) {
    if let Some(existing) = selected
        .iter_mut()
        .find(|candidate| candidate.id.as_str() == entry.id.as_str())
    {
        *existing = entry;
    } else {
        selected.push(entry);
    }
}

/// Named overlay layer (base, env, local, …). Later layers override earlier ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayLayer {
    pub name: String,
    pub actions: Vec<OverlayAction>,
}

impl OverlayLayer {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            actions: Vec::new(),
        }
    }

    #[must_use]
    pub fn enable(mut self, id: impl Into<PluginId>) -> Self {
        self.actions.push(OverlayAction::Enable(id.into()));
        self
    }

    #[must_use]
    pub fn replace(mut self, entry: PluginEntry) -> Self {
        self.actions.push(OverlayAction::Replace(entry));
        self
    }

    #[must_use]
    pub fn disable(mut self, id: impl Into<PluginId>) -> Self {
        self.actions.push(OverlayAction::Disable(id.into()));
        self
    }

    #[must_use]
    pub fn only<I, P>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PluginId>,
    {
        self.actions.push(OverlayAction::Only(
            ids.into_iter().map(Into::into).collect(),
        ));
        self
    }
}

/// One overlay mutation against the selected plugin set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayAction {
    Enable(PluginId),
    Replace(PluginEntry),
    Disable(PluginId),
    Only(Vec<PluginId>),
}

/// Loader-owned interpolation source. `disabled` reads from here, never from
/// the plugin context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderContext {
    values: ConfigValue,
}

impl LoaderContext {
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: ConfigValue::default(),
        }
    }

    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<ConfigValue>) -> Self {
        self.insert(key, value);
        self
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<ConfigValue>) {
        match &mut self.values {
            ConfigValue::Object(map) => {
                map.insert(key.into(), value.into());
            }
            other => *other = ConfigValue::object([(key.into(), value.into())]),
        }
    }

    #[must_use]
    pub fn values(&self) -> &ConfigValue {
        &self.values
    }

    /// Interpolate `disabled` from the loader context only.
    pub fn interpolate_disabled(
        &self,
        disabled: Option<&ConfigValue>,
    ) -> Result<bool, InterpolateError> {
        let Some(expr) = disabled else {
            return Ok(false);
        };
        coerce_disabled(&expr.interpolate(&self.values)?)
    }
}

impl Default for LoaderContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolved plugin after overlay selection and loader-context `disabled`.
///
/// `config` is still the raw template. Plugin-context interpolation happens
/// later, after inject, inside [`load_plugins`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPlugin {
    pub id: PluginId,
    pub inject: Vec<String>,
    pub disabled: bool,
    pub config: ConfigValue,
}

impl ResolvedPlugin {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.disabled
    }
}

/// Primer loader: overlay selects plugins, then interpolates `disabled` from
/// the loader context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loader {
    catalog: Vec<PluginEntry>,
    overlay: EnvironmentOverlay,
    context: LoaderContext,
}

impl Loader {
    #[must_use]
    pub fn new(overlay: EnvironmentOverlay, context: LoaderContext) -> Self {
        Self {
            catalog: Vec::new(),
            overlay,
            context,
        }
    }

    #[must_use]
    pub fn with_catalog(mut self, catalog: Vec<PluginEntry>) -> Self {
        self.catalog = catalog;
        self
    }

    #[must_use]
    pub fn overlay(&self) -> &EnvironmentOverlay {
        &self.overlay
    }

    #[must_use]
    pub fn loader_context(&self) -> &LoaderContext {
        &self.context
    }

    /// Select via overlay, interpolate `disabled` from the loader context.
    pub fn resolve(&self) -> Result<Vec<ResolvedPlugin>, InterpolateError> {
        self.overlay
            .select(&self.catalog)
            .into_iter()
            .map(|entry| {
                Ok(ResolvedPlugin {
                    id: entry.id,
                    inject: entry.inject,
                    disabled: self.context.interpolate_disabled(entry.disabled.as_ref())?,
                    config: entry.config,
                })
            })
            .collect()
    }

    /// Enabled plugins only, still with raw (pre-plugin-context) config.
    pub fn enabled(&self) -> Result<Vec<ResolvedPlugin>, InterpolateError> {
        Ok(self
            .resolve()?
            .into_iter()
            .filter(ResolvedPlugin::is_enabled)
            .collect())
    }
}

/// Interpolate plugin config from the plugin context **after** inject deps exist.
pub fn interpolate_plugin_config(
    ctx: &Context,
    config: &ConfigValue,
) -> Result<ConfigValue, InterpolateError> {
    config.interpolate(&ctx.plugin_interpolation_source())
}

/// A selected plugin plus the function that materializes it after interpolation.
pub struct PluginSpec {
    pub id: PluginId,
    pub inject: Vec<String>,
    pub disabled: Option<ConfigValue>,
    pub config: ConfigValue,
    factory: PluginFactory,
}

impl fmt::Debug for PluginSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginSpec")
            .field("id", &self.id)
            .field("inject", &self.inject)
            .field("disabled", &self.disabled)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PluginSpec {
    pub fn new<F, R>(id: impl Into<PluginId>, start: F) -> Self
    where
        F: Fn(ConfigValue, &mut Context) -> R + Send + Sync + 'static,
        R: IntoLifecycleEffect + 'static,
    {
        let id = id.into();
        Self {
            id: id.clone(),
            inject: Vec::new(),
            disabled: None,
            config: ConfigValue::default(),
            factory: PluginFactory::new(id, start),
        }
    }

    #[must_use]
    pub fn with_inject<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inject = keys.into_iter().map(Into::into).collect();
        self.factory = self.factory.with_inject(self.inject.clone());
        self
    }

    #[must_use]
    pub fn with_disabled(mut self, disabled: impl Into<ConfigValue>) -> Self {
        self.disabled = Some(disabled.into());
        self
    }

    #[must_use]
    pub fn with_config(mut self, config: ConfigValue) -> Self {
        self.config = config.clone();
        self.factory = self.factory.with_config(config);
        self
    }

    /// Stable identity retained by factory clones.
    #[must_use]
    pub const fn factory_id(&self) -> PluginFactoryId {
        self.factory.id()
    }

    #[must_use]
    pub fn factory(&self) -> PluginFactory {
        self.factory.clone()
    }

    #[must_use]
    pub fn entry(&self) -> PluginEntry {
        PluginEntry {
            id: self.id.clone(),
            inject: self.inject.clone(),
            disabled: self.disabled.clone(),
            config: self.config.clone(),
        }
    }
}

/// Load overlay-selected plugins into a context without a crate boot list.
///
/// 1. Overlay selects plugin entries for this environment.
/// 2. `disabled` interpolates from the **loader** context; skipped plugins never
///    start.
/// 3. Remaining plugins start when their `inject` keys exist on the **plugin**
///    context (dependency order, not catalog/crate order).
/// 4. After inject is satisfied, plugin `config` interpolates from the plugin
///    context, then `apply` runs.
pub fn load_plugins(
    ctx: &mut Context,
    loader: &LoaderContext,
    overlay: &EnvironmentOverlay,
    specs: &[PluginSpec],
) -> Result<LoadReport, CordisError> {
    let catalog: Vec<PluginEntry> = specs.iter().map(PluginSpec::entry).collect();
    let selected = overlay.select(&catalog);
    let selected_ids: BTreeSet<&str> = selected.iter().map(|entry| entry.id.as_str()).collect();
    let specs_by_id: BTreeMap<&str, &PluginSpec> =
        specs.iter().map(|spec| (spec.id.as_str(), spec)).collect();

    let mut report = LoadReport::default();
    for spec in specs {
        if !selected_ids.contains(spec.id.as_str()) {
            report.omitted.push(spec.id.clone());
        }
    }
    let mut pending: Vec<(PluginEntry, PluginFactory)> = Vec::new();

    for entry in selected {
        let Some(spec) = specs_by_id.get(entry.id.as_str()) else {
            report.skipped_unregistered.push(entry.id);
            continue;
        };
        if loader.interpolate_disabled(entry.disabled.as_ref())? {
            report.disabled.push(entry.id);
            continue;
        }
        pending.push((entry.clone(), spec.factory()));
    }

    loop {
        let mut progress = false;
        let mut still = Vec::new();
        for (entry, start) in pending {
            if entry.inject.iter().any(|key| !ctx.has(key)) {
                still.push((entry, start));
                continue;
            }
            let config = interpolate_plugin_config(ctx, &entry.config)?;
            start.start(config, ctx)?;
            report.started.push(entry.id);
            progress = true;
        }
        pending = still;
        if !progress {
            break;
        }
    }

    if !pending.is_empty() {
        let mut missing: Vec<String> = pending
            .iter()
            .flat_map(|(entry, _)| entry.inject.iter().filter(|key| !ctx.has(key)).cloned())
            .collect();
        missing.sort();
        missing.dedup();
        return Err(CordisError::MissingDependencies(missing));
    }

    Ok(report)
}

/// Load selected plugins while retaining unresolved entries as pending
/// Fiber-owned factories. Unlike [`load_plugins`], this route never converts
/// missing dependencies into a terminal error.
pub fn load_plugins_pending(
    ctx: &mut Context,
    loader: &LoaderContext,
    overlay: &EnvironmentOverlay,
    specs: &[PluginSpec],
) -> Result<LoadReport, CordisError> {
    let catalog: Vec<PluginEntry> = specs.iter().map(PluginSpec::entry).collect();
    let selected = overlay.select(&catalog);
    let selected_ids: BTreeSet<&str> = selected.iter().map(|entry| entry.id.as_str()).collect();
    let specs_by_id: BTreeMap<&str, &PluginSpec> =
        specs.iter().map(|spec| (spec.id.as_str(), spec)).collect();
    let mut report = LoadReport::default();
    for spec in specs {
        if !selected_ids.contains(spec.id.as_str()) {
            report.omitted.push(spec.id.clone());
        }
    }

    let mut handles = Vec::new();
    for entry in selected {
        let Some(spec) = specs_by_id.get(entry.id.as_str()) else {
            report.skipped_unregistered.push(entry.id);
            continue;
        };
        if loader.interpolate_disabled(entry.disabled.as_ref())? {
            report.disabled.push(entry.id);
            continue;
        }
        let factory = spec
            .factory()
            .with_inject(entry.inject.clone())
            .with_config(entry.config.clone());
        let handle = ctx.mount_pending(factory)?;
        handles.push((entry.id, handle));
    }
    for (id, handle) in handles {
        if handle.is_pending() {
            report.pending.push(id);
        } else if handle.is_active() {
            report.started.push(id);
        }
    }
    Ok(report)
}

/// Outcome of one loader pass.
///
/// Overlay omission (`omitted`) is not the same as interpolated `disabled`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    pub started: Vec<PluginId>,
    pub disabled: Vec<PluginId>,
    pub omitted: Vec<PluginId>,
    pub skipped_unregistered: Vec<PluginId>,
    /// Factories retained by `load_plugins_pending` because inject keys are
    /// not ready yet. `load_plugins` intentionally leaves this empty.
    pub pending: Vec<PluginId>,
}
