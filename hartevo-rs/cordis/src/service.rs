//! Explicit Rust service views.
//!
//! Upstream Cordis uses JavaScript proxies to keep the caller context apart
//! from the context in which a service was created. Rust makes that boundary
//! explicit: [`ServiceHandle`] carries separately typed caller and shadow
//! views, and callable services opt into [`CallableService`].

use std::any::Any;
use std::fmt;
use std::sync::Arc;

use crate::config::ConfigValue;
use crate::context::{Context, CordisError, ProviderId};
use crate::fiber::FiberUid;

/// Existing consuming plugin contract. N3 deliberately keeps this source
/// compatible while adding service handles alongside it.
pub trait Service {
    fn inject() -> &'static [&'static str] {
        &[]
    }

    fn apply(self, ctx: &mut Context) -> Result<(), CordisError>;
}

/// Tracing behavior recorded with a typed service provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceOptions {
    no_shadow: bool,
}

impl ServiceOptions {
    /// Default Cordis service behavior: calls receive the provider's origin as
    /// a shadow while preserving the lookup context separately.
    #[must_use]
    pub const fn shadowed() -> Self {
        Self { no_shadow: false }
    }

    /// Caller-traceable service which must not install a provider shadow.
    #[must_use]
    pub const fn no_shadow() -> Self {
        Self { no_shadow: true }
    }

    #[must_use]
    pub const fn is_no_shadow(self) -> bool {
        self.no_shadow
    }
}

/// Runtime role of one public service context view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceViewKind {
    Caller,
    Shadow,
}

/// Exact provider provenance carried by a service shadow and retained when
/// that shadow becomes the caller of a nested service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceOrigin {
    context_id: u64,
    fiber_uid: FiberUid,
    namespace: String,
    provider_id: ProviderId,
    generation: u64,
}

impl ServiceOrigin {
    pub(crate) fn new(
        context_id: u64,
        fiber_uid: FiberUid,
        namespace: String,
        provider_id: ProviderId,
        generation: u64,
    ) -> Self {
        Self {
            context_id,
            fiber_uid,
            namespace,
            provider_id,
            generation,
        }
    }

    #[must_use]
    pub const fn fiber_uid(&self) -> FiberUid {
        self.fiber_uid
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ServiceScope {
    context_id: u64,
    fiber_uid: FiberUid,
    namespace: String,
    shared_namespaces: Vec<String>,
    metadata: ConfigValue,
    origin: Option<ServiceOrigin>,
}

impl ServiceScope {
    pub(crate) fn new(
        context_id: u64,
        fiber_uid: FiberUid,
        namespace: String,
        shared_namespaces: Vec<String>,
        metadata: ConfigValue,
        origin: Option<ServiceOrigin>,
    ) -> Self {
        Self {
            context_id,
            fiber_uid,
            namespace,
            shared_namespaces,
            metadata,
            origin,
        }
    }

    pub(crate) fn namespaces(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.namespace.as_str())
            .chain(self.shared_namespaces.iter().map(String::as_str))
    }
}

impl fmt::Debug for ServiceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceScope")
            .field("context_id", &self.context_id)
            .field("fiber_uid", &self.fiber_uid)
            .field("namespace", &self.namespace)
            .field("shared_namespaces", &self.shared_namespaces)
            .field("metadata", &self.metadata)
            .field("origin", &self.origin)
            .finish()
    }
}

macro_rules! service_view {
    ($name:ident, $kind:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name {
            scope: ServiceScope,
        }

        impl $name {
            #[must_use]
            pub const fn kind(&self) -> ServiceViewKind {
                ServiceViewKind::$kind
            }

            #[must_use]
            pub const fn fiber_uid(&self) -> FiberUid {
                self.scope.fiber_uid
            }

            #[must_use]
            pub fn namespace(&self) -> &str {
                &self.scope.namespace
            }

            #[must_use]
            pub fn shared_namespaces(&self) -> &[String] {
                &self.scope.shared_namespaces
            }

            #[must_use]
            pub fn metadata(&self) -> &ConfigValue {
                &self.scope.metadata
            }

            #[must_use]
            pub fn origin(&self) -> Option<&ServiceOrigin> {
                self.scope.origin.as_ref()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("scope", &self.scope)
                    .finish()
            }
        }
    };
}

service_view!(
    ServiceCaller,
    Caller,
    "Context identity from which the service value was requested."
);

/// Context identity in which a shadowed service provider was registered.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceShadow {
    scope: ServiceScope,
    origin: ServiceOrigin,
}

impl ServiceShadow {
    pub(crate) fn new(mut scope: ServiceScope, origin: ServiceOrigin) -> Self {
        scope.origin = Some(origin.clone());
        Self { scope, origin }
    }

    #[must_use]
    pub const fn kind(&self) -> ServiceViewKind {
        ServiceViewKind::Shadow
    }

    #[must_use]
    pub const fn fiber_uid(&self) -> FiberUid {
        self.scope.fiber_uid
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.scope.namespace
    }

    #[must_use]
    pub fn shared_namespaces(&self) -> &[String] {
        &self.scope.shared_namespaces
    }

    #[must_use]
    pub fn metadata(&self) -> &ConfigValue {
        &self.scope.metadata
    }

    #[must_use]
    pub fn origin(&self) -> Option<&ServiceOrigin> {
        Some(&self.origin)
    }

    /// A shadow is constructed only from an exact live provider record.
    #[must_use]
    pub const fn exact_origin(&self) -> &ServiceOrigin {
        &self.origin
    }
}

impl fmt::Debug for ServiceShadow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceShadow")
            .field("scope", &self.scope)
            .field("origin", &self.origin)
            .finish()
    }
}

impl ServiceCaller {
    pub(crate) fn new(scope: ServiceScope) -> Self {
        Self { scope }
    }

    fn from_shadow(shadow: &ServiceShadow) -> Self {
        Self {
            scope: shadow.scope.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceIntercept {
    name: String,
    config: ConfigValue,
}

impl ServiceIntercept {
    pub(crate) fn new(name: String, config: ConfigValue) -> Self {
        Self { name, config }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceLookup {
    scope: ServiceScope,
    intercepts: Vec<ServiceIntercept>,
}

impl ServiceLookup {
    pub(crate) fn new(scope: ServiceScope, intercepts: Vec<ServiceIntercept>) -> Self {
        Self { scope, intercepts }
    }

    pub(crate) fn namespaces(&self) -> impl Iterator<Item = &str> {
        self.scope.namespaces()
    }

    fn config_layers(
        &self,
        name: &str,
        base: Option<&ConfigValue>,
        head: Option<&ConfigValue>,
    ) -> Vec<ConfigValue> {
        let mut layers = Vec::new();
        if let Some(base) = base {
            layers.push(base.clone());
        }
        layers.extend(
            self.intercepts
                .iter()
                .filter(|intercept| intercept.name == name)
                .map(|intercept| intercept.config.clone()),
        );
        if let Some(head) = head {
            layers.push(head.clone());
        }
        layers
    }
}

/// Typed service value plus its caller/shadow trace.
pub struct ServiceHandle<'ctx, T> {
    context: &'ctx Context,
    key: String,
    value: Arc<T>,
    lookup: ServiceLookup,
    caller: ServiceCaller,
    shadow: Option<ServiceShadow>,
}

impl<T> Clone for ServiceHandle<'_, T> {
    fn clone(&self) -> Self {
        Self {
            context: self.context,
            key: self.key.clone(),
            value: Arc::clone(&self.value),
            lookup: self.lookup.clone(),
            caller: self.caller.clone(),
            shadow: self.shadow.clone(),
        }
    }
}

impl<T> fmt::Debug for ServiceHandle<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceHandle")
            .field("key", &self.key)
            .field("caller", &self.caller)
            .field("shadow", &self.shadow)
            .finish_non_exhaustive()
    }
}

impl<'ctx, T> ServiceHandle<'ctx, T> {
    pub(crate) fn new(
        context: &'ctx Context,
        key: String,
        value: Arc<T>,
        lookup: ServiceLookup,
        caller: ServiceCaller,
        shadow: Option<ServiceShadow>,
    ) -> Self {
        Self {
            context,
            key,
            value,
            lookup,
            caller,
            shadow,
        }
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    #[must_use]
    pub fn value_arc(&self) -> Arc<T> {
        Arc::clone(&self.value)
    }

    #[must_use]
    pub fn caller(&self) -> &ServiceCaller {
        &self.caller
    }

    #[must_use]
    pub fn shadow(&self) -> Option<&ServiceShadow> {
        self.shadow.as_ref()
    }

    /// Explicit dotted-property association rooted at this service key.
    #[must_use]
    pub fn association(&self) -> ServiceAssociation<'ctx> {
        ServiceAssociation::new(
            self.context,
            self.key.clone(),
            self.lookup.clone(),
            self.caller.clone(),
        )
    }

    /// Default upstream-compatible shallow config resolution.
    #[must_use]
    pub fn resolve_config(
        &self,
        base: Option<&ConfigValue>,
        head: Option<&ConfigValue>,
    ) -> ConfigValue {
        self.resolve_config_with(base, head, merge_service_config)
    }

    /// Resolve config through a service-specific merger. The merger receives
    /// exact declared order: base, outer-to-inner intercepts, then head.
    #[must_use]
    pub fn resolve_config_with<F>(
        &self,
        base: Option<&ConfigValue>,
        head: Option<&ConfigValue>,
        merge: F,
    ) -> ConfigValue
    where
        F: FnOnce(&[ConfigValue]) -> ConfigValue,
    {
        let layers = self.lookup.config_layers(&self.key, base, head);
        merge(&layers)
    }

    /// Invoke a callable service without emulating a language-level function
    /// proxy. The call object is the only nested service tracing authority.
    pub fn call<Args>(&self, args: Args) -> T::Output
    where
        T: CallableService<Args>,
    {
        let call = ServiceCall {
            context: self.context,
            service_key: self.key.clone(),
            lookup: self.lookup.clone(),
            caller: self.caller.clone(),
            shadow: self.shadow.clone(),
        };
        self.value.invoke(call, args)
    }
}

/// Explicit callable-service contract used by [`ServiceHandle::call`].
pub trait CallableService<Args>: Send + Sync + 'static {
    type Output;

    fn invoke(&self, call: ServiceCall<'_>, args: Args) -> Self::Output;
}

/// One active service invocation and its nested lookup authority.
pub struct ServiceCall<'ctx> {
    context: &'ctx Context,
    service_key: String,
    lookup: ServiceLookup,
    caller: ServiceCaller,
    shadow: Option<ServiceShadow>,
}

impl fmt::Debug for ServiceCall<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceCall")
            .field("service_key", &self.service_key)
            .field("caller", &self.caller)
            .field("shadow", &self.shadow)
            .finish_non_exhaustive()
    }
}

impl<'ctx> ServiceCall<'ctx> {
    #[must_use]
    pub fn service_key(&self) -> &str {
        &self.service_key
    }

    #[must_use]
    pub fn caller(&self) -> &ServiceCaller {
        &self.caller
    }

    #[must_use]
    pub fn shadow(&self) -> Option<&ServiceShadow> {
        self.shadow.as_ref()
    }

    fn nested_caller(&self) -> ServiceCaller {
        self.shadow
            .as_ref()
            .map_or_else(|| self.caller.clone(), ServiceCaller::from_shadow)
    }

    /// Resolve a service from the original lookup/isolation context while
    /// using this service's origin as the nested caller identity.
    #[must_use]
    pub fn service<T>(&self, key: &str) -> Option<ServiceHandle<'ctx, T>>
    where
        T: Any + Send + Sync,
    {
        self.context
            .service_from_lookup(self.lookup.clone(), self.nested_caller(), key)
    }

    #[must_use]
    pub fn association(&self, name: impl Into<String>) -> ServiceAssociation<'ctx> {
        ServiceAssociation::new(
            self.context,
            name.into(),
            self.lookup.clone(),
            self.nested_caller(),
        )
    }

    #[must_use]
    pub fn resolve_config(
        &self,
        base: Option<&ConfigValue>,
        head: Option<&ConfigValue>,
    ) -> ConfigValue {
        merge_service_config(&self.lookup.config_layers(&self.service_key, base, head))
    }
}

/// Join an association and property without introducing namespace fallback.
#[must_use]
pub fn associated_key(association: &str, property: &str) -> String {
    format!("{association}.{property}")
}

/// Explicit resolver for dotted service and accessor properties.
pub struct ServiceAssociation<'ctx> {
    context: &'ctx Context,
    name: String,
    lookup: ServiceLookup,
    caller: ServiceCaller,
}

impl fmt::Debug for ServiceAssociation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceAssociation")
            .field("name", &self.name)
            .field("caller", &self.caller)
            .finish_non_exhaustive()
    }
}

impl<'ctx> ServiceAssociation<'ctx> {
    pub(crate) fn new(
        context: &'ctx Context,
        name: String,
        lookup: ServiceLookup,
        caller: ServiceCaller,
    ) -> Self {
        Self {
            context,
            name,
            lookup,
            caller,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn service<T>(&self, property: &str) -> Option<ServiceHandle<'ctx, T>>
    where
        T: Any + Send + Sync,
    {
        self.context.service_from_lookup(
            self.lookup.clone(),
            self.caller.clone(),
            &associated_key(&self.name, property),
        )
    }

    #[must_use]
    pub fn accessor<R, V>(&self, property: &str) -> Option<AssociatedAccessorHandle<'ctx, R, V>>
    where
        R: 'static,
        V: 'static,
    {
        let key = associated_key(&self.name, property);
        let handle = self
            .context
            .service_from_lookup::<AssociatedAccessor<R, V>>(
                self.lookup.clone(),
                self.caller.clone(),
                &key,
            )?;
        Some(AssociatedAccessorHandle {
            context: self.context,
            key,
            accessor: handle.value_arc(),
        })
    }
}

type AccessorGetter<R, V> = dyn Fn(&R) -> V + Send + Sync + 'static;
type AccessorSetter<R, V> = dyn Fn(&mut R, V) + Send + Sync + 'static;

/// Typed associated property implementation. The receiver is explicit, so no
/// proxy or hidden mutable alias is required.
pub struct AssociatedAccessor<R, V> {
    getter: Arc<AccessorGetter<R, V>>,
    setter: Option<Arc<AccessorSetter<R, V>>>,
}

impl<R, V> AssociatedAccessor<R, V> {
    #[must_use]
    pub fn read_only<G>(getter: G) -> Self
    where
        G: Fn(&R) -> V + Send + Sync + 'static,
    {
        Self {
            getter: Arc::new(getter),
            setter: None,
        }
    }

    #[must_use]
    pub fn read_write<G, S>(getter: G, setter: S) -> Self
    where
        G: Fn(&R) -> V + Send + Sync + 'static,
        S: Fn(&mut R, V) + Send + Sync + 'static,
    {
        Self {
            getter: Arc::new(getter),
            setter: Some(Arc::new(setter)),
        }
    }
}

impl<R, V> fmt::Debug for AssociatedAccessor<R, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssociatedAccessor")
            .field("writable", &self.setter.is_some())
            .finish_non_exhaustive()
    }
}

/// Resolved associated accessor retaining both the provider implementation and
/// its immutable Context borrow. It cannot cross an owner mutation.
///
/// ```compile_fail
/// use hartevo_cordis::{AssociatedAccessor, Context};
///
/// let mut context = Context::new();
/// let child = context.new_fiber().unwrap();
/// {
///     let mut view = context.with_fiber(&child);
///     view.provide_associated(
///         "session",
///         "value",
///         AssociatedAccessor::read_only(|value: &u32| *value),
///     ).unwrap();
/// }
/// let accessor = context
///     .association("session")
///     .unwrap()
///     .accessor::<u32, u32>("value")
///     .unwrap();
/// context.dispose_fiber(&child).unwrap();
/// let _ = accessor.get(&1);
/// ```
pub struct AssociatedAccessorHandle<'ctx, R, V> {
    context: &'ctx Context,
    key: String,
    accessor: Arc<AssociatedAccessor<R, V>>,
}

impl<R, V> Clone for AssociatedAccessorHandle<'_, R, V> {
    fn clone(&self) -> Self {
        Self {
            context: self.context,
            key: self.key.clone(),
            accessor: Arc::clone(&self.accessor),
        }
    }
}

impl<R, V> fmt::Debug for AssociatedAccessorHandle<'_, R, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssociatedAccessorHandle")
            .field("key", &self.key)
            .field("writable", &self.accessor.setter.is_some())
            .finish()
    }
}

impl<R, V> AssociatedAccessorHandle<'_, R, V> {
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.accessor.setter.is_some()
    }

    pub fn get(&self, receiver: &R) -> V {
        (self.accessor.getter)(receiver)
    }

    pub fn set(&self, receiver: &mut R, value: V) -> Result<(), CordisError> {
        let Some(setter) = &self.accessor.setter else {
            return Err(CordisError::ReadOnlyAssociatedAccessor {
                key: self.key.clone(),
            });
        };
        setter(receiver, value);
        Ok(())
    }
}

/// Shallow object merge matching Cordis' default `Object.assign` ordering.
#[must_use]
pub fn merge_service_config(layers: &[ConfigValue]) -> ConfigValue {
    let mut merged = ConfigValue::default();
    for layer in layers {
        match layer {
            ConfigValue::Object(entries) => match &mut merged {
                ConfigValue::Object(current) => current.extend(entries.clone()),
                current => *current = ConfigValue::Object(entries.clone()),
            },
            other => merged = other.clone(),
        }
    }
    merged
}
