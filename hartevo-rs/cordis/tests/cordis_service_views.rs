use hartevo_cordis::{
    AssociatedAccessor, CallableService, ConfigValue, Context, CordisError, ProviderId, Service,
    ServiceCall, ServiceOptions, ServiceViewKind,
};

#[derive(Debug)]
struct Named(&'static str);

#[derive(Debug, PartialEq, Eq)]
struct InnerTrace {
    value: &'static str,
    caller_namespace: String,
    caller_origin: Option<ProviderId>,
    shadow_namespace: Option<String>,
    shadow_origin: Option<ProviderId>,
    shadow_generation: Option<u64>,
    shadow_shared_namespaces: Vec<String>,
    shadow_metadata_marker: Option<String>,
}

impl CallableService<()> for Named {
    type Output = InnerTrace;

    fn invoke(&self, call: ServiceCall<'_>, (): ()) -> Self::Output {
        InnerTrace {
            value: self.0,
            caller_namespace: call.caller().namespace().to_string(),
            caller_origin: call
                .caller()
                .origin()
                .map(hartevo_cordis::ServiceOrigin::provider_id),
            shadow_namespace: call.shadow().map(|shadow| shadow.namespace().to_string()),
            shadow_origin: call
                .shadow()
                .map(|shadow| shadow.exact_origin().provider_id()),
            shadow_generation: call
                .shadow()
                .map(|shadow| shadow.exact_origin().generation()),
            shadow_shared_namespaces: call
                .shadow()
                .map_or_else(Vec::new, |shadow| shadow.shared_namespaces().to_vec()),
            shadow_metadata_marker: call.shadow().and_then(|shadow| {
                shadow
                    .metadata()
                    .lookup("origin")
                    .and_then(ConfigValue::as_str)
                    .map(str::to_string)
            }),
        }
    }
}

#[derive(Debug)]
struct NestedCaller {
    dependency: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct NestedTrace {
    outer_caller_namespace: String,
    outer_caller_origin: Option<ProviderId>,
    outer_shadow_namespace: Option<String>,
    outer_shadow_origin: Option<ProviderId>,
    inner: InnerTrace,
}

impl CallableService<()> for NestedCaller {
    type Output = NestedTrace;

    fn invoke(&self, call: ServiceCall<'_>, (): ()) -> Self::Output {
        let outer_caller_namespace = call.caller().namespace().to_string();
        let outer_caller_origin = call
            .caller()
            .origin()
            .map(hartevo_cordis::ServiceOrigin::provider_id);
        let outer_shadow_namespace = call.shadow().map(|shadow| shadow.namespace().to_string());
        let outer_shadow_origin = call
            .shadow()
            .map(|shadow| shadow.exact_origin().provider_id());
        let inner = call
            .service::<Named>(self.dependency)
            .expect("test fixture must provide nested service")
            .call(());
        NestedTrace {
            outer_caller_namespace,
            outer_caller_origin,
            outer_shadow_namespace,
            outer_shadow_origin,
            inner,
        }
    }
}

#[test]
fn caller_shadow_and_nested_callable_views_have_exact_provenance() {
    let mut context = Context::new();
    let inner_provider = context
        .provide_service("inner", Named("inner"), ServiceOptions::shadowed())
        .unwrap();
    let outer_provider = context
        .provide_service(
            "outer",
            NestedCaller {
                dependency: "inner",
            },
            ServiceOptions::shadowed(),
        )
        .unwrap();

    let outer = context.service::<NestedCaller>("outer").unwrap();
    assert_eq!(outer.caller().kind(), ServiceViewKind::Caller);
    assert_eq!(outer.shadow().unwrap().kind(), ServiceViewKind::Shadow);
    assert!(outer.caller().origin().is_none());
    assert_eq!(
        outer.shadow().unwrap().exact_origin().provider_id(),
        outer_provider.provider_id()
    );

    let trace = outer.call(());
    assert_eq!(trace.outer_caller_namespace, "root");
    assert_eq!(trace.outer_caller_origin, None);
    assert_eq!(trace.outer_shadow_namespace.as_deref(), Some("root"));
    assert_eq!(
        trace.outer_shadow_origin,
        Some(outer_provider.provider_id())
    );
    assert_eq!(trace.inner.value, "inner");
    assert_eq!(trace.inner.caller_namespace, "root");
    assert_eq!(
        trace.inner.caller_origin,
        Some(outer_provider.provider_id())
    );
    assert_eq!(trace.inner.shadow_namespace.as_deref(), Some("root"));
    assert_eq!(
        trace.inner.shadow_origin,
        Some(inner_provider.provider_id())
    );
    assert_eq!(trace.inner.shadow_generation, Some(0));
}

#[test]
fn outer_and_nested_no_shadow_rules_are_independent_and_survive_replacement() {
    let mut context = Context::new();
    let nested_provider = context
        .provide_service("probe", Named("v1"), ServiceOptions::no_shadow())
        .unwrap();
    context
        .provide_service(
            "shadowed-outer",
            NestedCaller {
                dependency: "probe",
            },
            ServiceOptions::shadowed(),
        )
        .unwrap();
    context
        .provide_service(
            "no-shadow-outer",
            NestedCaller {
                dependency: "probe",
            },
            ServiceOptions::no_shadow(),
        )
        .unwrap();

    let shadowed = context
        .service::<NestedCaller>("shadowed-outer")
        .unwrap()
        .call(());
    assert!(shadowed.outer_shadow_origin.is_some());
    assert!(shadowed.inner.caller_origin.is_some());
    assert_eq!(shadowed.inner.shadow_origin, None);

    let no_shadow = context
        .service::<NestedCaller>("no-shadow-outer")
        .unwrap()
        .call(());
    assert_eq!(no_shadow.outer_shadow_origin, None);
    assert_eq!(no_shadow.inner.caller_origin, None);
    assert_eq!(no_shadow.inner.shadow_origin, None);

    let replacement = context
        .replace_provider(&nested_provider, Named("v2"))
        .unwrap();
    let probe = context.service::<Named>("probe").unwrap();
    assert!(probe.shadow().is_none());
    assert_eq!(probe.call(()).value, "v2");
    assert_eq!(replacement.generation(), 1);
}

#[test]
fn nested_lookup_keeps_isolated_current_before_explicit_shared_root() {
    let mut context = Context::new();
    context
        .provide_service(
            "shadowed-outer",
            NestedCaller {
                dependency: "inner",
            },
            ServiceOptions::shadowed(),
        )
        .unwrap();
    context
        .provide_service(
            "no-shadow-outer",
            NestedCaller {
                dependency: "inner",
            },
            ServiceOptions::no_shadow(),
        )
        .unwrap();
    context
        .provide_service("inner", Named("root"), ServiceOptions::shadowed())
        .unwrap();

    let root = context.root();
    {
        let mut isolated = context
            .with_fiber(&root)
            .isolate("tenant")
            .share_label("root")
            .extend(ConfigValue::object([(
                "origin",
                "isolated-provider".into(),
            )]));
        isolated
            .provide_service("inner", Named("isolated"), ServiceOptions::shadowed())
            .unwrap();
    }

    {
        let isolated = context.with_fiber(&root).isolate("tenant");
        assert!(isolated.service::<NestedCaller>("shadowed-outer").is_none());
    }

    let isolated = context
        .with_fiber(&root)
        .isolate("tenant")
        .share_label("root");
    let shadowed = isolated
        .service::<NestedCaller>("shadowed-outer")
        .unwrap()
        .call(());
    assert_eq!(shadowed.outer_caller_namespace, "root::tenant");
    assert_eq!(shadowed.outer_shadow_namespace.as_deref(), Some("root"));
    assert_eq!(shadowed.inner.value, "isolated");
    assert_eq!(
        shadowed.inner.shadow_namespace.as_deref(),
        Some("root::tenant")
    );
    assert_eq!(shadowed.inner.shadow_shared_namespaces, ["root"]);
    assert_eq!(
        shadowed.inner.shadow_metadata_marker.as_deref(),
        Some("isolated-provider")
    );

    let no_shadow = isolated
        .service::<NestedCaller>("no-shadow-outer")
        .unwrap()
        .call(());
    assert_eq!(no_shadow.outer_shadow_namespace, None);
    assert_eq!(no_shadow.inner.value, "isolated");
    assert_eq!(no_shadow.inner.caller_namespace, "root::tenant");
}

#[derive(Debug)]
struct Parent;

#[derive(Debug)]
struct Child(u32);

#[derive(Debug)]
struct Receiver {
    value: i32,
}

#[test]
fn associated_services_and_accessors_are_removed_with_their_owner_fiber() {
    let mut context = Context::new();
    context
        .provide_service("parent", Parent, ServiceOptions::shadowed())
        .unwrap();
    let child_fiber = context.new_fiber().unwrap();
    {
        let mut child = context.with_fiber(&child_fiber);
        child
            .provide_associated("parent", "child", Child(7))
            .unwrap();
        child
            .provide_associated(
                "parent",
                "value",
                AssociatedAccessor::read_write(
                    |receiver: &Receiver| receiver.value,
                    |receiver: &mut Receiver, value| receiver.value = value + 1,
                ),
            )
            .unwrap();
        child
            .provide_associated(
                "parent",
                "readonly",
                AssociatedAccessor::read_only(|receiver: &Receiver| receiver.value),
            )
            .unwrap();
    }

    {
        let parent = context.service::<Parent>("parent").unwrap();
        assert_eq!(
            parent
                .association()
                .service::<Child>("child")
                .unwrap()
                .value()
                .0,
            7
        );
        let mut receiver = Receiver { value: 2 };
        let accessor = parent
            .association()
            .accessor::<Receiver, i32>("value")
            .unwrap();
        assert_eq!(accessor.get(&receiver), 2);
        accessor.set(&mut receiver, 40).unwrap();
        assert_eq!(accessor.get(&receiver), 41);
        let readonly = parent
            .association()
            .accessor::<Receiver, i32>("readonly")
            .unwrap();
        assert_eq!(
            readonly.set(&mut receiver, 0).unwrap_err(),
            CordisError::ReadOnlyAssociatedAccessor {
                key: "parent.readonly".to_string()
            }
        );
    }

    assert!(context.dispose_fiber(&child_fiber).unwrap());
    let parent = context.service::<Parent>("parent").unwrap();
    assert!(parent.association().service::<Child>("child").is_none());
    assert!(
        parent
            .association()
            .accessor::<Receiver, i32>("value")
            .is_none()
    );
}

#[test]
fn service_provider_replacement_remains_bound_to_the_registering_fiber() {
    let mut context = Context::new();
    let child_fiber = context.new_fiber().unwrap();
    let provider = {
        let mut child = context.with_fiber(&child_fiber);
        child
            .provide_service("owned", Named("v1"), ServiceOptions::shadowed())
            .unwrap()
    };
    assert_eq!(provider.owner_uid(), child_fiber.uid());
    assert_eq!(
        context
            .replace_provider(&provider, Named("forbidden"))
            .unwrap_err(),
        CordisError::ProviderOwnerMismatch {
            key: "owned".to_string()
        }
    );

    let replacement = {
        let mut child = context.with_fiber(&child_fiber);
        child.replace_provider(&provider, Named("v2")).unwrap()
    };
    let service = context.service::<Named>("owned").unwrap();
    assert_eq!(service.value().0, "v2");
    let origin = service.shadow().unwrap().exact_origin();
    assert_eq!(origin.fiber_uid(), child_fiber.uid());
    assert_eq!(origin.provider_id(), provider.provider_id());
    assert_eq!(origin.generation(), replacement.generation());
}

#[test]
fn config_layers_merge_in_declared_interception_order() {
    let mut context = Context::new();
    context
        .provide_service("configurable", Named("config"), ServiceOptions::shadowed())
        .unwrap();
    let root = context.root();
    let view = context
        .with_fiber(&root)
        .intercept(
            "configurable",
            ConfigValue::object([("winner", "first".into()), ("first", true.into())]),
        )
        .intercept("other", ConfigValue::object([("ignored", true.into())]))
        .intercept(
            "configurable",
            ConfigValue::object([("winner", "second".into()), ("second", true.into())]),
        );
    let service = view.service::<Named>("configurable").unwrap();
    let base = ConfigValue::object([("winner", "base".into()), ("base", true.into())]);
    let head = ConfigValue::object([("winner", "head".into()), ("head", true.into())]);
    assert_eq!(
        service.resolve_config(Some(&base), Some(&head)),
        ConfigValue::object([
            ("base", true.into()),
            ("first", true.into()),
            ("head", true.into()),
            ("second", true.into()),
            ("winner", "head".into()),
        ])
    );
    assert_eq!(
        service.resolve_config_with(Some(&base), Some(&head), |layers| {
            ConfigValue::Array(layers.to_vec())
        }),
        ConfigValue::Array(vec![
            base,
            ConfigValue::object([("winner", "first".into()), ("first", true.into())]),
            ConfigValue::object([("winner", "second".into()), ("second", true.into())]),
            head,
        ])
    );
}

struct LegacyService;

impl Service for LegacyService {
    fn apply(self, context: &mut Context) -> Result<(), CordisError> {
        context.provide("legacy", 42_u32).map(|_| ())
    }
}

#[test]
fn existing_typed_get_and_consuming_service_apply_remain_available() {
    let mut context = Context::new();
    context.mount(LegacyService).unwrap();
    assert_eq!(context.get::<u32>("legacy").as_deref(), Some(&42));
    assert_eq!(context.service::<u32>("legacy").unwrap().value(), &42);
}
