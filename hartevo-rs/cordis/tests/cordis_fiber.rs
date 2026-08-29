use hartevo_cordis::{
    ActivationEpoch, FiberState, FiberUid, ProviderFingerprint, TransitionTicket,
};

#[test]
fn six_states_and_deterministic_activation_epoch_are_public() {
    let states = [
        FiberState::Pending,
        FiberState::Loading,
        FiberState::Active,
        FiberState::Failed,
        FiberState::Disposed,
        FiberState::Unloading,
    ];
    assert_eq!(states.len(), 6);

    let first = ProviderFingerprint::new("root", "tools", FiberUid::ROOT, 2);
    let second = ProviderFingerprint::new("root", "llm", FiberUid::ROOT, 4);
    let left = ActivationEpoch::new(7, [first.clone(), second.clone()]);
    let right = ActivationEpoch::new(7, [second, first]);
    assert_eq!(left, right);

    let ticket = TransitionTicket::new(11, Some(left.clone()));
    assert_eq!(ticket.serial(), 11);
    assert_eq!(ticket.target(), Some(&left));
}
