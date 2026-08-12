#![cfg_attr(feature = "bundle", windows_subsystem = "windows")]

use hartevo_desktop::App;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();
    dioxus::launch(App);
}
