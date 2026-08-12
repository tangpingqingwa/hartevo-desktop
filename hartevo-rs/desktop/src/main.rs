#![cfg_attr(feature = "bundle", windows_subsystem = "windows")]

use hartevo_desktop::App;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let (window_width, window_height) = visual_window_size();
    let window = dioxus::desktop::WindowBuilder::new()
        .with_title("Hartevo Desktop")
        .with_inner_size(dioxus::desktop::LogicalSize::new(
            window_width,
            window_height,
        ))
        .with_min_inner_size(dioxus::desktop::LogicalSize::new(1024.0, 768.0));

    dioxus::LaunchBuilder::new()
        .with_cfg(dioxus::desktop::Config::new().with_window(window))
        .launch(App);
}

fn visual_window_size() -> (f64, f64) {
    let default = (1366.0, 900.0);
    #[cfg(feature = "visual-fixtures")]
    {
        let Ok(viewport) = std::env::var("HARTEVO_DESKTOP_UI_VIEWPORT") else {
            return default;
        };
        let Some((width, outer_height)) = viewport.split_once('x') else {
            return default;
        };
        let (Ok(width), Ok(outer_height)) = (width.parse::<f64>(), outer_height.parse::<f64>())
        else {
            return default;
        };
        if width < 1024.0 || outer_height < 768.0 {
            return default;
        }
        (width, outer_height)
    }
    #[cfg(not(feature = "visual-fixtures"))]
    default
}
