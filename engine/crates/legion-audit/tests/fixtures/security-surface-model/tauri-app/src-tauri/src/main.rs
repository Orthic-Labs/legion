use tauri::command;

#[tauri::command]
fn read_note(path: String) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_note(path: String, body: String) -> Result<(), String> {
    std::fs::write(path, body).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![read_note, save_note])
        .run(tauri::generate_context!())
        .expect("error");
}
