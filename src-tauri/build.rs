use std::process::Command;
use std::path::Path;

fn main() {
  let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
  let manifest_path = Path::new(&manifest_dir);
  
  let importance_path = manifest_path.join("assets/port_classifier_importance.onnx");
  let safety_path = manifest_path.join("assets/port_classifier_safety.onnx");
  let train_script = manifest_path.parent().unwrap().join("train_model.py");

  // Generate the ONNX files dynamically before compiling
  if !importance_path.exists() || !safety_path.exists() {
    println!("cargo:warning=ONNX models not found. Running train_model.py...");
    let output = Command::new("python")
      .arg(train_script)
      .output();
    
    match output {
      Ok(out) if out.status.success() => {
        println!("cargo:warning=Successfully generated port classifier models!");
      }
      Ok(out) => {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        std::fs::write(
          manifest_path.join("python_error.log"), 
          format!("Exit Code: {:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}", out.status.code(), stdout, stderr)
        ).ok();
        println!("cargo:warning=train_model.py failed with exit code: {:?}", out.status.code());
      }
      Err(e) => {
        println!("cargo:warning=Failed to execute python command: {:?}", e);
      }
    }
  }

  tauri_build::build()
}
