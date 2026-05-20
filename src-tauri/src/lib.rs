// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use std::collections::HashMap;
use std::process::Command;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct PortInfo {
    port: u16,
    pid: u32,
    process_name: String,
    protocol: String,
    user: String,
}

#[tauri::command]
async fn get_active_ports() -> Result<Vec<PortInfo>, String> {
    #[cfg(target_os = "windows")]
    {
        get_active_ports_windows().await
    }
    #[cfg(not(target_os = "windows"))]
    {
        get_active_ports_unix().await
    }
}

#[cfg(target_os = "windows")]
async fn get_active_ports_windows() -> Result<Vec<PortInfo>, String> {
    // 1. Get process names using tasklist
    let mut pid_to_name = HashMap::new();
    let tasklist_output = Command::new("tasklist")
        .args(&["/FO", "CSV", "/NH"])
        .output()
        .map_err(|e| format!("Failed to execute tasklist: {}", e))?;
    
    let tasklist_stdout = String::from_utf8_lossy(&tasklist_output.stdout);
    for line in tasklist_stdout.lines() {
        let parts: Vec<&str> = line.split("\",\"").collect();
        if parts.len() >= 2 {
            let name = parts[0].trim_matches('"').to_string();
            let pid_str = parts[1].trim_matches('"');
            if let Ok(pid) = pid_str.parse::<u32>() {
                pid_to_name.insert(pid, name);
            }
        }
    }

    // 2. Get active ports using netstat -ano
    let netstat_output = Command::new("netstat")
        .arg("-ano")
        .output()
        .map_err(|e| format!("Failed to execute netstat: {}", e))?;

    let netstat_stdout = String::from_utf8_lossy(&netstat_output.stdout);
    let mut ports = Vec::new();

    for line in netstat_stdout.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let proto = tokens[0].to_uppercase();
        if proto == "TCP" {
            // TCP line: Proto LocalAddress ForeignAddress State PID
            if tokens.len() >= 5 {
                let state = tokens[3].to_uppercase();
                if state == "LISTENING" {
                    let local_addr = tokens[1];
                    let pid_str = tokens[4];
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        if let Some(port) = parse_windows_port(local_addr) {
                            let process_name = pid_to_name.get(&pid).cloned().unwrap_or_else(|| "Unknown".to_string());
                            ports.push(PortInfo {
                                port,
                                pid,
                                process_name,
                                protocol: "TCP".to_string(),
                                user: "N/A".to_string(),
                            });
                        }
                    }
                }
            }
        } else if proto == "UDP" {
            // UDP line: Proto LocalAddress ForeignAddress PID
            // Note: UDP doesn't have a State column
            if tokens.len() >= 4 {
                let local_addr = tokens[1];
                let pid_str = tokens[3];
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Some(port) = parse_windows_port(local_addr) {
                        let process_name = pid_to_name.get(&pid).cloned().unwrap_or_else(|| "Unknown".to_string());
                        ports.push(PortInfo {
                            port,
                            pid,
                            process_name,
                            protocol: "UDP".to_string(),
                            user: "N/A".to_string(),
                        });
                    }
                }
            }
        }
    }

    // Deduplicate port list (sometimes multiple listener entries exist for IPv4/IPv6)
    ports.sort_by_key(|p| (p.port, p.pid, p.protocol.clone()));
    ports.dedup_by(|a, b| a.port == b.port && a.pid == b.pid && a.protocol == b.protocol);

    Ok(ports)
}

#[cfg(target_os = "windows")]
fn parse_windows_port(addr: &str) -> Option<u16> {
    // Address can be like: 0.0.0.0:80, [::]:80, 127.0.0.1:5000, etc.
    let parts: Vec<&str> = addr.split(':').collect();
    if let Some(last) = parts.last() {
        if let Ok(port) = last.parse::<u16>() {
            return Some(port);
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
async fn get_active_ports_unix() -> Result<Vec<PortInfo>, String> {
    // macOS / Linux: lsof -i -P -n
    let lsof_output = Command::new("lsof")
        .args(&["-i", "-P", "-n"])
        .output()
        .map_err(|e| format!("Failed to execute lsof: {}", e))?;

    let lsof_stdout = String::from_utf8_lossy(&lsof_output.stdout);
    let mut ports = Vec::new();

    for line in lsof_stdout.lines() {
        if !line.contains("(LISTEN)") && !line.contains("LISTEN") {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        // Column indices:
        // 0: COMMAND (process_name)
        // 1: PID
        // 2: USER
        // 3: FD
        // 4: TYPE (IPv4/IPv6)
        // 5: DEVICE
        // 6: SIZE/OFF
        // 7: NODE (TCP/UDP)
        // 8: NAME (e.g. *:3000, 127.0.0.1:3000)
        if tokens.len() >= 9 {
            let process_name = tokens[0].to_string();
            let pid_str = tokens[1];
            let user = tokens[2].to_string();
            let protocol = tokens[7].to_string(); // TCP or UDP
            let name = tokens[8];

            if let Ok(pid) = pid_str.parse::<u32>() {
                if let Some(port) = parse_unix_port(name) {
                    ports.push(PortInfo {
                        port,
                        pid,
                        process_name,
                        protocol,
                        user,
                    });
                }
            }
        }
    }

    // Deduplicate
    ports.sort_by_key(|p| (p.port, p.pid, p.protocol.clone()));
    ports.dedup_by(|a, b| a.port == b.port && a.pid == b.pid && a.protocol == b.protocol);

    Ok(ports)
}

#[cfg(not(target_os = "windows"))]
fn parse_unix_port(name: &str) -> Option<u16> {
    // Address name can be like: *:3000 (LISTEN) or 127.0.0.1:3000 or [::1]:3000 or *:3000
    // Strip "(LISTEN)" first if present
    let addr = name.split_whitespace().next().unwrap_or(name);
    let parts: Vec<&str> = addr.split(':').collect();
    if let Some(last) = parts.last() {
        if let Ok(port) = last.parse::<u16>() {
            return Some(port);
        }
    }
    None
}

#[tauri::command]
async fn kill_process(pid: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        // Windows: taskkill /F /PID <PID>
        let output = Command::new("taskkill")
            .args(&["/F", "/PID", &pid.to_string()])
            .output()
            .map_err(|e| format!("Failed to execute taskkill: {}", e))?;
        
        if output.status.success() {
            Ok(())
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(err_msg)
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // macOS/Linux: kill -9 <PID>
        let output = Command::new("kill")
            .args(&["-9", &pid.to_string()])
            .output()
            .map_err(|e| format!("Failed to execute kill: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr).to_string();
            Err(err_msg)
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct LocalAnalysis {
    category: String,
    importance: String,
    safety: String,
    reasoning: String,
}

#[tauri::command]
async fn analyze_port_local(port: u32, process_name: &str, is_system: bool) -> Result<LocalAnalysis, String> {
    use tract_onnx::prelude::Framework;
    
    // Load freshly trained ONNX models embedded at compile-time
    let importance_bytes = include_bytes!("../assets/port_classifier_importance.onnx");
    let safety_bytes = include_bytes!("../assets/port_classifier_safety.onnx");
    
    let name_lower = process_name.to_lowercase();
    let is_system = is_system || 
                     name_lower.contains("system") || 
                     name_lower.contains("svchost") || 
                     name_lower.contains("lsass") || 
                     name_lower.contains("wininit") || 
                     name_lower.contains("services") || 
                     name_lower.contains("smss") || 
                     name_lower.contains("csrss") || 
                     name_lower.contains("winlogon") ||
                     name_lower.contains("launchd") || 
                     name_lower.contains("init");
    let is_system_val = if is_system { 1.0 } else { 0.0 };
    let os_val = if cfg!(target_os = "windows") { 1.0 } else { 0.0 };
    
    let cat_val = if name_lower.contains("node") { 1.0 }
    else if name_lower.contains("vite") { 2.0 }
    else if name_lower.contains("postgres") { 3.0 }
    else if name_lower.contains("mysql") { 4.0 }
    else if name_lower.contains("redis") { 5.0 }
    else if name_lower.contains("mongo") { 6.0 }
    else if name_lower.contains("docker") { 7.0 }
    else if name_lower.contains("ssh") { 8.0 }
    else if name_lower.contains("nginx") || name_lower.contains("apache") || name_lower.contains("httpd") { 9.0 }
    else if name_lower.contains("w3svc") { 10.0 }
    else if name_lower.contains("svchost") || name_lower.contains("rpcss") || name_lower.contains("lsass") || name_lower.contains("wininit") || name_lower.contains("services") || name_lower.contains("smss") || name_lower.contains("csrss") || name_lower.contains("winlogon") { 11.0 }
    else if name_lower.contains("system") || name_lower.contains("launchd") || name_lower.contains("init") { 12.0 }
    else if name_lower.contains("mdnsresponder") || name_lower.contains("bonjour") { 13.0 }
    else if name_lower.contains("python") { 14.0 }
    else if name_lower.contains("chrome") || name_lower.contains("firefox") || name_lower.contains("edge") || name_lower.contains("brave") || name_lower.contains("safari") { 15.0 }
    else if name_lower.contains("slack") || name_lower.contains("discord") || name_lower.contains("teams") || name_lower.contains("zoom") || name_lower.contains("whatsapp") { 16.0 }
    else if name_lower.contains("anydesk") || name_lower.contains("teamviewer") || name_lower.contains("rustdesk") { 17.0 }
    else if name_lower.contains("explorer") || name_lower.contains("taskhost") || name_lower.contains("spoolsv") { 18.0 }
    else { 0.0 };

    let category = match cat_val as i32 {
        1 => "Dev Server".to_string(),
        2 => "Dev Server".to_string(),
        3 => "Database".to_string(),
        4 => "Database".to_string(),
        5 => "Database".to_string(),
        6 => "Database".to_string(),
        7 => "Docker Container".to_string(),
        8 => "Network Service".to_string(),
        9 => "Network Service".to_string(),
        10 => "Network Service".to_string(),
        11 => "System Service".to_string(),
        12 => "System Service".to_string(),
        13 => "System Service".to_string(),
        14 => "Dev Server".to_string(),
        15 => "Web Browser".to_string(),
        16 => "Communication App".to_string(),
        17 => "Remote Access".to_string(),
        18 => "System Utility".to_string(),
        _ => "Unknown".to_string(),
    };

    let run_inference = || -> Result<(String, String, String), String> {
        let input_data = tract_onnx::prelude::tract_ndarray::Array2::from_shape_vec(
            (1, 4),
            vec![port as f32, is_system_val, cat_val, os_val]
        ).map_err(|e| format!("Failed to create input array: {}", e))?;
        let input = tract_onnx::prelude::Tensor::from(input_data);

        // 1. Run Importance Inference
        let importance_model = tract_onnx::onnx()
            .model_for_read(&mut &importance_bytes[..])
            .map_err(|e| format!("Failed to read ONNX importance model: {}", e))?;
        let importance_plan = importance_model.into_runnable()
            .map_err(|e| format!("Failed to compile importance model plan: {}", e))?;
        let importance_result = importance_plan.run(vec![input.clone().into()].into())
            .map_err(|e| format!("Importance model inference error: {}", e))?;

        let importance_tensor = &importance_result[0];
        let importance_labels = importance_tensor.to_array_view::<i64>()
            .map_err(|e| format!("Failed to parse importance output tensor: {}", e))?;
        let importance_pred = importance_labels.iter().next().copied().unwrap_or(2);

        // 2. Run Safety Inference
        let safety_model = tract_onnx::onnx()
            .model_for_read(&mut &safety_bytes[..])
            .map_err(|e| format!("Failed to read ONNX safety model: {}", e))?;
        let safety_plan = safety_model.into_runnable()
            .map_err(|e| format!("Failed to compile safety model plan: {}", e))?;
        let safety_result = safety_plan.run(vec![input.into()].into())
            .map_err(|e| format!("Safety model inference error: {}", e))?;

        let safety_tensor = &safety_result[0];
        let safety_labels = safety_tensor.to_array_view::<i64>()
            .map_err(|e| format!("Failed to parse safety output tensor: {}", e))?;
        let safety_pred = safety_labels.iter().next().copied().unwrap_or(0);

        let importance = match importance_pred {
            0 => "CRITICAL".to_string(),
            1 => "DEVELOPMENT".to_string(),
            _ => "UNKNOWN/SUSPICIOUS".to_string(),
        };
        
        let safety = match safety_pred {
            0 => "SAFE_TO_KILL".to_string(),
            _ => "DANGEROUS_TO_KILL".to_string(),
        };

        let reasoning = match cat_val as i32 {
            15 => "Local web browser socket connection helper thread (e.g. Chrome, Firefox). Safe to terminate.".to_string(),
            16 => "Communication or online meeting tool workspace interface (e.g. Zoom, Discord, Slack, Skype). Safe to close.".to_string(),
            17 => "Desktop remote control sharing node (e.g. AnyDesk, TeamViewer). Use caution as this will close any active remote control sessions.".to_string(),
            18 => "Local system configuration assistant utility helper thread. Restricted: terminating system tasks risks UI crash.".to_string(),
            _ => match (importance_pred, safety_pred) {
                (0, _) => "Critical operating system or core service. Terminating this process will cause system instability or disconnect network bindings.".to_string(),
                (1, 0) => "User development environment or application server. Safe to terminate to free up port resources.".to_string(),
                (2, 1) => "Unknown process running under system user privileges. High risk. Recommended to inspect before termination.".to_string(),
                _ => "Unknown user space connection. Safe to kill if this port binding is no longer needed.".to_string(),
            }
        };

        Ok((importance, safety, reasoning))
    };

    let (mut importance, mut safety, mut reasoning) = match run_inference() {
        Ok(res) => res,
        Err(e) => {
            eprintln!("ONNX Inference failed, falling back to rules: {}", e);
            let is_critical = port < 1024 || is_system || name_lower.contains("system") || name_lower.contains("svchost") || name_lower.contains("mdns");
            let importance = if is_critical { "CRITICAL".to_string() } else { "DEVELOPMENT".to_string() };
            let safety = if is_critical { "DANGEROUS_TO_KILL".to_string() } else { "SAFE_TO_KILL".to_string() };
            let reasoning = if is_critical {
                "Critical operating system or core service. Terminating this process will cause system instability. (Fallback)".to_string()
            } else {
                "User development environment or application server. Safe to terminate to free up port resources. (Fallback)".to_string()
            };
            (importance, safety, reasoning)
        }
    };

    // Safety override to prevent false negatives from ML model on core system processes
    if is_system || port < 1024 {
        importance = "CRITICAL".to_string();
        safety = "DANGEROUS_TO_KILL".to_string();
        reasoning = "Critical operating system or core service. Terminating this process will cause system instability or disconnect network bindings.".to_string();
    }

    Ok(LocalAnalysis {
        category,
        importance,
        safety,
        reasoning,
    })
}

fn start_http_server() {
    std::thread::spawn(move || {
        let server = match tiny_http::Server::http("127.0.0.1:12200") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to start HTTP server: {}", e);
                return;
            }
        };

        println!("Background HTTP server listening on 127.0.0.1:12200");

        for request in server.incoming_requests() {
            handle_http_request(request);
        }
    });
}

fn handle_http_request(mut request: tiny_http::Request) {
    let url = request.url().to_string();
    let method = request.method().clone();

    // CORS preflight
    if method == tiny_http::Method::Options {
        let response = tiny_http::Response::empty(200)
            .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap())
            .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap())
            .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap())
            .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Private-Network"[..], &b"true"[..]).unwrap());
        let _ = request.respond(response);
        return;
    }

    let response_str;
    let mut status_code = 200;

    match (method, url.as_str()) {
        (tiny_http::Method::Get, "/ports") | (tiny_http::Method::Get, "/active-ports") => {
            match tauri::async_runtime::block_on(get_active_ports()) {
                Ok(ports) => {
                    response_str = serde_json::to_string(&ports).unwrap_or_default();
                }
                Err(e) => {
                    status_code = 500;
                    response_str = serde_json::to_string(&serde_json::json!({ "error": e })).unwrap_or_default();
                }
            }
        }
        (tiny_http::Method::Post, "/kill") | (tiny_http::Method::Post, "/kill-process") => {
            let mut content = String::new();
            let _ = request.as_reader().read_to_string(&mut content);
            
            #[derive(serde::Deserialize)]
            struct KillPayload {
                pid: u32,
            }

            match serde_json::from_str::<KillPayload>(&content) {
                Ok(payload) => {
                    match tauri::async_runtime::block_on(kill_process(payload.pid)) {
                        Ok(_) => {
                            response_str = serde_json::to_string(&serde_json::json!({ "success": true })).unwrap_or_default();
                        }
                        Err(e) => {
                            status_code = 500;
                            response_str = serde_json::to_string(&serde_json::json!({ "error": e })).unwrap_or_default();
                        }
                    }
                }
                Err(e) => {
                    status_code = 400;
                    response_str = serde_json::to_string(&serde_json::json!({ "error": format!("Invalid JSON: {}", e) })).unwrap_or_default();
                }
            }
        }
        (tiny_http::Method::Post, "/analyze") | (tiny_http::Method::Post, "/analyze-port") => {
            let mut content = String::new();
            let _ = request.as_reader().read_to_string(&mut content);

            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct AnalyzePayload {
                port: u32,
                process_name: String,
                is_system: bool,
            }

            match serde_json::from_str::<AnalyzePayload>(&content) {
                Ok(payload) => {
                    match tauri::async_runtime::block_on(analyze_port_local(payload.port, &payload.process_name, payload.is_system)) {
                        Ok(analysis) => {
                            response_str = serde_json::to_string(&analysis).unwrap_or_default();
                        }
                        Err(e) => {
                            status_code = 500;
                            response_str = serde_json::to_string(&serde_json::json!({ "error": e })).unwrap_or_default();
                        }
                    }
                }
                Err(e) => {
                    status_code = 400;
                    response_str = serde_json::to_string(&serde_json::json!({ "error": format!("Invalid JSON: {}", e) })).unwrap_or_default();
                }
            }
        }
        _ => {
            status_code = 404;
            response_str = serde_json::to_string(&serde_json::json!({ "error": "Not Found" })).unwrap_or_default();
        }
    }

    let response = tiny_http::Response::from_string(response_str)
        .with_status_code(status_code)
        .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Origin"[..], &b"*"[..]).unwrap())
        .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Methods"[..], &b"GET, POST, OPTIONS"[..]).unwrap())
        .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Headers"[..], &b"Content-Type"[..]).unwrap())
        .with_header(tiny_http::Header::from_bytes(&b"Access-Control-Allow-Private-Network"[..], &b"true"[..]).unwrap())
        .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    let _ = request.respond(response);
}

pub fn run() {
    start_http_server();
    
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_active_ports, kill_process, analyze_port_local])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
