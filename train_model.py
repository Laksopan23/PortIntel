import os
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Process Vocabulary Mapping:
# 0: Unknown/Other
# 1: Node.js (node)
# 2: Vite (vite)
# 3: PostgreSQL (postgres)
# 4: MySQL (mysql)
# 5: Redis (redis)
# 6: MongoDB (mongo)
# 7: Docker (docker)
# 8: SSH (ssh)
# 9: Nginx/Apache (nginx, apache, httpd)
# 10: IIS (w3svc)
# 11: RPC (svchost, rpcss)
# 12: Core OS (system, launchd, init)
# 13: Bonjour (mdnsresponder, bonjour)
# 14: Python (python)
# 15: Web Browser (chrome, firefox, msedge, brave, safari)
# 16: Communication App (slack, discord, teams, zoom, whatsapp)
# 17: Remote Access (anydesk, teamviewer, rustdesk)
# 18: System Utility (explorer, taskhostw, spoolsv)

# Feature list: [port_number, is_system_user (0/1), process_category_index (0-18), operating_system (0:macos, 1:windows)]
# Targets: [Importance, TerminationSafety]
# Importance: 0 = CRITICAL, 1 = DEVELOPMENT, 2 = UNKNOWN/SUSPICIOUS
# TerminationSafety: 0 = SAFE_TO_KILL, 1 = DANGEROUS_TO_KILL

X = np.array([
    # Dev Servers (Development, Safe)
    [3000, 0, 1, 1], # node, win -> Dev, Safe
    [3000, 0, 1, 0], # node, mac -> Dev, Safe
    [5173, 0, 2, 1], # vite, win -> Dev, Safe
    [5173, 0, 2, 0], # vite, mac -> Dev, Safe
    [8080, 0, 1, 1], # node, win -> Dev, Safe
    [8000, 0, 14, 1], # python, win -> Dev, Safe
    [5000, 0, 14, 0], # python, mac -> Dev, Safe
    [8081, 0, 1, 1], # node, win -> Dev, Safe
    [4200, 0, 1, 1], # angular node, win -> Dev, Safe

    # Databases (Development, Safe - but with caution flag in UI)
    [5432, 0, 3, 1], # postgres, win -> Dev, Safe
    [5432, 0, 3, 0], # postgres, mac -> Dev, Safe
    [3306, 0, 4, 1], # mysql, win -> Dev, Safe
    [6379, 0, 5, 1], # redis, win -> Dev, Safe
    [27017, 0, 6, 1], # mongo, win -> Dev, Safe

    # Docker Proxies (Development, Safe)
    [8080, 0, 7, 1], # docker-proxy -> Dev, Safe
    [3306, 0, 7, 0], # docker-proxy -> Dev, Safe

    # Web Browsers (Development/User space, Safe)
    [8008, 0, 15, 1], # chrome, win -> Dev, Safe
    [9222, 0, 15, 1], # chrome devtools, win -> Dev, Safe
    [9229, 0, 15, 0], # chrome devtools, mac -> Dev, Safe

    # Communication Apps (Development/User space, Safe)
    [5060, 0, 16, 1], # skype/teams, win -> Dev, Safe
    [3478, 0, 16, 0], # zoom, mac -> Dev, Safe

    # Remote Access (Development/User space, Safe - caution handled in frontend based on category)
    [50001, 0, 17, 1], # anydesk, win -> Dev, Safe
    [5938, 0, 17, 1],  # teamviewer, win -> Dev, Safe
    [21115, 0, 17, 0], # rustdesk, mac -> Dev, Safe

    # System / Core Network Ports (Critical, Dangerous)
    [22, 1, 8, 1],  # sshd, win system -> Critical, Dangerous
    [22, 0, 8, 0],  # ssh, mac user -> Critical, Dangerous
    [80, 1, 9, 1],  # web servers, system -> Critical, Dangerous
    [443, 1, 9, 1], # SSL web servers, system -> Critical, Dangerous
    [53, 1, 12, 0], # dns system resolver -> Critical, Dangerous
    [135, 1, 11, 1], # Windows RPC -> Critical, Dangerous
    [137, 1, 12, 1], # NetBIOS system -> Critical, Dangerous
    [139, 1, 12, 1], # NetBIOS system -> Critical, Dangerous
    [445, 1, 12, 1], # Windows SMB system -> Critical, Dangerous
    [0, 1, 12, 1],   # System process -> Critical, Dangerous
    [5353, 1, 13, 0], # Bonjour / mDNS -> Critical, Dangerous

    # System Utilities (Critical, Dangerous to kill)
    [137, 1, 18, 1],   # spoolsv, win system -> Critical, Dangerous
    [1000, 1, 18, 1],  # system utility, win -> Critical, Dangerous

    # Unknown / Anomalous binds
    [4444, 0, 0, 1], # unknown user port -> Unknown, Safe
    [9999, 1, 0, 1], # unknown system user port -> Unknown, Dangerous
    [8085, 1, 0, 1], # unknown system user port -> Unknown, Dangerous
], dtype=np.float32)

y = np.array([
    [1, 0], # 3000 -> Dev, Safe
    [1, 0], # 3000 -> Dev, Safe
    [1, 0], # 5173 -> Dev, Safe
    [1, 0], # 5173 -> Dev, Safe
    [1, 0], # 8080 -> Dev, Safe
    [1, 0], # 8000 -> Dev, Safe
    [1, 0], # 5000 -> Dev, Safe
    [1, 0], # 8081 -> Dev, Safe
    [1, 0], # 4200 -> Dev, Safe

    [1, 0], # 5432 -> Dev, Safe
    [1, 0], # 5432 -> Dev, Safe
    [1, 0], # 3306 -> Dev, Safe
    [1, 0], # 6379 -> Dev, Safe
    [1, 0], # 27017 -> Dev, Safe

    [1, 0], # 8080 (docker) -> Dev, Safe
    [1, 0], # 3306 (docker) -> Dev, Safe

    [1, 0], # 8008 (chrome) -> Dev, Safe
    [1, 0], # 9222 (chrome) -> Dev, Safe
    [1, 0], # 9229 (chrome) -> Dev, Safe

    [1, 0], # 5060 (skype) -> Dev, Safe
    [1, 0], # 3478 (zoom) -> Dev, Safe

    [1, 0], # 50001 (anydesk) -> Dev, Safe
    [1, 0], # 5938 (teamviewer) -> Dev, Safe
    [1, 0], # 21115 (rustdesk) -> Dev, Safe

    [0, 1], # 22 -> Critical, Dangerous
    [0, 1], # 22 -> Critical, Dangerous
    [0, 1], # 80 -> Critical, Dangerous
    [0, 1], # 443 -> Critical, Dangerous
    [0, 1], # 53 -> Critical, Dangerous
    [0, 1], # 135 -> Critical, Dangerous
    [0, 1], # 137 -> Critical, Dangerous
    [0, 1], # 139 -> Critical, Dangerous
    [0, 1], # 445 -> Critical, Dangerous
    [0, 1], # 0 -> Critical, Dangerous
    [0, 1], # 5353 -> Critical, Dangerous

    [0, 1], # 137 (spoolsv) -> Critical, Dangerous
    [0, 1], # 1000 (system utility) -> Critical, Dangerous

    [2, 0], # 4444 -> Unknown, Safe
    [2, 1], # 9999 -> Unknown, Dangerous
    [2, 1], # 8085 (system user unknown) -> Unknown, Dangerous
], dtype=np.int64)

vocab_names = {
    0: "unknown",
    1: "node",
    2: "vite",
    3: "postgres",
    4: "mysql",
    5: "redis",
    6: "mongo",
    7: "docker",
    8: "ssh",
    9: "nginx",
    10: "w3svc",
    11: "svchost",
    12: "system",
    13: "mdnsresponder",
    14: "python",
    15: "chrome",
    16: "slack",
    17: "anydesk",
    18: "explorer"
}

def extend_features(X_old):
    X_new = []
    for row in X_old:
        port = row[0]
        is_system = row[1]
        cat_idx = int(row[2])
        os_val = row[3]
        
        name = vocab_names.get(cat_idx, "unknown")
        name_len = len(name)
        
        is_well_known = 1.0 if port < 1024 else 0.0
        is_common_dev_port = 1.0 if port in [3000, 5000, 8000, 8080, 5173, 8081, 4200, 5432, 3306, 6379, 27017] else 0.0
        
        X_new.append([port, is_system, float(cat_idx), os_val, is_well_known, float(name_len), is_common_dev_port])
    return np.array(X_new, dtype=np.float32)

X_extended = extend_features(X)

# Create assets folder in tauri backend relative to script path
script_dir = os.path.dirname(os.path.abspath(__file__))
assets_dir = os.path.join(script_dir, "src-tauri", "assets")
os.makedirs(assets_dir, exist_ok=True)

# 1. Train Importance Decision Tree Model
print("Training Importance Model...")
clf_importance = DecisionTreeClassifier(max_depth=5, random_state=42)
clf_importance.fit(X_extended, y[:, 0])

# Convert Importance model to ONNX format
print("Converting Importance Model to ONNX...")
initial_type = [('input', FloatTensorType([None, 7]))]
onx_importance = convert_sklearn(clf_importance, initial_types=initial_type, options={'zipmap': False})

onnx_path_imp = os.path.join(assets_dir, "port_classifier_importance.onnx")
with open(onnx_path_imp, "wb") as f:
    f.write(onx_importance.SerializeToString())
print(f"Importance model successfully saved to {onnx_path_imp}!")

# 2. Train Safety Decision Tree Model
print("Training Safety Model...")
clf_safety = DecisionTreeClassifier(max_depth=5, random_state=42)
clf_safety.fit(X_extended, y[:, 1])

# Convert Safety model to ONNX format
print("Converting Safety Model to ONNX...")
onx_safety = convert_sklearn(clf_safety, initial_types=initial_type, options={'zipmap': False})

onnx_path_saf = os.path.join(assets_dir, "port_classifier_safety.onnx")
with open(onnx_path_saf, "wb") as f:
    f.write(onx_safety.SerializeToString())
print(f"Safety model successfully saved to {onnx_path_saf}!")
