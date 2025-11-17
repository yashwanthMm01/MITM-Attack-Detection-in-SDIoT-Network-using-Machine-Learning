## MITM Attack Detection in SDIoT Networks

This project demonstrates how to detect and actively mitigate Man-in-the-Middle (MiTM) attacks in a software-defined IoT (SDIoT) testbed. It combines a Mininet-based topology, Ryu SDN controllers, IoT application scripts, live traffic collection, and an ML pipeline that learns MiTM behaviour from real packets and enforces protection in production.

### Key Capabilities
- **End-to-end SDIoT testbed** – `topology.py` spins up a sensor–switch–receiver network with an optional attacker host inside Mininet.
- **Live IoT workloads** – `sensor.py` continuously streams temperature readings to `receiver.py`, enabling realistic traffic generation.
- **Attack simulation** – `attacker_final.py` performs ARP spoofing and TCP stream manipulation with iptables redirection to prove impact.
- **Data-driven detection** – `data_collector.py` captures per-MAC statistics, while `advanced_ml_trainer.py` trains and compares multiple models (RF, GB, SVM, MLP) before exporting the best one to `mitm_detector_model.pkl`, `feature_scaler.pkl`, and `model_metadata.json`.
- **Production-grade enforcement** – `miti_ml_controller.py` (and the lighter `production_ml_controller.py`) run on Ryu, compute features online, predict attacks, and push OpenFlow rules to block or redirect malicious hosts.
- **Operational insight** – JSON reports (`ml_based_performance.json`, `rule_based_performance.json`) and `model_evaluation.png` capture how ML compares to rule-based baselines.

---

### Repository Layout

| Path | Description |
| --- | --- |
| `topology.py` | Mininet topology with sensor, receiver, and attacker nodes controlled by a remote Ryu controller. |
| `sensor.py`, `receiver.py` | IoT application pair exchanging temperature data via TCP. |
| `attacker_final.py` | Full MiTM adversary (ARP spoofing + packet rewrite + iptables-based redirection). |
| `data_collector.py` | Sliding-window feature extractor that labels traffic as normal/attack for training. |
| `advanced_ml_trainer.py` | Trains and evaluates multiple classifiers, saves the best model, scaler, metadata, and plots. |
| `miti_ml_controller.py`, `production_ml_controller.py`, `controller_3.py` | Ryu controllers with ML and/or rule-based detection plus mitigation logic. |
| `performance_monitor.py` | Utility comparing rule-based vs ML accuracy using stored JSON results. |
| `collected_dataset.csv` | Sample dataset produced by the collector (contains timestamps, MACs, features, labels). |
| `*.pkl`, `*.json`, `model_evaluation.png` | Artifacts from training and evaluation. |

---

### Prerequisites
- Ubuntu 20.04+ (recommended for Mininet/Ryu), Python 3.8/3.10.
- System packages: `sudo apt install -y mininet python3-ryu python3-scapy python3-pip`.
- Optional but recommended: `virtualenv`, `tcpdump`, `wireshark`, and `openvswitch-switch`.
- Python libs (install inside the repo/virtualenv):
  ```bash
  pip install --upgrade pip
  pip install ryu mininet scapy pandas numpy scikit-learn matplotlib seaborn joblib
  ```

> **Tip:** When running inside Mininet, prepend commands with `sudo` so the controller and packet capture can access raw sockets and kernel networking features.

---

### Quick Start Workflow

1. **Clone & configure**
   ```bash
   git clone https://github.com/yashwanthMm01/MITM-Attack-Detection-in-SDIoT-Network-using-Machine-Learning.git
   cd MITM-Attack-Detection-in-SDIoT-Network-using-Machine-Learning
   ```
   Adjust IPs/MACs in the Python scripts if your lab topology differs.

2. **Launch the SDIoT topology**
   ```bash
   sudo python3 topology.py
   ```
   This starts Mininet with a remote Ryu controller at `127.0.0.1:6633`. Keep the CLI open for host xterms or diagnostics.

3. **Run the controller**
   ```bash
   ryu-manager miti_ml_controller.py
   ```
   - Loads `mitm_detector_model.pkl` and `feature_scaler.pkl`.
   - Tracks per-MAC stats, scores each window, and auto-mitigates (drop or redirect) when confidence > 70%.
   - Toggle mitigation behaviour via `self.mitigation_enabled` / `self.mitigation_mode` in the script or through planned CLI hooks.

4. **Start IoT workloads**
   - In Mininet CLI: `xterm sensor receiver attacker`.
   - On the `receiver` host: `python3 receiver.py`.
   - On the `sensor` host: `python3 sensor.py` and periodically enter temperature values.

5. **(Optional) Launch the attacker**
   - On the `attacker` host:
     ```bash
     sudo python3 attacker_final.py
     ```
   - The script enables iptables NAT, poisons ARP caches, intercepts the sensor→receiver stream, and rewrites readings (+10 °C by default).

6. **Collect labelled training data**
   - Run `sudo python3 data_collector.py --interface sensor-eth0`.
   - Press `n` / `a` when prompted (or call `set_label`) to describe whether traffic is normal or under MiTM.
   - Stop with `Ctrl+C` to persist `collected_dataset.csv`.

7. **Train/compare ML models**
   ```bash
   python3 advanced_ml_trainer.py --dataset collected_dataset.csv
   ```
   - Performs preprocessing, trains RF/GB/SVM/MLP, prints metrics, and selects the best F1-score model.
   - Saves:
     - `mitm_detector_model.pkl`
     - `feature_scaler.pkl`
     - `model_metadata.json`
     - `model_evaluation.png`

8. **Evaluate runtime performance**
   - `python3 performance_monitor.py` reads `ml_based_performance.json` & `rule_based_performance.json` to compare detection latency, accuracy, and false-positive rates.

---

### Deployment Variants
- **`miti_ml_controller.py`** – Primary controller with advanced mitigation (block or redirect) and attack history tracking.
- **`production_ml_controller.py`** – Leaner runtime (fewer logs) suited for lab demos.
- **`controller_3.py`** – Rule-based-only fallback, useful when ML artifacts are unavailable.

Switch between controllers by restarting `ryu-manager` with the desired script:
```bash
ryu-manager production_ml_controller.py
```

---

### Troubleshooting
- **`ryu-manager` can’t find the model** – rerun the trainer to regenerate `.pkl` files or update `load_ml_model()` paths.
- **Permission errors on iptables/tcpdump** – ensure commands run with `sudo` and the user is part of the `wireshark`/`sudo` group.
- **Mininet hosts can’t reach the controller** – verify `ryu-manager` is listening on `0.0.0.0:6633` or adjust `RemoteController` IP in `topology.py`.
- **Dataset too small (<50 samples)** – the trainer will warn; collect both normal and attack traffic longer to balance classes.
- **Windows/macOS support** – the SDN/Mininet pieces require Linux; you can still train/evaluate ML locally by reusing CSV captures.

---

### Next Steps
- Automate feature collection + labelling via REST or controller RPCs.
- Containerise Ryu + Mininet for reproducible demos (e.g., Vagrant or Docker-in-Docker).
- Extend the dataset with additional attack types (DNS spoofing, TCP reset floods) and retrain the model for multi-class detection.

Feel free to open issues or PRs with reproducible bugs, new attacks, or performance enhancements. Happy hacking!

