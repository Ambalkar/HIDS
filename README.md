
# 🛡️ Windows Intrusion Detection System (IDS)

## 📌 Project Overview

The **Windows Intrusion Detection System (IDS)** is a real-time security solution for Windows that monitors folders, analyzes files using a trained machine learning model, and alerts users of suspicious or malicious activity. With an intuitive graphical interface, it supports various file types and ensures seamless file inspection and reporting — all backed by a **Random Forest classifier**.

---

## ✨ Features

* ✅ **Real-time Folder Monitoring**
  Continuously observes a chosen folder using the `watchdog` library for new or modified files.

* 🧠 **ML-Based File Analysis**
  Uses a trained **RandomForest** model to detect and classify files as *safe* or *malicious*.

* 📄 **Multi-format File Support**
  Supports: `.docx`, `.pptx`, `.pdf`, `.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.js`, `.py`, `.txt`, and more.

* 🖼️ **Graphical User Interface (GUI)**
  Built using `Tkinter` for easy folder selection, control, and result visualization.

* 🔍 **Detailed File Descriptions**
  Shows metadata including size, type, timestamps, and content summaries.

* 🧾 **Logging and Alerts**
  Logs all events with daily rotation and a 7-day retention policy using `loguru`.

* 📦 **Standalone Executable Support**
  Easily package the application as a `.exe` using PyInstaller for end-user deployment.

---

## 🛠️ Installation & Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/windows-ids.git
cd windows-ids

# Install dependencies
pip install -r requirements.txt

# Place your dataset in the data/ directory
# Example: data/cybersecurity_attacks.csv
```

---

## ▶️ How to Use

```bash
python main.py
```

Use the GUI to:

* 📁 **Browse** and select a folder to monitor
* ▶️ **Start Monitoring** / ⏹️ **Stop Monitoring**
* 🔍 View results in three tabs:

  * **Analysis Results**: Logs of file inspection
  * **File Description**: Metadata summaries
  * **Alert Messages**: Malicious file warnings (color-coded)

🔔 Alerts and logs are stored in the `logs/` directory.

---

## 📂 Project Structure

| File / Folder         | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| `main.py`             | Application entry point; initializes logging and GUI       |
| `gui.py`              | Implements the `Tkinter`-based GUI                         |
| `file_monitor.py`     | Folder monitoring using `watchdog`                         |
| `ml_model.py`         | Loads/trains Random Forest model; classifies files         |
| `evaluate_model.py`   | Evaluates model with cross-validation and test data        |
| `logger.py`           | Logging with rotating logs using `loguru`                  |
| `utils.py`            | Utility functions (e.g., SHA256, file extension detection) |
| `data/`               | Folder for datasets (e.g., `cybersecurity_attacks.csv`)    |
| `logs/`               | Auto-generated runtime logs                                |
| `evaluation_results/` | Model evaluation output                                    |

---

## 🧠 Machine Learning Model

* **Model Type:** Random Forest Classifier
* **Training Data:** `cybersecurity_attacks.csv`
* **Features:** Source/destination ports, packet length, protocol, entropy, file type, file size
* **Target:** Binary classification — *safe* or *malicious*

### 🔍 File Analysis Details:

| File Type      | Analysis Details                              |
| -------------- | --------------------------------------------- |
| `.exe`, `.dll` | Automatically flagged as suspicious by policy |
| Scripts        | Analyzed for abnormal size/content patterns   |
| Documents      | Checked for emptiness, structure, anomalies   |
| PDF            | Page count, metadata inspection               |
| Others         | Size, entropy, MIME type, SHA256 hash         |

---

## 🔁 Real-Time Monitoring

* Recursive folder monitoring
* Ignores system folders like `.git`, `__pycache__`, `venv`
* Filters by allowed file extensions
* Triggers classification on every new or modified file

---

## 📊 Model Evaluation

* Run evaluation:

  ```bash
  python evaluate_model.py
  ```
* **Evaluation Metrics:**

  * 5-Fold Cross Validation
  * Accuracy, Confusion Matrix, Logs

📁 Results saved in: `evaluation_results/accuracy_results.txt`

---

## 🧱 Building a Windows Executable

1. Install PyInstaller:

   ```bash
   pip install pyinstaller
   ```

2. Create the executable:

   ```bash
   pyinstaller --onefile --windowed main.py
   ```

3. Find the `.exe` in the `dist/` folder.

---

## 🤝 Contributing

Contributions are welcome!
Please feel free to fork the repo, submit pull requests, or open issues for bug reports and enhancements.

---

## 📄 License

This project is licensed under the **MIT License**.
Feel free to use and modify it for personal or commercial use.


