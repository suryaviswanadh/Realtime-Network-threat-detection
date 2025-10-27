import tkinter as tk
from tkinter import ttk, scrolledtext
from utils.constants import THEME_COLORS


class MLDashboard:
    """Dashboard for ML model monitoring"""
    
    def __init__(self, parent, monitor):
        self.monitor = monitor
        self.window = tk.Toplevel(parent)
        self.window.title("ML Security Dashboard")
        self.window.geometry("1000x700")
        
        self.current_theme = "purple"
        self._setup_ui()
        self._update_loop()
    
    def _setup_ui(self):
        """Setup the UI components"""
        colors = THEME_COLORS[self.current_theme]
        self.window.config(bg=colors["bg"])
        
        # Title
        title_frame = ttk.Frame(self.window)
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        
        title_label = ttk.Label(
            title_frame,
            text="🤖 ML Security Dashboard",
            font=("Consolas", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        status_label = ttk.Label(title_frame, text="", font=("Consolas", 10))
        status_label.pack(side=tk.RIGHT)
        self.status_label = status_label
        
        # Main content notebook
        notebook = ttk.Notebook(self.window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: ML Status
        ml_status_frame = ttk.Frame(notebook)
        notebook.add(ml_status_frame, text="ML Status")
        self._setup_ml_status_tab(ml_status_frame, colors)
        
        # Tab 2: Anomaly Detection
        anomaly_frame = ttk.Frame(notebook)
        notebook.add(anomaly_frame, text="Anomaly Detection")
        self._setup_anomaly_tab(anomaly_frame, colors)
        
        # Tab 3: Model Statistics
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="Model Statistics")
        self._setup_stats_tab(stats_frame, colors)
    
    def _setup_ml_status_tab(self, parent, colors):
        """Setup ML status tab"""
        # ML Engine Status
        status_lf = ttk.LabelFrame(parent, text="ML Engine Status")
        status_lf.pack(fill=tk.X, padx=10, pady=10)
        
        self.ml_status_text = tk.Text(
            status_lf,
            height=10,
            font=("Consolas", 10),
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        self.ml_status_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Recent Predictions
        pred_lf = ttk.LabelFrame(parent, text="Recent ML Predictions")
        pred_lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.predictions_text = scrolledtext.ScrolledText(
            pred_lf,
            font=("Consolas", 9),
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        self.predictions_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _setup_anomaly_tab(self, parent, colors):
        """Setup anomaly detection tab"""
        # Anomaly Statistics
        stats_lf = ttk.LabelFrame(parent, text="Anomaly Statistics")
        stats_lf.pack(fill=tk.X, padx=10, pady=10)
        
        self.anomaly_stats_text = tk.Text(
            stats_lf,
            height=8,
            font=("Consolas", 10),
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        self.anomaly_stats_text.pack(fill=tk.X, padx=5, pady=5)
        
        # Detected Anomalies List
        anomalies_lf = ttk.LabelFrame(parent, text="Detected Anomalies")
        anomalies_lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("Time", "Type", "Severity", "Details")
        self.anomalies_tree = ttk.Treeview(
            anomalies_lf,
            columns=columns,
            show="tree headings",
            height=15
        )
        
        self.anomalies_tree.column("#0", width=50)
        self.anomalies_tree.heading("#0", text="#")
        
        widths = [120, 150, 100, 400]
        for col, width in zip(columns, widths):
            self.anomalies_tree.column(col, width=width)
            self.anomalies_tree.heading(col, text=col)
        
        scrollbar = ttk.Scrollbar(
            anomalies_lf,
            orient=tk.VERTICAL,
            command=self.anomalies_tree.yview
        )
        self.anomalies_tree.configure(yscrollcommand=scrollbar.set)
        
        self.anomalies_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Color coding
        self.anomalies_tree.tag_configure('high', background='#ff6666')
        self.anomalies_tree.tag_configure('medium', background='#ffaa66')
        self.anomalies_tree.tag_configure('low', background='#ffff66')
    
    def _setup_stats_tab(self, parent, colors):
        """Setup model statistics tab"""
        self.model_stats_text = scrolledtext.ScrolledText(
            parent,
            font=("Consolas", 10),
            bg=colors["text_bg"],
            fg=colors["text_fg"]
        )
        self.model_stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _update_ml_status(self):
        """Update ML engine status"""
        if not self.monitor.ml_available:
            self.status_label.config(text="❌ ML Not Available")
            self.ml_status_text.delete(1.0, tk.END)
            self.ml_status_text.insert(
                tk.END,
                "ML Engine is not available.\n\n"
                "To enable ML features:\n"
                "1. Install scikit-learn: pip install scikit-learn\n"
                "2. (Optional) Install tensorflow for deep learning\n"
                "3. Restart the application\n"
            )
            return
        
        self.status_label.config(text="✅ ML Active")
        
        # Get ML stats
        ml_stats = self.monitor.ml_engine.get_ml_stats()
        
        status_text = f"""ML Engine Status: {'✅ Active' if ml_stats['models_available'] else '❌ Inactive'}
Models Trained: {'Yes' if ml_stats['models_trained'] else 'No'}
Training Samples: {ml_stats['training_samples']}
Predictions Made: {ml_stats['predictions_made']}

Available Models:
"""
        for model in ml_stats['model_types']:
            status_text += f"  • {model}\n"
        
        if ml_stats['models_trained']:
            status_text += "\n✓ Models are actively analyzing traffic"
        else:
            remaining = 100 - ml_stats['training_samples']
            status_text += f"\n⏳ Collecting training data... ({remaining} samples needed)"
        
        self.ml_status_text.delete(1.0, tk.END)
        self.ml_status_text.insert(tk.END, status_text)
    
    def _update_anomaly_stats(self):
        """Update anomaly detection statistics"""
        stats = self.monitor.get_stats()
        
        anomaly_text = f"""Total Anomalies Detected: {stats.get('ml_anomalies', 0)}
Statistical Anomalies: {stats.get('ml_anomalies', 0)}
High Severity: {stats.get('dos_count', 0)}
Medium Severity: {stats.get('port_scan_count', 0)}

Detection Methods:
  • Isolation Forest (Unsupervised)
  • Statistical Analysis (3-sigma rule)
  • Heuristic Rules
"""
        
        self.anomaly_stats_text.delete(1.0, tk.END)
        self.anomaly_stats_text.insert(tk.END, anomaly_text)
    
    def _update_model_stats(self):
        """Update detailed model statistics"""
        if not self.monitor.ml_available or not hasattr(self.monitor, 'ml_engine') or not self.monitor.ml_engine:
            self.model_stats_text.delete(1.0, tk.END)
            self.model_stats_text.insert(tk.END, "ML models not available")
            return
        
        ml_stats = self.monitor.ml_engine.get_ml_stats()
        stats = self.monitor.get_stats()

        header = "ML SECURITY ENGINE - DETAILED STATISTICS"
        
        details = f"""{header.center(60)}
{'═' * 60}

MODEL STATUS:
  • Isolation Forest: {'✓ Trained' if ml_stats.get('models_trained') else '✗ Not Trained'}
  • Random Forest: {'✓ Available' if 'Random Forest' in ml_stats.get('model_types', []) else '✗ Not Available'}
  • Heuristic Rules: ✓ Active

ANALYSIS STATISTICS:
  • Total Predictions: {ml_stats.get('predictions_made', 0)}
  • Training Samples: {ml_stats.get('training_samples', 0)}/100
  • Threats Detected: {stats.get('threats_detected', 0)}
  • ML Anomalies: {stats.get('ml_anomalies', 0)}

DETECTION ACCURACY (CONCEPTUAL):
  • False Positive Rate: Monitoring...
  • True Positive Rate: Monitoring...
  • Confidence Threshold: 0.70

FEATURE ENGINEERING:
  • Packet Size Analysis: ✓
  • Inter-arrival Time: ✓
  • Protocol Distribution: ✓
  • Port Scanning Pattern: ✓
  • Traffic Burst Detection: ✓

MODEL PARAMETERS:
  • Window Size: 100 packets
  • Contamination Rate: 10%
  • Update Frequency: Real-time

PERFORMANCE (CONCEPTUAL):
  • Average Prediction Time: <1ms
  • Memory Usage: Normal
  • CPU Usage: Low

{'═' * 60}
"""
        
        self.model_stats_text.delete(1.0, tk.END)
        self.model_stats_text.insert(tk.END, details)
    
    def _update_loop(self):
        """Periodic update loop"""
        if self.window.winfo_exists():
            self._update_ml_status()
            self._update_anomaly_stats()
            self._update_model_stats()
            self.window.after(3000, self._update_loop)