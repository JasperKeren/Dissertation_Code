from flask import Flask, request, jsonify, render_template
import torch
import joblib
import numpy as np
import pandas as pd
import os
import random

# ==== Load artifacts ====
scaler = joblib.load('scaler.pkl')
pca = joblib.load('pca.pkl')
le = joblib.load('label_encoder.pkl')

# ==== Define LSTM model ====
class LSTMModel(torch.nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, num_classes):
        super(LSTMModel, self).__init__()
        self.lstm = torch.nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = torch.nn.Linear(hidden_size, num_classes)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        return out

# ==== Initialize model ====
input_size = 10
hidden_size = 128
num_layers = 2
num_classes = len(le.classes_)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

lstm = LSTMModel(input_size, hidden_size, num_layers, num_classes).to(device)
lstm.load_state_dict(torch.load('lstm_model.pth', map_location=device))
lstm.eval()

# ==== Flask App ====
app = Flask(__name__)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        input_json = request.get_json(force=True)

        features = [
            'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Fwd IAT Mean',
            'Fwd IAT Max', 'Bwd IAT Mean', 'Packet Length Mean', 'PSH Flag Count',
            'ACK Flag Count', 'Average Packet Size'
        ]

        sample_df = pd.DataFrame([input_json], columns=features)

        sample_scaled = scaler.transform(sample_df)
        sample_pca = pca.transform(sample_scaled)
        sample_tensor = torch.tensor(sample_pca.reshape(1, 1, 10), dtype=torch.float32).to(device)

        with torch.no_grad():
            out = lstm(sample_tensor)
            _, pred = torch.max(out, 1)
            pred_label = le.inverse_transform([pred.item()])[0]

        return jsonify({'prediction': int(pred.item()), 'label': pred_label})

    except Exception as e:
        return jsonify({'error': str(e)})

# ==== Zeek Log Fetch Endpoint ====
@app.route('/fetch-latest-zeek', methods=['GET'])
def fetch_latest_from_zeek():
    try:
        log_path = 'zeek_output/conn.log'
        if not os.path.exists(log_path):
            return jsonify({'error': 'Zeek conn.log not found'})

        with open(log_path, 'r') as f:
            lines = [line for line in f if not line.startswith('#')]

        if not lines:
            return jsonify({'error': 'No valid Zeek connection entries found'})

        last = lines[-1].strip().split('\t')

        def safe_float(value, default=0.0):
            try:
                return float(value)
            except:
                return default

        duration = safe_float(last[8])
        orig_bytes = safe_float(last[9])
        resp_bytes = safe_float(last[10])
        orig_pkts = safe_float(last[16])
        resp_pkts = safe_float(last[18])
        orig_ip_bytes = safe_float(last[17])
        resp_ip_bytes = safe_float(last[19])

        total_bytes = orig_ip_bytes + resp_ip_bytes
        total_pkts = orig_pkts + resp_pkts
        avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0.0
        pkts_per_sec = total_pkts / duration if duration > 0 else 0.0

        latest_data = {
            "Flow Duration": duration * 1000, # Convert to milliseconds  random.uniform(200,1000),
            "Flow Bytes/s": orig_bytes + resp_bytes, #random.uniform(11,614),
            "Flow Packets/s": pkts_per_sec, #random.uniform(3, 820),
            "Fwd IAT Mean": 25.0,  # Placeholder # random.uniform(113, 914),
            "Fwd IAT Max": 60.0,   # Placeholder #random.uniform(12, 919),
            "Bwd IAT Mean": 22.0,  # Placeholder #random.uniform(62, 934),
            "Packet Length Mean": avg_pkt_size, #random.uniform(519, 996),
            "PSH Flag Count": 1.0,  # Placeholder # random.uniform(0,855),
            "ACK Flag Count": 2.0,  # Placeholder #random.uniform(0,739),
            "Average Packet Size": avg_pkt_size #random.uniform(284, 717)
}
        

        return jsonify(latest_data)

    except Exception as e:
        return jsonify({'error': str(e)})


# ==== Run Server ====
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
