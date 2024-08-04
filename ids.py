import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model
import os
import datetime
from subprocess import Popen
import time
import logging
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter

# Xác định tên cột
COLUMN_NAMES = [
    "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
    "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Tot",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Len",
    "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s", "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std",
    "Pkt Len Var", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt",
    "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts", "Init Fwd Win Byts",
    "Init Bwd Win Byts", "Fwd Act Data Pkts", "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"
]
def send_email_alert(subject, body):
    sender_email = "thinhvipbr3@@gmail.com"
    receiver_email = "hoangh2002@gmail.com"
    password = "xsnxsdvtludcchlu"

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    message.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Bước 1: Khởi động CICFlowMeter
def startup():
    curdirname = os.getcwd()  # thư mục làm việc hiện tại
    csvfilename = "%s_Flow.csv" % (datetime.datetime.today().strftime('%Y-%m-%d'))
    dir_path = os.path.join(curdirname, r'CICFlowMeter-4.0/bin/data/daily')
    
    # Tạo các thư mục nếu chúng chưa tồn tại
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    
    file_path = os.path.join(dir_path, csvfilename)
    isFileExist = os.path.exists(file_path)
    
    # Nếu tệp csv lưu lượng mạng không tồn tại, tạo một tệp mới và ghi tên cột
    if not isFileExist:
        with open(file_path, 'w') as file:
            file.write(','.join(COLUMN_NAMES) + '\n')
    
    # Khởi động CICFlowMeter
    Popen(os.path.join(curdirname, r"CICFlowMeter-4.0/bin/startIDS.sh"), stdout=subprocess.PIPE)

# Bước 2: Tải và tiền xử lý dữ liệu từ tệp CSV do CICFlowMeter tạo
def load_and_preprocess_data():
    curdirname = os.getcwd()  # thư mục làm việc hiện tại
    csvfilename = "%s_Flow.csv" % (datetime.datetime.today().strftime('%Y-%m-%d'))
    file_path = os.path.join(curdirname, r'CICFlowMeter-4.0/bin/data/daily', csvfilename)
    
    # Kiểm tra xem tệp CSV có tồn tại và không trống
    while not (os.path.exists(file_path) and os.path.getsize(file_path) > 0):
        print(f"Waiting for data in {file_path}...")
        time.sleep(10)  # Đợi 10 giây trước khi kiểm tra lại
    
    # Đọc dữ liệu từ tệp CSV theo từng chunk
    for chunk in pd.read_csv(file_path, chunksize=1000):
        dframe = chunk
    
    # # Đọc dữ liệu từ tệp CSV
    # dframe = pd.read_csv(file_path)
    
    # Kiểm tra xem DataFrame có dữ liệu hay không
    while dframe.shape[0] == 0:
        print(f"CSV file {file_path} does not contain any data. Waiting for data...")
        time.sleep(10)  # Đợi 10 giây trước khi kiểm tra lại
        dframe = pd.read_csv(file_path)
    
    col_name_consistency = {
        'Flow ID': 'Flow ID',
        'Source IP': 'Source IP',
        'Src IP':  'Source IP',
        'Source Port': 'Source Port',
        'Src Port': 'Source Port',
        'Destination IP': 'Destination IP',
        'Dst IP': 'Destination IP',
        'Destination Port': 'Destination Port',
        'Dst Port': 'Destination Port',
        'Protocol': 'Protocol',
        'Timestamp': 'Timestamp',
        'Flow Duration': 'Flow Duration',
        'Total Fwd Packets': 'Total Fwd Packets',
        'Tot Fwd Pkts': 'Total Fwd Packets',
        'Total Backward Packets': 'Total Backward Packets',
        'Tot Bwd Pkts': 'Total Backward Packets',
        'Total Length of Fwd Packets': 'Fwd Packets Length Total',
        'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets': 'Bwd Packets Length Total',
        'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
        'Fwd Packet Length Max': 'Fwd Packet Length Max',
        'Fwd Pkt Len Max': 'Fwd Packet Length Max',
        'Fwd Packet Length Min': 'Fwd Packet Length Min',
        'Fwd Pkt Len Min': 'Fwd Packet Length Min',
        'Fwd Packet Length Mean': 'Fwd Packet Length Mean',
        'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
        'Fwd Packet Length Std': 'Fwd Packet Length Std',
        'Fwd Pkt Len Std': 'Fwd Packet Length Std',
        'Bwd Packet Length Max': 'Bwd Packet Length Max',
        'Bwd Pkt Len Max': 'Bwd Packet Length Max',
        'Bwd Packet Length Min': 'Bwd Packet Length Min',
        'Bwd Pkt Len Min': 'Bwd Packet Length Min',
        'Bwd Packet Length Mean': 'Bwd Packet Length Mean',
        'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
        'Bwd Packet Length Std': 'Bwd Packet Length Std',
        'Bwd Pkt Len Std': 'Bwd Packet Length Std',
        'Flow Bytes/s': 'Flow Bytes/s',
        'Flow Byts/s': 'Flow Bytes/s',
        'Flow Packets/s': 'Flow Packets/s',
        'Flow Pkts/s': 'Flow Packets/s',
        'Flow IAT Mean': 'Flow IAT Mean',
        'Flow IAT Std': 'Flow IAT Std',
        'Flow IAT Max': 'Flow IAT Max',
        'Flow IAT Min': 'Flow IAT Min',
        'Fwd IAT Total': 'Fwd IAT Total',
        'Fwd IAT Tot': 'Fwd IAT Total',
        'Fwd IAT Mean': 'Fwd IAT Mean',
        'Fwd IAT Std': 'Fwd IAT Std',
        'Fwd IAT Max': 'Fwd IAT Max',
        'Fwd IAT Min': 'Fwd IAT Min',
        'Bwd IAT Total': 'Bwd IAT Total',
        'Bwd IAT Tot': 'Bwd IAT Total',
        'Bwd IAT Mean': 'Bwd IAT Mean',
        'Bwd IAT Std': 'Bwd IAT Std',
        'Bwd IAT Max': 'Bwd IAT Max',
        'Bwd IAT Min': 'Bwd IAT Min',
        'Fwd PSH Flags': 'Fwd PSH Flags',
        'Bwd PSH Flags': 'Bwd PSH Flags',
        'Fwd URG Flags': 'Fwd URG Flags',
        'Bwd URG Flags': 'Bwd URG Flags',
        'Fwd Header Length': 'Fwd Header Length',
        'Fwd Header Len': 'Fwd Header Length',
        'Bwd Header Length': 'Bwd Header Length',
        'Bwd Header Len': 'Bwd Header Length',
        'Fwd Packets/s': 'Fwd Packets/s',
        'Fwd Pkts/s': 'Fwd Packets/s',
        'Bwd Packets/s': 'Bwd Packets/s',
        'Bwd Pkts/s': 'Bwd Packets/s',
        'Min Packet Length': 'Packet Length Min',
        'Pkt Len Min': 'Min Packet Length',
        'Max Packet Length': 'Packet Length Max',
        'Pkt Len Max': 'Max Packet Length',
        'Packet Length Mean': 'Packet Length Mean',
        'Pkt Len Mean': 'Packet Length Mean',
        'Packet Length Std': 'Packet Length Std',
        'Pkt Len Std': 'Packet Length Std',
        'Packet Length Variance': 'Packet Length Variance',
        'Pkt Len Var': 'Packet Length Variance',
        'FIN Flag Count': 'FIN Flag Count',
        'FIN Flag Cnt': 'FIN Flag Count',
        'SYN Flag Count': 'SYN Flag Count',
        'SYN Flag Cnt': 'SYN Flag Count',
        'RST Flag Count': 'RST Flag Count',
        'RST Flag Cnt': 'RST Flag Count',
        'PSH Flag Count': 'PSH Flag Count',
        'PSH Flag Cnt': 'PSH Flag Count',
        'ACK Flag Count': 'ACK Flag Count',
        'ACK Flag Cnt': 'ACK Flag Count',
        'URG Flag Count': 'URG Flag Count',
        'URG Flag Cnt': 'URG Flag Count',
        'CWE Flag Count': 'CWE Flag Count',
        'CWE Flag Cnt': 'CWE Flag Count',
        'ECE Flag Count': 'ECE Flag Count',
        'ECE Flag Cnt': 'ECE Flag Count',
        'Down/Up Ratio': 'Down/Up Ratio',
        'Average Packet Size': 'Avg Packet Size',
        'Pkt Size Avg': 'Average Packet Size',
        'Avg Fwd Segment Size': 'Avg Fwd Segment Size',
        'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
        'Avg Bwd Segment Size': 'Avg Bwd Segment Size',
        'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
        'Fwd Avg Bytes/Bulk': 'Fwd Avg Bytes/Bulk',
        'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
        'Fwd Avg Packets/Bulk': 'Fwd Avg Packets/Bulk',
        'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
        'Fwd Avg Bulk Rate': 'Fwd Avg Bulk Rate',
        'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk': 'Bwd Avg Bytes/Bulk',
        'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
        'Bwd Avg Packets/Bulk': 'Bwd Avg Packets/Bulk',
        'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
        'Bwd Avg Bulk Rate': 'Bwd Avg Bulk Rate',
        'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets': 'Subflow Fwd Packets',
        'Subflow Fwd Pkts': 'Subflow Fwd Packets',
        'Subflow Fwd Bytes': 'Subflow Fwd Bytes',
        'Subflow Fwd Byts': 'Subflow Fwd Bytes',
        'Subflow Bwd Packets': 'Subflow Bwd Packets',
        'Subflow Bwd Pkts': 'Subflow Bwd Packets',
        'Subflow Bwd Bytes': 'Subflow Bwd Bytes',
        'Subflow Bwd Byts': 'Subflow Bwd Bytes',
        'Init_Win_bytes_forward': 'Init Fwd Win Bytes',
        'Init Fwd Win Byts': 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward': 'Init Bwd Win Bytes',
        'Init Bwd Win Byts': 'Init_Win_bytes_backward',
        'act_data_pkt_fwd': 'Fwd Act Data Packets',
        'Fwd Act Data Pkts': 'act_data_pkt_fwd',
        'min_seg_size_forward': 'Fwd Seg Size Min',
        'Fwd Seg Size Min': 'min_seg_size_forward',
        'Active Mean': 'Active Mean',
        'Active Std': 'Active Std',
        'Active Max': 'Active Max',
        'Active Min': 'Active Min',
        'Idle Mean': 'Idle Mean',
        'Idle Std': 'Idle Std',
        'Idle Max': 'Idle Max',
        'Idle Min': 'Idle Min',
        'Label': 'Label'
    }
    drop_columns = [ # this list includes all spellings across CIC NIDS datasets
        "Flow ID",    
        'Fwd Header Length.1',
        "Unnamed: 0", "SimillarHTTP", # CIC-DDoS other undocumented columns
         'Protocol'
    ]
    dframe.columns = [col.strip() for col in dframe.columns]   
    dframe.rename(columns=col_name_consistency, inplace=True)
    dframe.drop(columns=drop_columns, inplace=True, errors='ignore') 
    for column in dframe.columns:
        if pd.api.types.is_numeric_dtype(dframe[column]):
            col_mean = dframe[column][np.isfinite(dframe[column])].mean()
            dframe[column].replace([np.nan, np.inf, -np.inf], col_mean, inplace=True)
    print(dframe.duplicated().sum(), "fully duplicates removed")
    dframe.drop_duplicates(inplace=True)
    dframe.reset_index(inplace=True, drop=True)
    
    
    X = dframe.drop(['Label', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp'], axis=1, errors='ignore')
    
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    y = dframe['Label']
    return X, y, dframe


# Hàm parsePredictionDF để trích xuất thông tin từ DataFrame
def parsePredictionDF(dataframe):
    src_ip = dataframe["Source IP"].values[0]
    src_port = dataframe["Source Port"].values[0]
    dst_ip = dataframe["Destination IP"].values[0]
    dst_port = dataframe["Destination Port"].values[0]
    timestamp = dataframe["Timestamp"].values[0]
    return "%s %s:%s => %s:%s" % (timestamp, src_ip, src_port, dst_ip, dst_port)

# Bước 3: Chạy mô hình phát hiện tấn công mạng

def runIDS():
    print("Starting IDS...")
    email_sent = False
    try:
        # Tạo thư mục và tệp log nếu chưa tồn tại
        if not os.path.exists(r'logs/idslog/ids.log'):
            os.makedirs(r'logs/idslogs', exist_ok=True)
            with open(os.path.join(r'logs/idslogs', 'ids.log'), 'w') as file:
                pass
        logging.basicConfig(filename=os.path.join(r'logs/idslogs', 'ids.log'), level=logging.INFO)

        # Tải mô hình đã lưu
        loaded_model = load_model("cnn_model.h5")

        while True:
            # Tải và tiền xử lý dữ liệu
            X, y, dframe = load_and_preprocess_data()

            # Dự đoán nhãn
            y_pred_new = loaded_model.predict(X)
            y_pred_new = np.argmax(y_pred_new, axis=1)

            # Ánh xạ các giá trị mã hóa nhãn về tên nhãn gốc
            label_mapping = {0: 'BENIGN', 1: 'Bot', 2: 'PortScan', 3: 'DDoS', 4: 'DoS Attack', 
                            5: 'Brute Force', 6: 'Web Attack'}

            # Chuyển mã hóa nhãn thành tên nhãn
            predicted_labels = [label_mapping[label] for label in y_pred_new]

            # Đếm số lượng các nhãn khác BENIGN
            label_counter = Counter(predicted_labels)
            label_counter.pop('BENIGN', None)  # Loại bỏ nhãn BENIGN nếu có

            # Tìm nhãn xuất hiện nhiều nhất
            if label_counter:
                most_common_label, most_common_count = label_counter.most_common(1)[0]
            else:
                most_common_label, most_common_count = None, 0

            # Hiển thị và ghi log kết quả
            log_messages = []
            for label, row in zip(predicted_labels, dframe.iterrows()):
                csValsDF = pd.DataFrame([row[1]])
                log_message = f"{label}: %s" % (parsePredictionDF(csValsDF))
                print(log_message)
                logging.info(log_message)
                log_messages.append(log_message)

            # Gửi email cảnh báo nếu có nhãn khác BENIGN xuất hiện nhiều nhất
            if most_common_label and not email_sent:
                subject = f"Cảnh báo: phát hiện tấn công {most_common_label}"
                body = f"Tấn công {most_common_label} đã được phát hiện.\n\nChi tiết:\n"
                body += "\n".join([msg for msg in log_messages if most_common_label in msg])
                send_email_alert(subject, body)
                email_sent = True  # Đánh dấu là đã gửi email

            dframe['Predicted_Label'] = predicted_labels
            # Lưu kết quả ra file .csv
            curdirname = os.path.dirname(os.path.abspath(__file__))
            output_path = os.path.join(curdirname, "predicted_data.csv")
            dframe.to_csv(output_path, index=False)

            print("Results saved to", output_path)

            # Thêm khoảng nghỉ để tránh vòng lặp chạy quá nhanh
            time.sleep(10)

    except KeyboardInterrupt:
        print("Exiting...")


if __name__ == "__main__":
    startup()
    runIDS()
    
