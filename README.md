# DNS-Traffic-Analysis-for-Malicious-Activity-Detection
#DNS traffic analysis for detecting malicious DNS queries. This project aims to identify DNS tunneling, DNS exfiltration, and other DNS-based attacks by analyzing patterns in DNS reques
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Simulated DNS query dataset
# Features might include: query type, query length, query frequency, response time
data = {
    'query_length': [20, 25, 18, 35, 40, 30, 80, 95, 10, 20],
    'response_time': [100, 150, 120, 180, 200, 130, 350, 400, 80, 110],
    'queries_per_second': [5, 4, 6, 3, 2, 7, 1, 0, 8, 4],
    'domain_name_length': [15, 16, 14, 13, 20, 25, 30, 35, 12, 18],
    'label': ['Normal', 'Normal', 'Normal', 'Normal', 'Normal', 'Malicious', 'Malicious', 'Malicious', 'Normal', 'Normal']
}

# Convert to DataFrame
df = pd.DataFrame(data)

# Map labels: 'Normal' -> 0, 'Malicious' -> 1
df['label'] = df['label'].map({'Normal': 0, 'Malicious': 1})

# Split features and labels
X = df.drop(columns=['label'])
y = df['label']

# Normalize the features using StandardScaler
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train a Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predict on the test set
y_pred = model.predict(X_test)

# Evaluate the model's performance
print("Classification Report:")
print(classification_report(y_test, y_pred))

# Real-time DNS query detection function
def detect_malicious_dns(query_length, response_time, queries_per_second, domain_name_length):
    features = np.array([[query_length, response_time, queries_per_second, domain_name_length]])
    features_scaled = scaler.transform(features)
    
    # Predict whether the query is normal or malicious
    prediction = model.predict(features_scaled)
    if prediction == 1:
        print("ALERT! Malicious DNS query detected!")
    else:
        print("Normal DNS query.")

# Simulate real-time DNS query detection
new_dns_query = {
    'query_length': 120,
    'response_time': 300,
    'queries_per_second': 10,
    'domain_name_length': 40
}
detect_malicious_dns(new_dns_query['query_length'], new_dns_query['response_time'],
                     new_dns_query['queries_per_second'], new_dns_query['domain_name_length'])
