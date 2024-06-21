import requests
import pandas as pd
from sklearn.cluster import KMeans
import matplotlib.pyplot as plt
import subprocess

# Конфигурация Elasticsearch
ELASTICSEARCH_URL = 'http://localhost:9200'
ELASTICSEARCH_INDEX = 'security_events'
ELASTICSEARCH_API_KEY = ''

# Конфигурация TheHive
THEHIVE_URL = 'http://localhost:9000'
THEHIVE_API_KEY = ''

# Конфигурация OpenDXL
OPEN_DXL_API_KEY = ''

# Функция для получения данных из Elasticsearch
def fetch_security_events():
    headers = {
        'Authorization': f'ApiKey {ELASTICSEARCH_API_KEY}'
    }
    response = requests.get(f'{ELASTICSEARCH_URL}/{ELASTICSEARCH_INDEX}/_search', headers=headers)
    response.raise_for_status()
    return response.json()

# Функция для нормализации данных
def normalize_data(events):
    df = pd.json_normalize(events['hits']['hits'])
    df['timestamp'] = pd.to_datetime(df['_source.@timestamp'])
    df = df.sort_values('timestamp')
    return df

# Функция для кластеризации данных
def analyze_data(df):
    features = ['_source.feature1', '_source.feature2', '_source.feature3']
    kmeans = KMeans(n_clusters=2)
    df['cluster'] = kmeans.fit_predict(df[features])
    return df

# Функция для автоматического реагирования на угрозы
def automate_response(ip_address):
    # Пример использования Ansible для блокировки IP
    subprocess.run(['ansible-playbook', 'ansible_playbook.yml', '--extra-vars', f'infected_ip={ip_address}'])

# Функция для создания инцидента в TheHive
def create_thehive_alert(description):
    headers = {
        'Authorization': f'Bearer {THEHIVE_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'title': 'Security Alert',
        'description': description,
        'type': 'external',
        'source': 'Elasticsearch',
        'sourceRef': 'es_alert_001'
    }
    response = requests.post(f'{THEHIVE_URL}/api/alert', json=payload, headers=headers)
    response.raise_for_status()
    return response.json()

# Функция для визуализации данных
def plot_event_trends(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp', inplace=True)
    df['_source.feature1'].plot()
    plt.title('Event Trends')
    plt.show()

# Основная функция для выполнения всех этапов
def main():
    # Шаг 1: Получение и нормализация данных
    events = fetch_security_events()
    df = normalize_data(events)

    # Шаг 2: Кластеризация данных и анализ
    df = analyze_data(df)

    # Шаг 3: Обработка выявленных угроз
    for _, row in df.iterrows():
        if row['cluster'] == 1:  # Пример условия для реагирования
            automate_response(row['_source.source_ip'])
            create_thehive_alert(f'Anomalous activity detected from IP: {row["_source.source_ip"]}')

    # Шаг 4: Визуализация данных
    plot_event_trends(df)

if __name__ == '__main__':
    main()