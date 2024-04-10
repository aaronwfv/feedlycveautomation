import requests
import json
import os
import time
import configparser

def fetch_articles(config_file_path):
    config = configparser.ConfigParser()
    config.read(config_file_path)
    api_key = config['FEEDLY']['ApiKey']
    stream_id = config['FEEDLY']['StreamId']
    last_timestamp = config['FEEDLY'].get('LastTimestamp', None)
    base_url = "https://api.feedly.com/v3/streams/contents"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    continuation = None
    file_path = config['FEEDLY'].get('CveFilePath')  # Directly use the file path from config
    all_vulnerabilities = []
    
    while True:
        params = {
            "streamId": stream_id,
            "count": 100
        }
        if last_timestamp:
            params["newerThan"] = last_timestamp
        if continuation:
            params["continuation"] = continuation

        response = requests.get(base_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = [entity.get('label') for item in data.get('items', [])
                               for entity in item.get('entities', [])
                               if 'vulnerabilityInfo' in entity]
            all_vulnerabilities.extend(vulnerabilities)
            continuation = data.get('continuation')
            last_timestamp = data.get('updated', last_timestamp)
            if not continuation:
                break
        else:
            print(f"Failed to fetch articles, status code: {response.status_code}")
            break
        time.sleep(1)  # Adjust sleep time as needed

    # Save the unique CVE IDs to the JSON file
    unique_cve_ids = list(set(all_vulnerabilities))
    with open(file_path, 'w') as file:
        json.dump(unique_cve_ids, file)

    # Update the INI file with the new last timestamp
    config.set('FEEDLY', 'LastTimestamp', str(last_timestamp))
    with open(config_file_path, 'w') as configfile:
        config.write(configfile)

    return unique_cve_ids

def batch_cves_and_call_api(config_file_path, cve_ids):
    config = configparser.ConfigParser()
    config.read(config_file_path)
    api_key = config['FEEDLY']['ApiKey']
    insights_path = config['FEEDLY'].get('InsightsFilePath')
    batch_size = 100
    url = "https://api.feedly.com/v3/vulns/.mget"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i+batch_size]
        response = requests.post(url, json=batch, headers=headers)
        if response.ok:
            data = response.json()
            with open(insights_path, 'a') as file:
                json.dump(data, file, indent=4)
                file.write('\n')

if __name__ == '__main__':
    config_file_path = '/filepath/CVE_AUTOMATION.ini' #Replace with CVE_AUTOMATION File path
    vulns = fetch_articles(config_file_path)
    batch_cves_and_call_api(config_file_path, vulns)