import requests
import json
import configparser
import re

def load_configuration(config_file_path):
    config = configparser.ConfigParser()
    config.read(config_file_path)
    return config

def fetch_vulnerability_data(api_key, file_path):
    url = "https://api.feedly.com/v3/memes/vulnerabilities/en?count=25"
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        # Use a regular expression to find valid CVE IDs
        cve_ids = []
        for item in data.get('memes', []):
            label = item.get('label', '')
            matches = re.findall(r'CVE-\d{4}-\d{4,7}', label)
            cve_ids.extend(matches)
        
        unique_cve_ids = list(set(cve_ids))  # Remove duplicates
        save_to_file(file_path, {"cveids": unique_cve_ids})
        print(f"Number of unique CVEs added: {len(unique_cve_ids)}")
        return unique_cve_ids
    else:
        print(f"Failed to fetch data, status code: {response.status_code}")
        return []

def save_to_file(file_path, data, mode='w'):
    with open(file_path, mode) as file:
        json.dump(data, file, indent=4)
        file.write('\n')
    print(f"Data saved to {file_path}")

def batch_cves_and_call_api(api_key, insights_path, cve_ids):
    url = "https://api.feedly.com/v3/vulns/.mget"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    batch_size = 100

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        response = requests.post(url, json={"ids": batch}, headers=headers)
        if response.ok:
            data = response.json()
            save_to_file(insights_path, data, mode='a')
        else:
            print(f"Failed to fetch insights, status code: {response.status_code}, reason: {response.text}")

def main():
    config_file_path = '/path to/CVE_AUTOMATION.ini'
    config = load_configuration(config_file_path)
    api_key = config['FEEDLY']['ApiKey']
    cve_file_path = config['FEEDLY'].get('CveFilePath', 'vulnerabilities.txt')
    insights_path = config['FEEDLY'].get('InsightsFilePath', 'CVE_JSON.txt')

    cve_ids = fetch_vulnerability_data(api_key, cve_file_path)
    if cve_ids:
        batch_cves_and_call_api(api_key, insights_path, cve_ids)
    else:
        print("No CVE IDs fetched to process insights.")

if __name__ == '__main__':
    main()
