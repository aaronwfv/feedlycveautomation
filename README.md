1. Add your API Key and StreamId in the CVE_AUTOMATION.ini file
2. Leave lasttimestamp blank in the CVE_AUTOMATION.ini file
3. Create a .txt file and paste the file path in 'cvefilepath' in the CVE_AUTOMATION.ini file
4. Create a .txt file and paste the file path in 'insightsfilepath' in the CVE_AUTOMATION.ini file
5. Paste the file path of the CVE_AUTOMATION.ini file to the 'Automated CVE Extraction.py' code (line 83)
6. Run 'Automated CVE Extraction.py'

CVEIDs from your StreamID are saved in a dictionary in the .txt file at 'cvefilepath'.
Metadata from the CVEIDs extracted and saved in 'cvefilepath' are saved as JSON in 'insightsfilepath'.

Contact aaron@feedly.com with any questions.
