import streamlit as st
import requests
import time
from sklearn.ensemble import RandomForestClassifier  # Example ML model (optional)
import pandas as pd

# Function to upload the file and get the scan ID
def upload_file_to_virustotal(apk_file, api_key):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    files = {"file": (apk_file.name, apk_file)}

    try:
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()
        return response.json()  # Return the scan response containing scan_id
    except requests.exceptions.RequestException as e:
        st.error(f"Error uploading file: {e}")
        return None

# Function to poll the scan results
def get_scan_results(scan_id, api_key):
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()  # Return the scan results
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching scan results: {e}")
        return None

# Streamlit UI
def apk_virus_scanner():
    st.title("APK Virus Scanner")

    # Upload an APK file
    apk_file = st.file_uploader("Upload an APK File", type=["apk"])

    if apk_file is not None:
        st.success(f"File '{apk_file.name}' uploaded successfully!")

        # VirusTotal API key (replace with your key)
        api_key = "ce399f694aff643b1ec8c53e7f8363ed4672ce02b5676997a1ef807a39608294"

        # Step 1: Upload the file to VirusTotal
        st.text("Uploading the APK file to VirusTotal...")
        upload_response = upload_file_to_virustotal(apk_file, api_key)

        if upload_response:
            scan_id = upload_response.get("data", {}).get("id")
            if not scan_id:
                st.error("Failed to retrieve scan ID. Please try again.")
                return

            st.text("Scanning the APK file... This may take a few seconds.")

            # Step 2: Poll for scan results
            for attempt in range(10):  # Retry up to 10 times
                st.text(f"Checking scan results (Attempt {attempt + 1}/10)...")
                result_data = get_scan_results(scan_id, api_key)

                if result_data and result_data.get("data", {}).get("attributes", {}).get("status") == "completed":
                    # Parse the VirusTotal scan results
                    attributes = result_data["data"]["attributes"]
                    stats = attributes.get("stats", {})
                    malicious_count = stats.get("malicious", 0)
                    harmless_count = stats.get("harmless", 0)
                    undetected_count = stats.get("undetected", 0)

                    # Display the VirusTotal scan results
                    st.subheader("VirusTotal Scan Results")
                    st.write(f"**Malicious Engines:** {malicious_count}")
                    st.write(f"**Harmless Engines:** {harmless_count}")
                    st.write(f"**Undetected Engines:** {undetected_count}")

                    # Add safety statement based on malicious count
                    if malicious_count > 0:
                        st.error("⚠️ Malware detected in the APK file. It is NOT SAFE to use this file.")
                    else:
                        st.success("✅ No malware detected. The APK file appears to be SAFE to use.")

                    # Option to show full VirusTotal scan details (JSON)
                    with st.expander("Show Full VirusTotal Scan Details (JSON)"):
                        st.json(result_data)

                    return  # Exit loop once results are ready

                # Wait before retrying
                time.sleep(15)

            # If scan results are still not ready
            st.warning("Scan results not ready. Please try again later.")
        else:
            st.error("Failed to upload file to VirusTotal. Please try again.")

# Run the Streamlit app
if __name__ == "__main__":
    apk_virus_scanner()
