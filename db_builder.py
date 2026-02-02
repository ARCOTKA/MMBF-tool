import pandas as pd
import duckdb
import xml.etree.ElementTree as ET
import os

# --- CONFIGURATION (PORTABLE PATHS) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_INPUT = os.path.join(BASE_DIR, 'all_units_oct_to_jan_export.csv')
XML_INPUT = os.path.join(BASE_DIR, 'alarmlist.xml')
WHITELIST_INPUT = os.path.join(BASE_DIR, 'MMbf_whitelist.csv')
DB_OUTPUT = os.path.join(BASE_DIR, 'alarm_logs3.duckdb')


def parse_alarm_xml(xml_file):
    """
    Parses the alarmlist.xml provided by the user.
    """
    print(f"Parsing {xml_file}...")
    if not os.path.exists(xml_file):
        print(f"Warning: {xml_file} not found. Skipping XML parsing.")
        return pd.DataFrame(columns=['alarm_index', 'alarm_class_ref', 'description_ref'])

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        alarm_data = []
        for alarm in root.findall('alarm'):
            idx = alarm.get('index')
            desc_node = alarm.find('desc')
            class_node = alarm.find('class')

            if idx is not None:
                alarm_data.append({
                    'alarm_index': int(idx),
                    'alarm_class_ref': class_node.text if class_node is not None else "Unknown",
                    'description_ref': desc_node.text if desc_node is not None else "No Description"
                })
        return pd.DataFrame(alarm_data)
    except Exception as e:
        print(f"Error parsing XML: {e}")
        return pd.DataFrame(columns=['alarm_index', 'alarm_class_ref', 'description_ref'])


def process_and_save():
    # 1. Parse XML Descriptions
    df_ref = parse_alarm_xml(XML_INPUT)

    # 2. Process Whitelist (Moved from MMBF Tool)
    print(f"Processing Whitelist: {WHITELIST_INPUT}...")
    df_whitelist = pd.DataFrame(columns=['alarm_index', 'description'])

    if os.path.exists(WHITELIST_INPUT):
        try:
            # Use latin-1 to handle special characters commonly found in RMG logs
            df_white_raw = pd.read_csv(WHITELIST_INPUT, encoding='latin-1')

            # Standardize columns: Expecting 'Code' and 'Description'
            if 'Code' in df_white_raw.columns:
                df_white_raw = df_white_raw.rename(
                    columns={'Code': 'alarm_index', 'Description': 'description'})

                # Clean Data
                df_white_raw['alarm_index'] = pd.to_numeric(
                    df_white_raw['alarm_index'], errors='coerce').fillna(0).astype(int)
                df_white_raw['description'] = df_white_raw['description'].fillna(
                    'No Description')

                df_whitelist = df_white_raw[['alarm_index', 'description']]
                print(
                    f"Successfully processed {len(df_whitelist)} whitelist items.")
        except Exception as e:
            print(f"Error processing Whitelist CSV: {e}")
    else:
        print(
            f"Warning: {WHITELIST_INPUT} not found. Whitelist table will be empty.")

    # 3. Load Raw CSV Logs
    print(f"Loading {CSV_INPUT}...")
    if not os.path.exists(CSV_INPUT):
        print(f"Error: {CSV_INPUT} not found. Aborting.")
        return

    try:
        df_raw = pd.read_csv(CSV_INPUT, encoding='latin-1')
    except Exception as e:
        print(f"Error reading raw CSV: {e}")
        return

    # 4. Filter for RMG fleet (RMG01 - RMG12)
    print("Filtering for RMG fleet...")
    if 'unit_id' in df_raw.columns:
        df_raw = df_raw[df_raw['unit_id'].str.contains(
            r'^RMG(0[1-9]|1[0-2])$', regex=True, na=False)]
    else:
        print("Error: 'unit_id' column not found in CSV.")
        return

    # 5. Cross-Reference with XML descriptions
    print("Merging alarm descriptions...")
    df_final = df_raw.merge(df_ref, on='alarm_index', how='left')

    df_final['description'] = df_final['description_ref'].fillna(
        "Unknown Alarm")
    df_final['alarm_class'] = df_final['alarm_class_ref'].fillna("Unknown")

    columns_to_keep = [
        'unit_id', 'alarm_date', 'alarm_time', 'alarm_index',
        'alarm_class', 'description', 'alarm_state'
    ]
    df_db = df_final[columns_to_keep]

    # 6. Export to DuckDB
    print(f"Building Database: {DB_OUTPUT}...")
    if os.path.exists(DB_OUTPUT):
        try:
            os.remove(DB_OUTPUT)
        except PermissionError:
            print(
                f"Error: {DB_OUTPUT} is currently in use. Please close the MMBF Tool.")
            return

    con = duckdb.connect(DB_OUTPUT)

    # Create Tables
    con.execute("CREATE TABLE alarm_logs AS SELECT * FROM df_db")
    con.execute("CREATE TABLE whitelist AS SELECT * FROM df_whitelist")

    # Metadata tables for User Session Tracking
    con.execute("""
        CREATE TABLE IF NOT EXISTS forensic_metadata (
            unit_id VARCHAR,
            session_start VARCHAR,
            is_mmbf BOOLEAN,
            primary_index INTEGER,
            primary_issue VARCHAR,
            PRIMARY KEY (unit_id, session_start)
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS manual_move_overrides (
            unit_id VARCHAR PRIMARY KEY,
            manual_count INTEGER
        )
    """)

    con.close()
    print("Success! Database built and whitelist imported.")


if __name__ == "__main__":
    process_and_save()
