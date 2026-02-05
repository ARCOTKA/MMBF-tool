import duckdb
import pandas as pd
import os
import io
import base64
import math
import bisect
import logging
from datetime import date
from fpdf import FPDF

# --- LOGGING CONFIGURATION ---
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- CONFIGURATION & CONSTANTS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, 'alarm_logs3.duckdb')
DEFAULT_WHITELIST_PATH = os.path.join(BASE_DIR, 'MMbf_whitelist.csv')

CRANE_LIST = [f'RMG{str(i).zfill(2)}' for i in range(1, 13)]

# Alarm Index Constants
MANUAL_MODE_INDEX = 57011
DEFAULT_MIN_DURATION = 0
TWISTLOCK_LOCKED_INDEX = 5740
TWISTLOCK_UNLOCKED_INDEX = 5741
PAGE_SIZE = 20

# --- HELPER FUNCTIONS (Static) ---


def sanitize_str(text):
    if not isinstance(text, str):
        text = str(text)
    replacements = {'\u2013': '-', '\u2014': '-', '\u2019': "'",
                    '\u201c': '"', '\u201d': '"', '\xae': '(R)'}
    for char, rep in replacements.items():
        text = text.replace(char, rep)
    return text.encode('latin-1', 'ignore').decode('latin-1')


def parse_whitelist_content(content_type, content_string):
    """Parses uploaded CSV content into a list of dicts."""
    try:
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(io.BytesIO(decoded), encoding='latin-1')
        if 'Code' in df.columns:
            df = df.rename(
                columns={'Code': 'alarm_index', 'Description': 'description'})
        df['alarm_index'] = pd.to_numeric(
            df['alarm_index'], errors='coerce').fillna(0).astype(int)
        df['description'] = df['description'].fillna('No Description')
        logging.info("Whitelist parsed successfully from upload.")
        return df[['alarm_index', 'description']].to_dict('records')
    except Exception as e:
        logging.error(f"Parse Whitelist Error: {e}")
        return []


def load_default_whitelist():
    """Loads the default whitelist CSV from disk if it exists."""
    if not os.path.exists(DEFAULT_WHITELIST_PATH):
        logging.warning("Default whitelist file not found.")
        return []
    try:
        df = pd.read_csv(DEFAULT_WHITELIST_PATH, encoding='latin-1')
        if 'Code' in df.columns:
            df = df.rename(
                columns={'Code': 'alarm_index', 'Description': 'description'})
        df['alarm_index'] = pd.to_numeric(
            df['alarm_index'], errors='coerce').fillna(0).astype(int)
        df['description'] = df['description'].fillna('No Description')
        logging.info("Default whitelist loaded.")
        return df[['alarm_index', 'description']].to_dict('records')
    except Exception as e:
        logging.error(f"Error loading default whitelist: {e}")
        return []

# --- FORENSIC ANALYZER CLASS ---


class ForensicAnalyzer:
    def __init__(self, db_path=DEFAULT_DB_PATH, read_only=True):
        self.db_path = db_path
        self.read_only = read_only
        self.con = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        """Establishes the DuckDB connection."""
        if not self.db_path or not os.path.exists(self.db_path):
            logging.error(
                f"Database path invalid or not found: {self.db_path}")
            self.con = None
            return
        try:
            self.con = duckdb.connect(self.db_path, read_only=self.read_only)
            logging.debug(
                f"Connected to DB: {self.db_path} (Read-Only: {self.read_only})")
        except Exception as e:
            logging.error(f"Connection Error ({self.db_path}): {e}")
            self.con = None

    def close(self):
        """Closes the DuckDB connection."""
        if self.con:
            try:
                self.con.close()
                logging.debug("Database connection closed.")
            except Exception as e:
                logging.error(f"Error closing connection: {e}")
            self.con = None

    def init_metadata_tables(self):
        """Initializes user-state tables. Requires read_only=False."""
        if not self.con:
            return
        try:
            self.con.execute("""
                CREATE TABLE IF NOT EXISTS forensic_metadata (
                    unit_id VARCHAR,
                    session_start VARCHAR,
                    is_mmbf BOOLEAN,
                    primary_index INTEGER,
                    primary_issue VARCHAR,
                    PRIMARY KEY (unit_id, session_start)
                )
            """)
            self.con.execute("""
                CREATE TABLE IF NOT EXISTS manual_move_overrides (
                    unit_id VARCHAR PRIMARY KEY,
                    manual_count INTEGER
                )
            """)
            logging.info("Metadata tables initialized/verified.")
        except Exception as e:
            logging.error(f"Table Init Error: {e}")

    def get_db_date_range(self):
        if not self.con:
            return date(2025, 1, 1), date(2025, 12, 31)
        try:
            res = self.con.execute("""
                SELECT MIN(try_cast(alarm_date as DATE)), MAX(try_cast(alarm_date as DATE)) 
                FROM alarm_logs
            """).fetchone()
            if res and res[0] and res[1]:
                return pd.to_datetime(res[0]).date(), pd.to_datetime(res[1]).date()
        except Exception as e:
            logging.error(f"Date Range Fetch Error: {e}")
        return date(2025, 1, 1), date(2025, 12, 31)

    def set_manual_override(self, crane_id, manual_count):
        """Writes a manual move count override to the DB."""
        if not self.con or self.read_only:
            logging.error(
                "Cannot write override: DB is read-only or not connected.")
            return
        try:
            self.con.execute("INSERT OR REPLACE INTO manual_move_overrides (unit_id, manual_count) VALUES (?, ?)",
                             [crane_id, manual_count])
            logging.info(f"Manual override set for {crane_id}: {manual_count}")
        except Exception as e:
            logging.error(f"Error setting manual override: {e}")

    def update_forensic_metadata(self, crane_id, session_start, is_mmbf, p_index, p_issue):
        """Updates the forensic decision (MMBF tag) for a session."""
        if not self.con or self.read_only:
            logging.error(
                "Cannot update metadata: DB is read-only or not connected.")
            return
        try:
            if is_mmbf:
                self.con.execute("INSERT OR REPLACE INTO forensic_metadata (unit_id, session_start, is_mmbf, primary_index, primary_issue) VALUES (?, ?, ?, ?, ?)",
                                 [crane_id, session_start, True, p_index, p_issue])
            else:
                self.con.execute("DELETE FROM forensic_metadata WHERE unit_id ILIKE ? AND session_start = ?",
                                 [crane_id, session_start])
            logging.info(f"Metadata updated for {crane_id} at {session_start}")
        except Exception as e:
            logging.error(f"Error updating forensic metadata: {e}")

    def get_refined_move_count(self, crane_id, start_date, end_date):
        if not self.con:
            return 0
        try:
            # Check for override first
            try:
                res = self.con.execute(
                    "SELECT manual_count FROM manual_move_overrides WHERE UPPER(unit_id) = UPPER(?)", [crane_id]).fetchone()
                if res is not None:
                    return res[0]
            except:
                pass  # Table might not exist or other error, fallback to calc

            # Calculate from logs
            query = f"""
            SELECT alarm_index, UPPER(alarm_state) as state
            FROM alarm_logs
            WHERE unit_id ILIKE ? 
            AND (alarm_date || ' ' || alarm_time)::TIMESTAMP >= '{start_date} 00:00:00'
            AND (alarm_date || ' ' || alarm_time)::TIMESTAMP <= '{end_date} 23:59:59'
            AND alarm_index IN ({TWISTLOCK_LOCKED_INDEX}, {TWISTLOCK_UNLOCKED_INDEX})
            ORDER BY (alarm_date || ' ' || alarm_time)::TIMESTAMP ASC
            """
            auto_count = 0
            df = self.con.execute(query, [crane_id]).df()
            if not df.empty:
                is_carrying = False
                for idx, state in zip(df['alarm_index'], df['state']):
                    if idx == TWISTLOCK_LOCKED_INDEX and 'ON' in state:
                        is_carrying = True
                    elif idx == TWISTLOCK_UNLOCKED_INDEX and 'ON' in state and is_carrying:
                        auto_count += 1
                        is_carrying = False
            return auto_count
        except Exception as e:
            logging.error(f"Move Calculation Error: {e}")
            return 0

    def get_maintenance_sessions(self, crane_id, start_date, end_date, whitelist_indices, min_duration=DEFAULT_MIN_DURATION):
        if not self.con:
            return pd.DataFrame(), {}
        try:
            query = """
                SELECT alarm_index, description, alarm_class, alarm_state,
                (alarm_date || ' ' || alarm_time)::TIMESTAMP as ts
                FROM alarm_logs
                WHERE unit_id ILIKE ?
                ORDER BY ts ASC
            """
            df = self.con.execute(query, [crane_id]).df()

            try:
                meta_df = self.con.execute(
                    "SELECT * FROM forensic_metadata WHERE unit_id ILIKE ?", [crane_id]).df()
            except:
                meta_df = pd.DataFrame()

            if df.empty:
                return pd.DataFrame(), {}

            df_manual = df[df['alarm_index'] == MANUAL_MODE_INDEX].copy()
            windows = []
            current_start = None
            range_start_ts = pd.Timestamp(f"{start_date} 00:00:00")
            range_end_ts = pd.Timestamp(f"{end_date} 23:59:59")

            for row in df_manual.itertuples():
                state = str(row.alarm_state).upper()
                ts = row.ts
                if 'ON' in state and current_start is None:
                    current_start = ts
                elif 'OFF' in state and current_start is not None:
                    if ts >= range_start_ts and ts <= range_end_ts:
                        dur = (ts - current_start).total_seconds() / 60
                        if dur >= min_duration:
                            windows.append(
                                {'start': current_start, 'end': ts, 'duration': round(dur, 2)})
                    current_start = None

            sessions = []
            details_map = {}
            df_faults = df[df['alarm_index'] != MANUAL_MODE_INDEX].copy()

            for i, w in enumerate(windows):
                sid = i + 1
                w_start, w_end = w['start'], w['end']
                in_window_mask = (df_faults['ts'] >= w_start) & (df_faults['ts'] <= w_end) & (
                    df_faults['alarm_state'].str.contains('OFF', case=False, na=False))
                candidates = df_faults[in_window_mask]
                qualified_faults = []

                for cand in candidates.itertuples():
                    idx = cand.alarm_index
                    off_ts = cand.ts
                    alarm_history = df_faults[df_faults['alarm_index'] == idx]
                    prior_on_mask = (alarm_history['ts'] < off_ts) & (
                        alarm_history['alarm_state'].str.contains('ON', case=False, na=False))
                    prior_on_events = alarm_history[prior_on_mask]

                    if not prior_on_events.empty:
                        last_on_ts = prior_on_events.iloc[-1]['ts']
                        if last_on_ts < w_start:
                            fault_dur = (
                                off_ts - last_on_ts).total_seconds() / 60
                            qualified_faults.append({
                                'description': cand.description,
                                'alarm_index': int(idx),
                                'alarm_class': cand.alarm_class,
                                'total_duration_mins': round(fault_dur, 2),
                                'first_occurrence': last_on_ts,
                                'resolution_time': off_ts,
                                'mmbf_tick': False,
                                'is_whitelisted': 'True' if int(idx) in whitelist_indices else 'False'
                            })

                w_start_str = w_start.strftime('%Y-%m-%d %H:%M:%S')
                saved = meta_df[meta_df['session_start'] ==
                                w_start_str] if not meta_df.empty else pd.DataFrame()

                summary = []
                if qualified_faults:
                    df_q = pd.DataFrame(qualified_faults)
                    for desc, grp in df_q.groupby('description'):
                        f_grp = grp
                        first_idx = int(f_grp['alarm_index'].iloc[0])
                        is_ticked = False
                        if not saved.empty:
                            if saved.iloc[0]['is_mmbf'] and saved.iloc[0]['primary_issue'] == desc:
                                is_ticked = True
                        res_time = f_grp.sort_values(
                            'resolution_time', ascending=False).iloc[0]['resolution_time']
                        first_occ = f_grp['first_occurrence'].min()
                        summary.append({
                            'description': desc,
                            'alarm_index': first_idx,
                            'alarm_class': f_grp['alarm_class'].iloc[0],
                            'occurrence_count': len(f_grp),
                            'total_duration_mins': f_grp['total_duration_mins'].sum(),
                            'first_occurrence': first_occ.strftime('%Y-%m-%d %H:%M:%S'),
                            'resolution_time': res_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'mmbf_tick': is_ticked,
                            'is_whitelisted': 'True' if first_idx in whitelist_indices else 'False',
                            'raw_start_ts': first_occ
                        })

                if summary:
                    df_sum = pd.DataFrame(summary).sort_values('raw_start_ts')
                    if not saved.empty:
                        mmbf_tag = 'Yes' if saved.iloc[0]['is_mmbf'] else 'No'
                        p_issue = saved.iloc[0]['primary_issue']
                        p_index = saved.iloc[0]['primary_index']
                    else:
                        mmbf_tag = 'No'
                        p_issue = df_sum.iloc[0]['description']
                        p_index = df_sum.iloc[0]['alarm_index']
                    sessions.append({
                        'session_id': sid, 'start_timestamp': w_start_str, 'end_timestamp': w_end.strftime('%Y-%m-%d %H:%M:%S'),
                        'session_duration_mins': w['duration'], 'primary_index': p_index, 'primary_issue': p_issue,
                        'mmbf_tag': mmbf_tag, 'is_whitelisted': 'True' if int(p_index) in whitelist_indices else 'False'
                    })
                    df_sum = df_sum.drop(columns=['raw_start_ts'])
                    details_map[str(sid)] = df_sum.to_dict('records')
                else:
                    sessions.append({
                        'session_id': sid, 'start_timestamp': w_start_str, 'end_timestamp': w_end.strftime('%Y-%m-%d %H:%M:%S'),
                        'session_duration_mins': w['duration'], 'primary_index': 0, 'primary_issue': "No Pre-Existing Fault Resolved",
                        'mmbf_tag': 'No', 'is_whitelisted': 'False'
                    })

            return pd.DataFrame(sessions), details_map

        except Exception as e:
            logging.error(f"Session Analysis Error: {e}")
            return pd.DataFrame(), {}

    def get_transient_faults(self, crane_id, start_date, end_date, whitelist_indices, only_whitelist=False):
        if not self.con:
            return pd.DataFrame(), pd.DataFrame()

        try:
            manual_query = """
                SELECT (alarm_date || ' ' || alarm_time)::TIMESTAMP as ts, UPPER(alarm_state) as state
                FROM alarm_logs
                WHERE unit_id ILIKE ? AND alarm_index = 57011
                AND (alarm_date || ' ' || alarm_time)::TIMESTAMP BETWEEN ? AND ?
                ORDER BY ts
            """
            start_ts_str = f"{start_date} 00:00:00"
            end_ts_str = f"{end_date} 23:59:59"

            manual_df = self.con.execute(
                manual_query, [crane_id, start_ts_str, end_ts_str]).df()

            manual_intervals = []
            current_start = None
            for row in manual_df.itertuples():
                if 'ON' in row.state and current_start is None:
                    current_start = row.ts
                elif 'OFF' in row.state and current_start is not None:
                    manual_intervals.append((current_start, row.ts))
                    current_start = None

            wl_clause = ""
            if only_whitelist and whitelist_indices:
                wl_ids = ", ".join(map(str, whitelist_indices))
                wl_clause = f"AND alarm_index IN ({wl_ids})"
            elif only_whitelist and not whitelist_indices:
                return pd.DataFrame(), pd.DataFrame()

            fault_query = f"""
                WITH raw_events AS (
                    SELECT 
                        alarm_index, description, alarm_class, alarm_state,
                        (alarm_date || ' ' || alarm_time)::TIMESTAMP as ts
                    FROM alarm_logs
                    WHERE unit_id ILIKE ? AND alarm_index != 57011
                    AND (alarm_date || ' ' || alarm_time)::TIMESTAMP BETWEEN ? AND ?
                    {wl_clause}
                ),
                paired_events AS (
                    SELECT
                        alarm_index, description, alarm_class, ts as start_ts, UPPER(alarm_state) as state,
                        LEAD(ts) OVER (PARTITION BY alarm_index ORDER BY ts) as end_ts,
                        LEAD(UPPER(alarm_state)) OVER (PARTITION BY alarm_index ORDER BY ts) as next_state
                    FROM raw_events
                )
                SELECT * FROM paired_events WHERE state LIKE '%ON%'
            """

            faults_df = self.con.execute(
                fault_query, [crane_id, start_ts_str, end_ts_str]).df()

            if faults_df.empty:
                return pd.DataFrame(), pd.DataFrame()

            man_starts = [x[0] for x in manual_intervals]
            man_ends = [x[1] for x in manual_intervals]

            transient_faults = []

            for row in faults_df.itertuples():
                f_start = row.start_ts
                idx = bisect.bisect_right(man_starts, f_start) - 1
                is_manual = False

                if idx >= 0:
                    if f_start < man_ends[idx]:
                        is_manual = True

                if not is_manual and (idx + 1) < len(man_starts):
                    if row.end_ts and row.end_ts > man_starts[idx + 1]:
                        is_manual = True

                if not is_manual:
                    duration_sec = 0.0
                    if row.next_state and 'OFF' in row.next_state and row.end_ts:
                        duration_sec = (row.end_ts - f_start).total_seconds()
                        if duration_sec < 0:
                            duration_sec = 0

                    transient_faults.append({
                        'alarm_index': row.alarm_index,
                        'description': row.description,
                        'start_ts': f_start,
                        'duration_sec': duration_sec,
                        'is_whitelisted': 'True' if int(row.alarm_index) in whitelist_indices else 'False'
                    })

            if not transient_faults:
                return pd.DataFrame(), pd.DataFrame()

            df_trans = pd.DataFrame(transient_faults)
            summary_rows = []
            for (idx, desc), grp in df_trans.groupby(['alarm_index', 'description']):
                freq = len(grp)
                total_dur = grp['duration_sec'].sum()
                avg_dur = total_dur / freq if freq > 0 else 0

                grp_time = grp.set_index('start_ts')
                if not grp_time.empty:
                    hourly_counts = grp_time.resample('h').size()
                    if not hourly_counts.empty:
                        peak_hour_ts = hourly_counts.idxmax()
                        peak_count = hourly_counts.max()
                        peak_str = f"{peak_hour_ts.strftime('%Y-%m-%d %H:00')} ({peak_count} events)"
                    else:
                        peak_str = "N/A"
                else:
                    peak_str = "N/A"

                summary_rows.append({
                    'alarm_index': idx,
                    'description': desc,
                    'frequency': freq,
                    'avg_duration_sec': round(avg_dur, 3),
                    'total_duration_sec': round(total_dur, 2),
                    'peak_activity': peak_str,
                    'is_whitelisted': grp['is_whitelisted'].iloc[0]
                })

            summary_df = pd.DataFrame(summary_rows).sort_values(
                'frequency', ascending=False)
            return summary_df, df_trans

        except Exception as e:
            logging.error(f"Transient Analysis Error: {e}")
            return pd.DataFrame(), pd.DataFrame()

    def get_explorer_logs(self, crane_id, start_date, end_date, index_filter, desc_filter, whitelist_indices, only_whitelist=False):
        if not self.con:
            return pd.DataFrame()

        query = f"""
            SELECT unit_id, alarm_date, alarm_time, alarm_index, alarm_class, description, alarm_state,
            (alarm_date || ' ' || alarm_time)::TIMESTAMP as full_ts
            FROM alarm_logs 
            WHERE unit_id ILIKE ? 
            AND (alarm_date || ' ' || alarm_time)::TIMESTAMP >= '{start_date} 00:00:00'
            AND (alarm_date || ' ' || alarm_time)::TIMESTAMP <= '{end_date} 23:59:59'
        """
        params = [crane_id]

        if only_whitelist and whitelist_indices:
            wl_str = ", ".join(map(str, whitelist_indices))
            query += f" AND alarm_index IN ({wl_str})"
        elif only_whitelist:
            return pd.DataFrame()

        if index_filter:
            query += " AND CAST(alarm_index AS VARCHAR) LIKE ?"
            params.append(f"%{index_filter}%")
        if desc_filter:
            query += " AND description ILIKE ?"
            params.append(f"%{desc_filter}%")

        query += " ORDER BY (alarm_date || ' ' || alarm_time)::TIMESTAMP DESC"

        try:
            df = self.con.execute(query, params).df()
            df['is_whitelisted'] = df['alarm_index'].apply(
                lambda x: 'True' if int(x) in whitelist_indices else 'False')
            return df
        except Exception as e:
            logging.error(f"Explorer Error: {e}")
            return pd.DataFrame()

# --- REPORT GENERATOR (Static) ---


def generate_pdf_report_bytes(session_data, details_data, crane_id, total_moves, start_date, end_date, mmbf_val):
    if not session_data:
        return None

    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"MMBF Tool Forensic Report - {crane_id}", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, f"Period: {start_date} to {end_date}", ln=True)
        pdf.cell(
            0, 7, f"Total Moves: {total_moves} | Failures per 1000 Moves: {mmbf_val}", ln=True)
        pdf.ln(10)

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 10, "1. Executive Summary of Maintenance Sessions", ln=True)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(220, 38, 38)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(8, 8, "ID", 1, 0, 'C', True)
        pdf.cell(35, 8, "Start", 1, 0, 'C', True)
        pdf.cell(35, 8, "End", 1, 0, 'C', True)
        pdf.cell(12, 8, "Dur", 1, 0, 'C', True)
        pdf.cell(12, 8, "Idx", 1, 0, 'C', True)
        pdf.cell(78, 8, "Primary Issue", 1, 0, 'C', True)
        pdf.cell(10, 8, "MMBF", 1, 1, 'C', True)

        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(0, 0, 0)
        HIGHLIGHT_COLOR = (255, 230, 230)

        for row in session_data:
            is_mmbf = str(row['mmbf_tag']) == 'Yes'
            fill = True if is_mmbf else False
            if is_mmbf:
                pdf.set_fill_color(*HIGHLIGHT_COLOR)
            pdf.cell(8, 7, str(row['session_id']), 1, 0, 'C', fill)
            pdf.cell(35, 7, str(row['start_timestamp']), 1, 0, 'C', fill)
            pdf.cell(35, 7, str(row['end_timestamp']), 1, 0, 'C', fill)
            pdf.cell(12, 7, str(row['session_duration_mins']), 1, 0, 'C', fill)
            pdf.cell(12, 7, str(row['primary_index']), 1, 0, 'C', fill)
            pdf.cell(78, 7, sanitize_str(
                str(row['primary_issue'])[:60]), 1, 0, 'L', fill)
            pdf.cell(10, 7, str(row['mmbf_tag']), 1, 1, 'C', fill)

        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "2. Detailed Session Fault Analysis", ln=True)
        pdf.ln(5)

        for row in session_data:
            sid = str(row['session_id'])
            if pdf.get_y() > 250:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(
                0, 8, f"Session {sid} Breakdown | Started: {row['start_timestamp']} | Duration: {row['session_duration_mins']} mins", 1, 1, 'L', True)

            faults = details_data.get(sid, [])
            if faults:
                pdf.set_font("Helvetica", "B", 7)
                pdf.set_fill_color(220, 220, 220)
                pdf.cell(35, 6, "Start", 1, 0, 'C', True)
                pdf.cell(35, 6, "End", 1, 0, 'C', True)
                pdf.cell(12, 6, "Idx", 1, 0, 'C', True)
                pdf.cell(12, 6, "Cls", 1, 0, 'C', True)
                pdf.cell(70, 6, "Fault", 1, 0, 'C', True)
                pdf.cell(15, 6, "Dur", 1, 1, 'C', True)
                pdf.set_font("Helvetica", "", 7)
                for f in faults:
                    is_this_mmbf = f.get('mmbf_tick', False)
                    fill = True if is_this_mmbf else False
                    if is_this_mmbf:
                        pdf.set_fill_color(*HIGHLIGHT_COLOR)
                    if pdf.get_y() > 275:
                        pdf.add_page()
                    pdf.cell(35, 6, str(f.get('first_occurrence', '')),
                             1, 0, 'C', fill)
                    pdf.cell(35, 6, str(f.get('resolution_time', '')),
                             1, 0, 'C', fill)
                    pdf.cell(12, 6, str(f['alarm_index']), 1, 0, 'C', fill)
                    pdf.cell(12, 6, str(f['alarm_class']), 1, 0, 'C', fill)
                    pdf.cell(70, 6, sanitize_str(
                        str(f['description'])[:65]), 1, 0, 'L', fill)
                    pdf.cell(15, 6, str(
                        f['total_duration_mins']), 1, 1, 'C', fill)
            else:
                pdf.set_font("Helvetica", "I", 7)
                pdf.cell(
                    0, 6, "No specific fault events identified during this window.", 1, 1)
            pdf.ln(6)

        return pdf.output(dest='S').encode('latin-1')
    except Exception as e:
        logging.error(f"PDF Generation Error: {e}")
        return None
