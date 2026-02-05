"""
Forensic analysis tool for RMG Fleet (RMG01 - RMG12) maintenance logs.
Version: 9.6 - Features: Insights Tab (Individual Toggles), Predictive Storm Tracking, Forensic Audit (Strict Logic)
"""

import io
import base64
import duckdb
import pandas as pd
import plotly.express as px
import dash
from dash import dcc, html, dash_table, Input, Output, State, callback_context
from fpdf import FPDF
import os
from datetime import date, timedelta
import math
import bisect

# --- CONFIGURATION (DEFAULTS) ---
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

# --- HELPER FUNCTIONS ---


def parse_whitelist_content(content_type, content_string):
    """Parses uploaded CSV content into a dataframe."""
    try:
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(io.BytesIO(decoded), encoding='latin-1')
        if 'Code' in df.columns:
            df = df.rename(
                columns={'Code': 'alarm_index', 'Description': 'description'})
        df['alarm_index'] = pd.to_numeric(
            df['alarm_index'], errors='coerce').fillna(0).astype(int)
        df['description'] = df['description'].fillna('No Description')
        return df[['alarm_index', 'description']].to_dict('records')
    except Exception as e:
        print(f"[ERROR] Parse Whitelist Error: {e}")
        return []


def load_default_whitelist():
    """Loads the default whitelist CSV from disk if it exists."""
    if not os.path.exists(DEFAULT_WHITELIST_PATH):
        return []
    try:
        df = pd.read_csv(DEFAULT_WHITELIST_PATH, encoding='latin-1')
        if 'Code' in df.columns:
            df = df.rename(
                columns={'Code': 'alarm_index', 'Description': 'description'})
        df['alarm_index'] = pd.to_numeric(
            df['alarm_index'], errors='coerce').fillna(0).astype(int)
        df['description'] = df['description'].fillna('No Description')
        return df[['alarm_index', 'description']].to_dict('records')
    except:
        return []


def get_db_con(db_path, read_only=True):
    """Returns a DuckDB connection to the specified path."""
    if not db_path or not os.path.exists(db_path):
        return None
    try:
        return duckdb.connect(db_path, read_only=read_only)
    except Exception as e:
        print(f"[DEBUG] Connection Error ({db_path}): {e}")
        return None


def init_metadata_tables(db_path):
    """Initializes user-state tables on the active database."""
    con = get_db_con(db_path, read_only=False)
    if not con:
        return
    try:
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
    except Exception as e:
        print(f"[DEBUG] Table Init Error: {e}")
    finally:
        if con:
            con.close()


def get_db_date_range(db_path):
    con = get_db_con(db_path)
    if not con:
        return date(2025, 1, 1), date(2025, 12, 31)
    try:
        res = con.execute("""
            SELECT MIN(try_cast(alarm_date as DATE)), MAX(try_cast(alarm_date as DATE)) 
            FROM alarm_logs
        """).fetchone()
        if res and res[0] and res[1]:
            return pd.to_datetime(res[0]).date(), pd.to_datetime(res[1]).date()
    except Exception as e:
        print(f"[DEBUG] Date Range Fetch Error: {e}")
    finally:
        if con:
            con.close()
    return date(2025, 1, 1), date(2025, 12, 31)


def sanitize_str(text):
    if not isinstance(text, str):
        text = str(text)
    replacements = {'\u2013': '-', '\u2014': '-', '\u2019': "'",
                    '\u201c': '"', '\u201d': '"', '\xae': '(R)'}
    for char, rep in replacements.items():
        text = text.replace(char, rep)
    return text.encode('latin-1', 'ignore').decode('latin-1')

# --- CORE LOGIC: FORENSIC ---


def get_refined_move_count(crane_id, start_date, end_date, db_path):
    con = get_db_con(db_path)
    if not con:
        return 0
    try:
        res = con.execute("SELECT manual_count FROM manual_move_overrides WHERE UPPER(unit_id) = UPPER(?)", [
                          crane_id]).fetchone()
        if res is not None:
            con.close()
            return res[0]
    except:
        pass

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
    try:
        df = con.execute(query, [crane_id]).df()
        if not df.empty:
            is_carrying = False
            for idx, state in zip(df['alarm_index'], df['state']):
                if idx == TWISTLOCK_LOCKED_INDEX and 'ON' in state:
                    is_carrying = True
                elif idx == TWISTLOCK_UNLOCKED_INDEX and 'ON' in state and is_carrying:
                    auto_count += 1
                    is_carrying = False
    except Exception as e:
        print(f"[DEBUG] Move Calculation Error: {e}")
    finally:
        if con:
            con.close()
    return auto_count


def get_maintenance_sessions(crane_id, start_date, end_date, db_path, whitelist_indices, min_duration=DEFAULT_MIN_DURATION):
    # (Same implementation as previous version - kept for stability)
    con = get_db_con(db_path)
    if not con:
        return pd.DataFrame(), {}
    try:
        query = """
            SELECT alarm_index, description, alarm_class, alarm_state,
            (alarm_date || ' ' || alarm_time)::TIMESTAMP as ts
            FROM alarm_logs
            WHERE unit_id ILIKE ?
            ORDER BY ts ASC
        """
        df = con.execute(query, [crane_id]).df()
        try:
            meta_df = con.execute(
                "SELECT * FROM forensic_metadata WHERE unit_id ILIKE ?", [crane_id]).df()
        except:
            meta_df = pd.DataFrame()
        con.close()

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
                        fault_dur = (off_ts - last_on_ts).total_seconds() / 60
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

            # REMOVED: Lookback Strategy block has been removed as requested.

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
        print(f"[DEBUG] Session Analysis Error: {e}")
        return pd.DataFrame(), {}

# --- CORE LOGIC: PREDICTIVE / TRANSIENT ---


def get_transient_faults(crane_id, start_date, end_date, db_path, whitelist_indices, only_whitelist=False):
    """
    Identifies faults that turn ON and OFF without a Manual Mode intervention.
    Designed for high-performance 'Chatter' detection.
    """
    con = get_db_con(db_path)
    if not con:
        return pd.DataFrame(), pd.DataFrame()

    try:
        # 1. Get Manual Mode (57011) Windows
        manual_query = """
            SELECT (alarm_date || ' ' || alarm_time)::TIMESTAMP as ts, UPPER(alarm_state) as state
            FROM alarm_logs
            WHERE unit_id ILIKE ? AND alarm_index = 57011
            AND (alarm_date || ' ' || alarm_time)::TIMESTAMP BETWEEN ? AND ?
            ORDER BY ts
        """
        start_ts_str = f"{start_date} 00:00:00"
        end_ts_str = f"{end_date} 23:59:59"

        manual_df = con.execute(
            manual_query, [crane_id, start_ts_str, end_ts_str]).df()

        # Build Manual Intervals List [(start, end), ...]
        manual_intervals = []
        current_start = None
        for row in manual_df.itertuples():
            if 'ON' in row.state and current_start is None:
                current_start = row.ts
            elif 'OFF' in row.state and current_start is not None:
                manual_intervals.append((current_start, row.ts))
                current_start = None

        # 2. Get All Fault ON/OFF Events
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

        faults_df = con.execute(
            fault_query, [crane_id, start_ts_str, end_ts_str]).df()
        con.close()

        if faults_df.empty:
            return pd.DataFrame(), pd.DataFrame()

        # 3. Filter out faults that occurred during Manual Mode
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

        # 4. Aggregation for Summary Table
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
        print(f"[DEBUG] Transient Analysis Error: {e}")
        if con:
            con.close()
        return pd.DataFrame(), pd.DataFrame()


def get_explorer_logs(crane_id, start_date, end_date, index_filter, desc_filter, db_path, whitelist_indices, only_whitelist=False):
    con = get_db_con(db_path)
    if not con:
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
        con.close()
        return pd.DataFrame()

    if index_filter:
        query += " AND CAST(alarm_index AS VARCHAR) LIKE ?"
        params.append(f"%{index_filter}%")
    if desc_filter:
        query += " AND description ILIKE ?"
        params.append(f"%{desc_filter}%")

    query += " ORDER BY (alarm_date || ' ' || alarm_time)::TIMESTAMP DESC"

    try:
        df = con.execute(query, params).df()
        df['is_whitelisted'] = df['alarm_index'].apply(
            lambda x: 'True' if int(x) in whitelist_indices else 'False')
        con.close()
        return df
    except Exception as e:
        print(f"[DEBUG] Explorer Error: {e}")
        if con:
            con.close()
        return pd.DataFrame()


# --- DASHBOARD UI ---
app = dash.Dash(__name__, title="MMBF Tool")

upload_btn_style = {
    'display': 'inline-block', 'width': '140px', 'padding': '8px', 'lineHeight': '16px',
    'border': '1px solid #475569', 'borderRadius': '4px', 'textAlign': 'center', 'cursor': 'pointer',
    'backgroundColor': '#334155', 'color': '#f1f5f9', 'fontSize': '12px', 'fontWeight': '600',
    'margin': '0 5px', 'boxShadow': '0 1px 2px rgba(0,0,0,0.2)'
}

app.layout = html.Div(style={'fontFamily': 'Segoe UI, Arial', 'backgroundColor': '#f4f7f9', 'minHeight': '100vh'}, children=[
    dcc.Store(id='session-store'),
    dcc.Store(id='details-store'),
    dcc.Store(id='moves-store'),
    dcc.Store(id='transient-raw-store'),
    dcc.Store(id='current-db-path', data=DEFAULT_DB_PATH),
    dcc.Store(id='whitelist-data-store', data=load_default_whitelist()),
    dcc.Store(id='target-session-store'),

    # Header
    html.Div(style={'backgroundColor': '#1e293b', 'padding': '20px', 'color': 'white', 'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center'}, children=[
        html.Div([
            html.H1("MMBF Tool", style={
                    'margin': '0', 'fontSize': '28px', 'fontWeight': 'bold'}),
            html.P("Validated Forensic Logic - Asset Analysis Period",
                   style={'margin': '5px 0 0 0', 'opacity': '0.8'})
        ]),
        html.Div(style={'display': 'flex', 'gap': '10px', 'alignItems': 'center'}, children=[
            html.Div(style={'display': 'flex', 'flexDirection': 'column', 'alignItems': 'flex-end', 'marginRight': '20px'}, children=[
                html.Label("Configuration Source", style={
                           'fontSize': '10px', 'color': '#94a3b8', 'fontWeight': 'bold', 'marginBottom': '4px'}),
                html.Div(style={'display': 'flex'}, children=[
                    dcc.Upload(id='upload-db', children=html.Div(
                        ["📁 Select DB File"]), style=upload_btn_style, multiple=False),
                    dcc.Upload(id='upload-whitelist', children=html.Div(
                        ["📋 Select Whitelist"]), style=upload_btn_style, multiple=False)
                ]),
                html.Div(id='config-status', children="Default Configuration Loaded", style={
                         'fontSize': '10px', 'color': '#64748b', 'marginTop': '5px', 'fontStyle': 'italic'})
            ]),
            html.Div([
                html.Label("Analysis Period:", style={
                           'fontSize': '12px', 'color': '#94a3b8', 'display': 'block'}),
                html.Div(style={'backgroundColor': 'white', 'borderRadius': '4px', 'overflow': 'hidden'}, children=[
                    dcc.DatePickerRange(
                        id='date-picker', style={'fontSize': '12px', 'border': 'none'},
                        start_date_placeholder_text="Start", end_date_placeholder_text="End", clearable=False
                    )
                ])
            ]),
            html.Div([html.Label("Asset Identifier:", style={'fontSize': '12px', 'color': '#94a3b8', 'display': 'block'}),
                      dcc.Dropdown(id='crane-selector', options=[{'label': c, 'value': c} for c in CRANE_LIST], value='RMG05', clearable=False, style={'width': '120px', 'color': '#1e293b'})]),
            html.Div([html.Label("Min Duration (min):", style={'fontSize': '12px', 'color': '#94a3b8', 'display': 'block'}),
                      dcc.Input(id='min-duration-input', type='number', value=0, min=0, step=1, style={'width': '100px', 'color': '#1e293b', 'borderRadius': '4px', 'border': 'none', 'padding': '4px'})])
        ])
    ]),

    dcc.Tabs(id="tabs-main", value='tab-audit', children=[
        # TAB 1: FORENSIC AUDIT
        dcc.Tab(label='Forensic Audit', value='tab-audit', children=[
            dcc.Loading(id="loading-audit", type="default", color="#1e293b", children=html.Div(style={'minHeight': '600px'}, children=[
                html.Div(style={'display': 'flex', 'gap': '15px', 'padding': '20px', 'alignItems': 'flex-end'}, children=[
                    html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '15px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'}, children=[
                        html.Label("Total Moves", style={'color': '#64748b', 'fontSize': '12px'}), html.H2(id='kpi-moves-val', style={'margin': '5px 0', 'color': '#0f172a'})]),
                    html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '15px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'}, children=[html.Label(
                        "Failures per 1000 Moves", style={'color': '#64748b', 'fontSize': '12px'}), html.H2(id='mmbf-value', children="N/A", style={'margin': '5px 0', 'color': '#e11d48'})]),
                    html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '15px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'}, children=[html.Label(
                        "MMBF Fault Count", style={'color': '#64748b', 'fontSize': '12px'}), html.H2(id='kpi-mmbf-count', children="0", style={'margin': '5px 0', 'color': '#2563eb'})]),
                    html.Div(style={'backgroundColor': 'white', 'padding': '15px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'display': 'flex', 'gap': '10px', 'alignItems': 'center'}, children=[
                        html.Div([html.Label("Set Total Moves (Global):", style={'fontSize': '12px', 'display': 'block'}), dcc.Input(
                            id='manual-move-input', type='number', placeholder='Fixed Total...', style={'width': '110px', 'padding': '5px'})]),
                        html.Button("Set Total", id="save-moves-btn", style={'backgroundColor': '#2563eb', 'color': 'white',
                                    'border': 'none', 'padding': '8px 15px', 'borderRadius': '5px', 'cursor': 'pointer', 'marginTop': '15px'})
                    ]),
                    html.Button("PDF Report", id="pdf-btn", style={'backgroundColor': '#0f172a', 'color': 'white',
                                'border': 'none', 'padding': '15px 25px', 'borderRadius': '6px', 'cursor': 'pointer'})
                ]),
                html.Div(style={'padding': '0 20px'}, children=[dcc.Graph(
                    id='main-trend-graph', style={'height': '200px'})]),
                html.Div(style={'padding': '20px', 'display': 'flex', 'flexDirection': 'column', 'gap': '25px'}, children=[
                    html.Div([html.H3("1. Executive Summary of Maintenance Sessions", style={'color': '#1e293b', 'marginBottom': '10px'}),
                              dash_table.DataTable(id='session-table', sort_action="native", filter_action="native", row_selectable="single", page_size=10, style_header={'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'}, style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '10px'}, style_data_conditional=[{'if': {'column_id': 'mmbf_tag', 'filter_query': '{mmbf_tag} eq "Yes"'}, 'backgroundColor': '#fee2e2', 'color': '#b91c1c', 'fontWeight': 'bold'}])]),
                    html.Div([
                        html.Div([
                             html.H3("2. Internal Fault Analysis (Session Focused)", style={
                                     'color': '#1e293b', 'display': 'inline-block', 'marginRight': '20px'}),
                             html.Div([
                                 html.Label("Filter:", style={
                                            'fontWeight': 'bold', 'marginRight': '10px', 'fontSize': '12px'}),
                                 dcc.RadioItems(id='detail-view-mode', options=[{'label': ' All Faults', 'value': 'ALL'}, {
                                                'label': ' Whitelist Only', 'value': 'WL'}], value='ALL', inline=True, style={'display': 'inline-block', 'fontSize': '12px'})
                             ], style={'display': 'inline-block', 'verticalAlign': 'middle'})
                             ], style={'marginBottom': '10px'}),
                        dash_table.DataTable(id='detail-table', sort_action="native", filter_action="native", editable=True, page_size=10, style_header={'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'}, style_cell={
                                             'textAlign': 'left', 'fontSize': '11px', 'padding': '10px'}, dropdown={'mmbf_tick': {'options': [{'label': 'YES', 'value': True}, {'label': 'NO', 'value': False}]}})
                    ])
                ])
            ]))
        ]),

        # TAB 2: INSIGHTS (Formerly Transient)
        dcc.Tab(label='Insights & Predictive', value='tab-insights', children=[
            dcc.Loading(id="loading-transient", type="default", color="#1e293b", children=html.Div(style={'padding': '20px', 'minHeight': '800px'}, children=[

                # --- NEW INSIGHTS SECTION (Actionable Tables) ---
                html.Div(style={'marginBottom': '30px'}, children=[
                    html.H2("Maintenance Strategy Insights", style={
                            'color': '#1e293b', 'marginTop': 0}),
                    html.Div(style={'display': 'flex', 'gap': '20px'}, children=[
                        # Table 1: Nuisance Alarms (High Frequency, Zero Stops)
                        html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'}, children=[
                            html.H3("⚠️ Nuisance Alarms (High Chatter, No Stops)", style={
                                    'fontSize': '16px', 'fontWeight': 'bold', 'color': '#d97706'}),
                            html.P("Frequent alarms that almost never result in maintenance.", style={
                                   'fontSize': '12px', 'color': '#64748b'}),

                            # NEW: Nuisance Toggle
                            html.Div(style={'marginBottom': '10px'}, children=[
                                html.Label("Filter:", style={
                                           'fontSize': '12px', 'fontWeight': 'bold', 'marginRight': '5px'}),
                                dcc.RadioItems(id='nuisance-scope-toggle',
                                               options=[{'label': ' All', 'value': 'ALL'}, {
                                                   'label': ' Whitelist', 'value': 'WL'}],
                                               value='WL', inline=True, style={'fontSize': '12px', 'display': 'inline-block'})
                            ]),

                            dash_table.DataTable(
                                id='nuisance-table',
                                sort_action="native",
                                page_size=10,
                                style_header={
                                    'backgroundColor': '#f59e0b', 'color': 'white', 'fontWeight': 'bold'},
                                style_cell={'textAlign': 'left', 'fontSize': '11px',
                                            'padding': '8px', 'whiteSpace': 'normal', 'height': 'auto'},
                                style_data_conditional=[
                                    {
                                        'if': {'filter_query': '{is_whitelisted} eq "True"'},
                                        'fontWeight': 'bold',
                                        'fontStyle': 'italic',
                                        'color': '#0369a1'
                                    }
                                ],
                                columns=[
                                    {"name": "Idx", "id": "alarm_index"},
                                    {"name": "Description", "id": "description"},
                                    {"name": "Freq", "id": "frequency"},
                                    {"name": "Avg Clear Time (sec)",
                                     "id": "avg_duration_sec"}
                                ]
                            )
                        ]),
                        # Table 2: Critical Failures (Major Stops)
                        html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)'}, children=[
                            html.H3("🛑 Critical Failures (Major Stops)", style={
                                    'fontSize': '16px', 'fontWeight': 'bold', 'color': '#dc2626'}),
                            html.P("Top faults that certainly result in downtime (From Internal Fault Analysis).", style={
                                   'fontSize': '12px', 'color': '#64748b'}),

                            # NEW: Critical Toggle
                            html.Div(style={'marginBottom': '10px'}, children=[
                                html.Label("Filter:", style={
                                           'fontSize': '12px', 'fontWeight': 'bold', 'marginRight': '5px'}),
                                dcc.RadioItems(id='critical-scope-toggle',
                                               options=[{'label': ' All', 'value': 'ALL'}, {
                                                   'label': ' Whitelist', 'value': 'WL'}],
                                               value='WL', inline=True, style={'fontSize': '12px', 'display': 'inline-block'})
                            ]),

                            dash_table.DataTable(
                                id='critical-table',
                                sort_action="native",
                                page_size=10,
                                style_header={
                                    'backgroundColor': '#ef4444', 'color': 'white', 'fontWeight': 'bold'},
                                style_cell={'textAlign': 'left', 'fontSize': '11px',
                                            'padding': '8px', 'whiteSpace': 'normal', 'height': 'auto'},
                                style_data_conditional=[
                                    {
                                        'if': {'filter_query': '{is_whitelisted} eq "True"'},
                                        'fontWeight': 'bold',
                                        'fontStyle': 'italic',
                                        'color': '#0369a1'
                                    }
                                ],
                                columns=[
                                    {"name": "Idx", "id": "alarm_index"},
                                    {"name": "Description", "id": "description"},
                                    {"name": "Frequency", "id": "frequency"},
                                    {"name": "Sessions", "id": "sessions"}
                                ]
                            )
                        ])
                    ])
                ]),

                # --- ORIGINAL TRANSIENT SECTION ---
                html.Div(style={'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'marginBottom': '20px'}, children=[
                    html.H2("Ghost Fault & Chatter Detector", style={
                            'color': '#1e293b', 'marginTop': 0}),
                    html.P("Detects alarms that self-clear (turn ON then OFF) without entering Manual Mode. High frequency counts indicate degrading components.",
                           style={'color': '#64748b', 'fontSize': '14px'}),
                    html.Div(style={'marginTop': '15px'}, children=[
                        html.Label("Scope:", style={
                                   'fontWeight': 'bold', 'marginRight': '10px'}),
                        dcc.RadioItems(
                            id='transient-scope-toggle',
                            options=[{'label': ' All Faults', 'value': 'ALL'}, {
                                'label': ' Whitelist Only (Recommended)', 'value': 'WL'}],
                            value='WL', inline=True
                        )
                    ])
                ]),
                html.Div(style={'display': 'flex', 'gap': '20px'}, children=[
                    html.Div(style={'flex': 1}, children=[
                        html.H3("Fault Frequency Table", style={
                                'fontSize': '16px', 'fontWeight': 'bold', 'marginBottom': '10px'}),
                        dash_table.DataTable(
                            id='transient-table',
                            sort_action="native",
                            filter_action="native",
                            row_selectable="single",
                            page_size=15,
                            style_header={'backgroundColor': '#f59e0b',
                                          'color': 'white', 'fontWeight': 'bold'},
                            style_cell={'textAlign': 'left',
                                        'fontSize': '11px', 'padding': '8px'},
                            style_data_conditional=[
                                {'if': {'column_id': 'avg_duration_sec', 'filter_query': '{avg_duration_sec} < 1'},
                                    'color': '#d97706', 'fontWeight': 'bold'},  # Highlight fast chatter
                            ],
                            columns=[
                                {"name": "Index", "id": "alarm_index"},
                                {"name": "Description", "id": "description"},
                                {"name": "Frequency (Count)",
                                 "id": "frequency"},
                                {"name": "Avg Dur (s)",
                                 "id": "avg_duration_sec"},
                                {"name": "Peak Activity Window",
                                    "id": "peak_activity"}
                            ]
                        )
                    ]),
                    html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '15px', 'borderRadius': '8px'}, children=[
                        html.H3("Drill-Down: Frequency Trend", style={
                                'fontSize': '16px', 'fontWeight': 'bold', 'marginBottom': '10px'}),
                        html.P(id='transient-graph-title', children="Select a row in the table to view trend.",
                               style={'fontSize': '12px', 'color': '#94a3b8'}),
                        dcc.Graph(id='transient-trend-graph',
                                  style={'height': '400px'})
                    ])
                ])
            ]))
        ]),

        # TAB 3: DATA EXPLORER
        dcc.Tab(label='Data Explorer', value='tab-explorer', children=[
            dcc.Loading(id="loading-explorer", type="default", color="#1e293b", children=html.Div(style={'padding': '20px'}, children=[
                html.Div(style={'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'marginBottom': '20px', 'display': 'flex', 'gap': '20px', 'alignItems': 'center', 'flexWrap': 'wrap'}, children=[
                    html.Div([html.Label("Search Index:", style={'fontSize': '12px'}), dcc.Input(
                        id='explorer-index-input', type='text', placeholder='Index...', style={'padding': '8px', 'borderRadius': '4px', 'border': '1px solid #ddd'})]),
                    html.Div([html.Label("Search Description:", style={'fontSize': '12px'}), dcc.Input(
                        id='explorer-desc-input', type='text', placeholder='Keyword...', style={'padding': '8px', 'borderRadius': '4px', 'border': '1px solid #ddd', 'width': '300px'})]),
                    html.Div([
                        html.Label("Filter:", style={
                                   'fontSize': '12px', 'display': 'block'}),
                        dcc.RadioItems(id='explorer-view-mode', options=[{'label': ' All Faults', 'value': 'ALL'}, {
                                       'label': ' Whitelist Only', 'value': 'WL'}], value='ALL', inline=True, style={'fontSize': '12px'})
                    ]),
                    html.Button("Apply Filter", id="explorer-btn", style={
                                'backgroundColor': '#1e293b', 'color': 'white', 'padding': '8px 20px', 'borderRadius': '4px', 'border': 'none', 'cursor': 'pointer'})
                ]),
                html.Div([
                    html.H3("Raw Alarm Logs (Session Context Highlighted)"),
                    dash_table.DataTable(id='explorer-table', sort_action="native", filter_action="native", page_size=PAGE_SIZE, style_header={
                                         'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'}, style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '8px'})
                ])
            ]))
        ])
    ]),
    dcc.Download(id="download-pdf-report")
])

# --- CALLBACKS ---


@app.callback(
    [Output('current-db-path', 'data'), Output('whitelist-data-store', 'data'), Output('config-status', 'children'),
     Output('date-picker', 'min_date_allowed'), Output('date-picker', 'max_date_allowed'), Output('date-picker', 'start_date'), Output('date-picker', 'end_date')],
    [Input('upload-db', 'contents'), Input('upload-whitelist', 'contents')],
    [State('upload-db', 'filename'), State('upload-whitelist', 'filename'),
     State('current-db-path', 'data'), State('whitelist-data-store', 'data')]
)
def update_config(db_content, wl_content, db_name, wl_name, current_db_path, current_wl_data):
    ctx = dash.callback_context
    status_msg = "Config Loaded"
    if ctx.triggered and 'upload-db' in ctx.triggered[0]['prop_id'] and db_content:
        try:
            content_type, content_string = db_content.split(',')
            decoded = base64.b64decode(content_string)
            temp_path = os.path.join(BASE_DIR, f'temp_loaded_{db_name}')
            with open(temp_path, 'wb') as f:
                f.write(decoded)
            current_db_path = temp_path
            init_metadata_tables(current_db_path)
            status_msg = f"Database Switched: {db_name}"
        except Exception as e:
            status_msg = f"DB Load Error: {e}"

    if ctx.triggered and 'upload-whitelist' in ctx.triggered[0]['prop_id'] and wl_content:
        try:
            content_type, content_string = wl_content.split(',')
            current_wl_data = parse_whitelist_content(
                content_type, content_string)
            status_msg = f"Whitelist Updated: {wl_name} ({len(current_wl_data)} items)"
        except Exception as e:
            status_msg = f"Whitelist Load Error: {e}"

    min_date, max_date = get_db_date_range(current_db_path)
    return current_db_path, current_wl_data, status_msg, min_date, max_date, min_date, max_date


@app.callback(
    [Output('session-store', 'data'), Output('details-store', 'data'), Output('moves-store', 'data'),
     Output('kpi-moves-val', 'children'), Output('kpi-mmbf-count', 'children'), Output('mmbf-value', 'children'), Output('session-table', 'selected_rows')],
    [Input('crane-selector', 'value'), Input('date-picker', 'start_date'), Input('date-picker', 'end_date'),
     Input('save-moves-btn', 'n_clicks'), Input('current-db-path',
                                                'data'), Input('whitelist-data-store', 'data'),
     Input('min-duration-input', 'value')],
    [State('manual-move-input', 'value')]
)
def update_crane_and_moves(crane_id, start_date, end_date, n_clicks, db_path, whitelist_data, min_duration, manual_val):
    ctx = dash.callback_context
    if min_duration is not None:
        try:
            min_duration = float(min_duration)
        except ValueError:
            min_duration = DEFAULT_MIN_DURATION
    else:
        min_duration = DEFAULT_MIN_DURATION

    if ctx.triggered and 'save-moves-btn' in ctx.triggered[0]['prop_id'] and manual_val is not None:
        con = get_db_con(db_path, read_only=False)
        if con:
            con.execute("INSERT OR REPLACE INTO manual_move_overrides (unit_id, manual_count) VALUES (?, ?)", [
                        crane_id, manual_val])
            con.close()

    whitelist_indices = {int(x['alarm_index'])
                         for x in whitelist_data} if whitelist_data else set()
    moves = get_refined_move_count(crane_id, start_date, end_date, db_path)
    df_s, details = get_maintenance_sessions(
        crane_id, start_date, end_date, db_path, whitelist_indices, min_duration)
    mmbf_count = len(df_s[df_s['mmbf_tag'] == 'Yes']) if not df_s.empty else 0
    mmbf_val = f"{(mmbf_count / (moves / 1000)):.2f}" if moves > 0 else "0.00"

    return (df_s.to_dict('records') if not df_s.empty else [], details, moves, f"{moves:,}", str(mmbf_count), mmbf_val, [0] if not df_s.empty else [])


@app.callback([Output('session-table', 'columns'), Output('session-table', 'data')], [Input('session-store', 'data')])
def update_table_data(data):
    cols = [{"name": i, "id": j} for i, j in [("ID", "session_id"), ("Start", "start_timestamp"), ("End", "end_timestamp"), (
        "Duration (min)", "session_duration_mins"), ("Index", "primary_index"), ("Primary Root Cause", "primary_issue"), ("MMBF?", "mmbf_tag")]]
    cols.append({"name": "Logs", "id": "view_logs"})
    if data:
        for row in data:
            row['view_logs'] = "🔎 View"
    return cols, data or []


@app.callback([Output('detail-table', 'columns'), Output('detail-table', 'data')],
              [Input('session-table', 'selected_rows'),
               Input('detail-view-mode', 'value')],
              [State('session-table', 'data'), State('details-store', 'data')])
def update_details(selected, view_mode, session_data, details):
    if not selected or not session_data:
        return [], []
    sid = str(session_data[selected[0]]['session_id'])
    rows = details.get(sid, [])
    if view_mode == 'WL':
        rows = [r for r in rows if r.get('is_whitelisted') == 'True']
    cols = [{"name": "Start Time", "id": "first_occurrence"}, {"name": "End Time", "id": "resolution_time"}, {"name": "Idx", "id": "alarm_index"}, {"name": "Class", "id": "alarm_class"}, {
        "name": "Fault", "id": "description"}, {"name": "Duration (min)", "id": "total_duration_mins"}, {"name": "MMBF?", "id": "mmbf_tick", "presentation": "dropdown", "editable": True}]
    return cols, rows


@app.callback([Output('session-store', 'data', allow_duplicate=True), Output('mmbf-value', 'children', allow_duplicate=True), Output('kpi-mmbf-count', 'children', allow_duplicate=True)],
              [Input('detail-table', 'data_timestamp')],
              [State('detail-table', 'data'), State('session-table', 'selected_rows'), State('session-table', 'data'), State(
                  'session-store', 'data'), State('moves-store', 'data'), State('crane-selector', 'value'), State('current-db-path', 'data')],
              prevent_initial_call=True)
def sync_and_save_mmbf(ts, detail_data, selected_rows, current_table, session_store, total_moves, crane_id, db_path):
    if not selected_rows or not session_store:
        return session_store, "N/A", "0"
    sid, start_ts = str(current_table[selected_rows[0]]['session_id']
                        ), current_table[selected_rows[0]]['start_timestamp']
    ticked_fault = next(
        (f for f in detail_data if f.get('mmbf_tick') is True), None)
    con = get_db_con(db_path, read_only=False)
    if con:
        if ticked_fault:
            con.execute("INSERT OR REPLACE INTO forensic_metadata (unit_id, session_start, is_mmbf, primary_index, primary_issue) VALUES (?, ?, ?, ?, ?)", [
                        crane_id, start_ts, True, ticked_fault['alarm_index'], ticked_fault['description']])
        else:
            con.execute("DELETE FROM forensic_metadata WHERE unit_id ILIKE ? AND session_start = ?", [
                        crane_id, start_ts])
        con.close()
    for row in session_store:
        if str(row['session_id']) == sid:
            row['mmbf_tag'] = 'Yes' if ticked_fault else 'No'
            if ticked_fault:
                row['primary_issue'], row['primary_index'] = ticked_fault['description'], ticked_fault['alarm_index']
    mmbf_count = sum(1 for r in session_store if r['mmbf_tag'] == 'Yes')
    mmbf_val = f"{(mmbf_count / (total_moves / 1000)):.2f}" if total_moves > 0 else "0.00"
    return session_store, mmbf_val, str(mmbf_count)

# --- INSIGHTS & TRANSIENT CALLBACKS ---


@app.callback(
    [Output('transient-table', 'data'), Output('transient-raw-store', 'data'),
     Output('nuisance-table', 'data'), Output('critical-table', 'data')],
    [Input('tabs-main', 'value'),
     Input('transient-scope-toggle', 'value'),
     Input('nuisance-scope-toggle', 'value'),
     Input('critical-scope-toggle', 'value'),
     Input('crane-selector', 'value'), Input('date-picker', 'start_date'), Input('date-picker', 'end_date')],
    [State('current-db-path', 'data'), State('whitelist-data-store', 'data'),
     State('session-store', 'data'), State('details-store', 'data')]
)
def update_insights_tab_data(tab, trans_scope, nuis_scope, crit_scope, crane_id, start, end, db_path, whitelist_data, session_data, details_data):
    if tab != 'tab-insights':
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update

    whitelist_indices = {int(x['alarm_index'])
                         for x in whitelist_data} if whitelist_data else set()

    # We fetch ALL data initially to support independent filtering
    summary_df, raw_df = get_transient_faults(
        crane_id, start, end, db_path, whitelist_indices, only_whitelist=False)

    # Store raw data for graphing, but serialize timestamps to strings for JSON
    raw_records = []
    if not raw_df.empty:
        df_store = raw_df.copy()
        df_store['start_ts'] = df_store['start_ts'].astype(str)
        raw_records = df_store.to_dict('records')

    # --- INSIGHTS GENERATION ---

    # 1. Critical Failures (Aggregation from Details Store - "Internal Fault Analysis")
    # Iterate through all sessions in details-store and collect faults
    critical_rows = []
    if details_data:
        for sid, faults in details_data.items():
            for f in faults:
                critical_rows.append({
                    'alarm_index': f['alarm_index'],
                    'description': f['description'],
                    'session_id': int(sid),
                    'is_whitelisted': f.get('is_whitelisted', 'False')
                })

    df_crit = pd.DataFrame(critical_rows)
    critical_table_data = []

    if not df_crit.empty:
        # Group by Index/Desc/Whitelist Status
        # Aggregations: Frequency (Unique Sessions), List of Session IDs
        grp = df_crit.groupby(['alarm_index', 'description', 'is_whitelisted'])
        for (idx, desc, wl), g in grp:
            sessions = sorted(g['session_id'].unique())
            freq = len(sessions)
            critical_table_data.append({
                'alarm_index': idx,
                'description': desc,
                'frequency': freq,
                'sessions': ", ".join(map(str, sessions)),
                'is_whitelisted': wl
            })

        # Sort by frequency desc
        critical_table_data.sort(key=lambda x: x['frequency'], reverse=True)

    # 2. Nuisance Data (Chatter - Stops)
    nuisance_data = []
    chatter_counts = pd.DataFrame()

    # Helper to check if alarm is critical
    critical_map = {row['alarm_index']: row['frequency']
                    for row in critical_table_data}

    if not summary_df.empty:
        chatter_counts = summary_df[['alarm_index', 'description',
                                     'frequency', 'avg_duration_sec', 'is_whitelisted']].copy()

        # Calculate Stop Count based on Critical Data
        chatter_counts['stop_count'] = chatter_counts['alarm_index'].map(
            critical_map).fillna(0)

        # Filter: High Chatter AND Zero (or very low) Stops
        nuisance_df = chatter_counts[chatter_counts['stop_count'] == 0].copy()
        nuisance_df = nuisance_df.sort_values('frequency', ascending=False)

        nuisance_data = nuisance_df.to_dict('records')

    # --- FILTERING OUTPUTS ---

    # Filter Nuisance Table
    if nuis_scope == 'WL':
        nuisance_data = [row for row in nuisance_data if row.get(
            'is_whitelisted') == 'True']

    # Filter Critical Table
    if crit_scope == 'WL':
        critical_table_data = [
            row for row in critical_table_data if row.get('is_whitelisted') == 'True']

    # Filter Transient Table (summary_df)
    transient_data = summary_df.to_dict(
        'records') if not summary_df.empty else []
    if trans_scope == 'WL':
        transient_data = [row for row in transient_data if row.get(
            'is_whitelisted') == 'True']

    return transient_data, raw_records, nuisance_data, critical_table_data


@app.callback(
    [Output('transient-trend-graph', 'figure'),
     Output('transient-graph-title', 'children')],
    [Input('transient-table', 'selected_rows')],
    [State('transient-table', 'data'), State('transient-raw-store', 'data')]
)
def update_transient_graph(selected_rows, table_data, raw_data):
    if not selected_rows or not table_data or not raw_data:
        return {}, "Select a row in the table to view trend."

    row = table_data[selected_rows[0]]
    idx = row['alarm_index']
    desc = row['description']

    # Filter raw data for this specific alarm
    df_raw = pd.DataFrame(raw_data)
    df_raw = df_raw[df_raw['alarm_index'] == idx].copy()

    if df_raw.empty:
        return {}, f"No detail data for {desc}"

    df_raw['start_ts'] = pd.to_datetime(df_raw['start_ts'])
    df_raw.set_index('start_ts', inplace=True)

    # Resample to get counts per hour (or Day depending on range)
    # Default to Hourly for precision in identifying 'Storms'
    df_resampled = df_raw.resample('h').size().reset_index(name='count')

    fig = px.bar(
        df_resampled, x='start_ts', y='count',
        title=f"Chatter Frequency: {desc} ({idx})",
        labels={'start_ts': 'Time', 'count': 'Fault Count (per Hour)'}
    )
    fig.update_layout(bargap=0.1, margin=dict(l=40, r=40, t=40, b=40))
    fig.update_traces(marker_color='#f59e0b')

    return fig, f"Trend Analysis for: {desc}"

# --- EXPLORER & REPORT CALLBACKS ---


@app.callback(
    [Output('explorer-table', 'columns'), Output('explorer-table', 'data'),
     Output('explorer-table', 'style_data_conditional'), Output('explorer-table', 'page_current')],
    [Input('tabs-main', 'value'), Input('explorer-btn', 'n_clicks'), Input('target-session-store', 'data'),
     Input('crane-selector', 'value'), Input('date-picker',
                                             'start_date'), Input('date-picker', 'end_date'),
     Input('current-db-path', 'data'), Input('whitelist-data-store', 'data'),
     Input('session-store', 'data'), Input('details-store', 'data')],
    [State('explorer-index-input', 'value'), State('explorer-desc-input',
                                                   'value'), State('explorer-view-mode', 'value')]
)
def update_explorer_tab(tab, n, target_sid, crane_id, start, end, db_path, whitelist_data, session_data, details_data, idx_filter, desc_filter, view_mode):
    if tab != 'tab-explorer':
        return [], [], [], 0

    whitelist_indices = {int(x['alarm_index'])
                         for x in whitelist_data} if whitelist_data else set()
    only_whitelist = (view_mode == 'WL')
    df_logs = get_explorer_logs(crane_id, start, end, idx_filter, desc_filter,
                                db_path, whitelist_indices, only_whitelist=only_whitelist)
    if df_logs.empty:
        return [], [], [], 0

    PALETTE = ['#dbeafe', '#dcfce7', '#f3e8ff',
               '#ffedd5', '#fce7f3', '#cffafe']
    df_logs['session_context'] = ''
    df_logs['matched_session_id'] = None

    if session_data:
        for i, session in enumerate(session_data):
            sid = str(session['session_id'])
            color = PALETTE[i % len(PALETTE)]
            s_start = pd.Timestamp(session['start_timestamp'])
            s_end = pd.Timestamp(session['end_timestamp'])

            mask_manual = (df_logs['alarm_index'] == MANUAL_MODE_INDEX) & (
                df_logs['full_ts'] >= s_start) & (df_logs['full_ts'] <= s_end)
            df_logs.loc[mask_manual, 'matched_session_id'] = sid
            df_logs.loc[mask_manual, 'row_color'] = color
            df_logs.loc[mask_manual, 'session_context'] = f"Session {sid}"

            faults = details_data.get(sid, []) if details_data else []
            for f in faults:
                f_idx = int(f['alarm_index'])
                f_start_ts = pd.Timestamp(f['first_occurrence'])
                f_end_ts = pd.Timestamp(f['resolution_time'])

                mask_fault = (df_logs['alarm_index'] == f_idx) & (
                    (df_logs['full_ts'] == f_start_ts) | (df_logs['full_ts'] == f_end_ts))
                df_logs.loc[mask_fault, 'row_color'] = color
                df_logs.loc[mask_fault, 'session_context'] = f"Session {sid}"

    styles = []
    if 'row_color' in df_logs.columns:
        unique_colors = df_logs['row_color'].dropna().unique()
        for c in unique_colors:
            styles.append({'if': {'filter_query': f'{{row_color}} eq "{c}"'},
                          'backgroundColor': c, 'color': 'black'})

    cols = [{"name": i.replace('_', ' ').title(), "id": i} for i in df_logs.columns if i not in [
        'is_whitelisted', 'full_ts', 'matched_session_id', 'row_color']]

    page_current = 0
    if target_sid:
        target_str = f"Session {target_sid}"
        matches = df_logs.index[df_logs['session_context']
                                == target_str].tolist()
        if matches:
            page_current = math.floor(matches[0] / PAGE_SIZE)

    return cols, df_logs.to_dict('records'), styles, page_current


@app.callback(
    Output("download-pdf-report", "data"),
    Input("pdf-btn", "n_clicks"),
    [State('session-store', 'data'), State('details-store', 'data'), State('crane-selector', 'value'),
     State('moves-store', 'data'), State('date-picker',
                                         'start_date'), State('date-picker', 'end_date'),
     State('mmbf-value', 'children')],
    prevent_initial_call=True
)
def generate_pdf_report(n, session_data, details_data, crane_id, total_moves, start_date, end_date, mmbf_val):
    if not session_data:
        return dash.no_update
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
                pdf.cell(15, 6, str(f['total_duration_mins']), 1, 1, 'C', fill)
        else:
            pdf.set_font("Helvetica", "I", 7)
            pdf.cell(
                0, 6, "No specific fault events identified during this window.", 1, 1)
        pdf.ln(6)

    return dcc.send_bytes(pdf.output(dest='S').encode('latin-1'), f"{crane_id}_MMBF_Report.pdf")


@app.callback([Output('tabs-main', 'value'), Output('target-session-store', 'data')],
              [Input('session-table', 'active_cell')],
              [State('session-table', 'derived_virtual_data')], prevent_initial_call=True)
def jump_to_session_log(active_cell, rows):
    if not active_cell or not rows:
        return dash.no_update, dash.no_update
    if active_cell['column_id'] == 'view_logs':
        try:
            row_idx = active_cell['row']
            if row_idx < len(rows):
                return 'tab-explorer', rows[row_idx].get('session_id')
        except:
            pass
    return dash.no_update, dash.no_update


@app.callback(Output('main-trend-graph', 'figure'), [Input('session-store', 'data')])
def update_graph(data):
    if not data:
        return {}
    df = pd.DataFrame(data)
    fig = px.bar(df, x='session_id', y='session_duration_mins', color='mmbf_tag', color_discrete_map={'Yes': '#dc2626', 'No': '#94a3b8'}, labels={
                 'session_id': 'Session ID', 'session_duration_mins': 'Downtime (min)', 'mmbf_tag': 'MMBF'}, title="Maintenance Downtime Trends")
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor='rgba(0,0,0,0)',
                      plot_bgcolor='rgba(0,0,0,0)', xaxis=dict(type='category'))
    return fig


if __name__ == '__main__':
    app.run(debug=True)
