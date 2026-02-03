"""
Forensic analysis tool for RMG Fleet (RMG01 - RMG12) maintenance logs.
Version: 7.0 - Dynamic File Loading & UI
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
from datetime import date
from functools import lru_cache

# --- CONFIGURATION (DEFAULTS) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, 'alarm_logs3.duckdb')
DEFAULT_WHITELIST_PATH = os.path.join(BASE_DIR, 'MMbf_whitelist.csv')

CRANE_LIST = [f'RMG{str(i).zfill(2)}' for i in range(1, 13)]

# Alarm Index Constants
MANUAL_MODE_INDEX = 57011
MIN_SESSION_DURATION_MINS = 15
TWISTLOCK_LOCKED_INDEX = 5740
TWISTLOCK_UNLOCKED_INDEX = 5741

# --- HELPER FUNCTIONS ---


def parse_whitelist_content(content_type, content_string):
    """Parses uploaded CSV content into a dataframe."""
    try:
        decoded = base64.b64decode(content_string)
        df = pd.read_csv(io.BytesIO(decoded), encoding='latin-1')

        # Standardize columns
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
        # Fallback to in-memory if file missing to prevent crash
        print(f"[DEBUG] DB file not found: {db_path}")
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
        res = con.execute(
            "SELECT MIN(alarm_date), MAX(alarm_date) FROM alarm_logs").fetchone()
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

# --- CORE LOGIC (Refactored for Dependency Injection) ---


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
    AND alarm_date >= ? AND alarm_date <= ?
    AND alarm_index IN ({TWISTLOCK_LOCKED_INDEX}, {TWISTLOCK_UNLOCKED_INDEX})
    ORDER BY alarm_date ASC, alarm_time ASC
    """
    auto_count = 0
    try:
        df = con.execute(query, [crane_id, start_date, end_date]).df()
        is_carrying = False
        for _, row in df.iterrows():
            idx = row['alarm_index']
            state = str(row['state'])
            if idx == TWISTLOCK_LOCKED_INDEX and 'ON' in state:
                is_carrying = True
            elif idx == TWISTLOCK_UNLOCKED_INDEX and 'ON' in state and is_carrying:
                auto_count += 1
                is_carrying = False
    except Exception as e:
        print(f"[DEBUG] Move Calculation Error: {e}")
    if con:
        con.close()
    return auto_count


def get_maintenance_sessions(crane_id, start_date, end_date, db_path, whitelist_indices):
    con = get_db_con(db_path)
    if not con:
        return pd.DataFrame(), {}

    try:
        # 1. Identify Maintenance Windows
        query = f"SELECT alarm_state, (alarm_date || ' ' || alarm_time)::TIMESTAMP as ts FROM alarm_logs WHERE unit_id ILIKE ? AND alarm_index = {MANUAL_MODE_INDEX} AND alarm_date >= ? AND alarm_date <= ? ORDER BY ts ASC"
        df_manual = con.execute(query, [crane_id, start_date, end_date]).df()

        windows, start_ts = [], None
        for _, row in df_manual.iterrows():
            state = str(row['alarm_state']).upper()
            if 'ON' in state and start_ts is None:
                start_ts = row['ts']
            elif 'OFF' in state and start_ts is not None:
                dur = (row['ts'] - start_ts).total_seconds() / 60
                if dur >= MIN_SESSION_DURATION_MINS:
                    windows.append(
                        {'start': start_ts, 'end': row['ts'], 'duration': round(dur, 2)})
                start_ts = None

        # 2. Analyze Faults
        try:
            meta_df = con.execute(
                "SELECT * FROM forensic_metadata WHERE unit_id ILIKE ?", [crane_id]).df()
        except:
            # Handle case where table doesn't exist yet
            meta_df = pd.DataFrame()

        sessions, details_map = [], {}
        LOOKBACK_LIMIT = pd.Timedelta(minutes=60)

        for i, w in enumerate(windows):
            sid = i + 1
            start_str = w['start'].strftime('%Y-%m-%d %H:%M:%S')

            search_start_ts = w['start'] - LOOKBACK_LIMIT
            if i > 0:
                prev_end = windows[i-1]['end']
                if search_start_ts < prev_end:
                    search_start_ts = prev_end

            search_start_str = search_start_ts.strftime('%Y-%m-%d %H:%M:%S')
            end_str = w['end'].strftime('%Y-%m-%d %H:%M:%S')

            saved = meta_df[meta_df['session_start'] ==
                            start_str] if not meta_df.empty else pd.DataFrame()

            fault_query = f"""
                SELECT alarm_index, alarm_class, description, alarm_state, 
                (alarm_date || ' ' || alarm_time)::TIMESTAMP as ts 
                FROM alarm_logs 
                WHERE unit_id ILIKE ? 
                AND ts >= '{search_start_str}' AND ts <= '{end_str}' 
                AND (description ILIKE '%Fault%' OR description ILIKE '%Stop%' OR description ILIKE '%Failure%' OR description ILIKE '%Emergency%' OR description ILIKE '%Collision%') 
                ORDER BY ts ASC
            """
            df_faults = con.execute(fault_query, [crane_id]).df()

            if not df_faults.empty:
                summary = []
                for desc in df_faults['description'].unique():
                    f_events = df_faults[df_faults['description'] == desc].sort_values(
                        'ts')
                    first_occurrence_ts = f_events['ts'].min()

                    occ, dur_sec, on_time = 0, 0, None
                    for _, evt in f_events.iterrows():
                        st = str(evt['alarm_state']).upper()
                        if 'ON' in st and on_time is None:
                            on_time = evt['ts']
                            occ += 1
                        elif 'OFF' in st and on_time is not None:
                            dur_sec += (evt['ts'] - on_time).total_seconds()
                            on_time = None
                    if on_time is not None:
                        dur_sec += (w['end'] - on_time).total_seconds()

                    if occ > 0:
                        idx = int(f_events['alarm_index'].iloc[0])
                        is_ticked = any(
                            not saved.empty and saved.iloc[0]['is_mmbf'] and saved.iloc[0]['primary_issue'] == desc for _ in [0])
                        summary.append({
                            'description': desc,
                            'alarm_index': idx,
                            'alarm_class': f_events['alarm_class'].iloc[0],
                            'occurrence_count': occ,
                            'total_duration_mins': round(dur_sec / 60, 2),
                            'first_occurrence': first_occurrence_ts.strftime('%H:%M:%S'),
                            'mmbf_tick': is_ticked,
                            'is_whitelisted': 'True' if idx in whitelist_indices else 'False'
                        })

                if summary:
                    df_sum = pd.DataFrame(summary).sort_values(
                        'first_occurrence', ascending=True)
                    if not saved.empty:
                        mmbf_tag, p_issue, p_index = 'Yes' if saved.iloc[0]['is_mmbf'] else 'No', saved.iloc[
                            0]['primary_issue'], saved.iloc[0]['primary_index']
                    else:
                        mmbf_tag, p_issue, p_index = 'No', df_sum.iloc[0][
                            'description'], df_sum.iloc[0]['alarm_index']

                    sessions.append({
                        'session_id': sid,
                        'start_timestamp': start_str,
                        'end_timestamp': end_str,
                        'session_duration_mins': w['duration'],
                        'primary_index': p_index,
                        'primary_issue': p_issue,
                        'mmbf_tag': mmbf_tag,
                        'is_whitelisted': 'True' if int(p_index) in whitelist_indices else 'False'
                    })
                    details_map[str(sid)] = df_sum.to_dict('records')

        if con:
            con.close()
        return pd.DataFrame(sessions), details_map
    except Exception as e:
        print(f"[DEBUG] Session Analysis Error: {e}")
        if con:
            con.close()
        return pd.DataFrame(), {}


def get_explorer_logs(crane_id, start_date, end_date, index_filter, desc_filter, db_path, whitelist_indices):
    con = get_db_con(db_path)
    if not con:
        return pd.DataFrame()
    query = "SELECT unit_id, alarm_date, alarm_time, alarm_index, alarm_class, description, alarm_state FROM alarm_logs WHERE unit_id ILIKE ? AND alarm_date >= ? AND alarm_date <= ?"
    params = [crane_id, start_date, end_date]
    if index_filter:
        query += " AND CAST(alarm_index AS VARCHAR) LIKE ?"
        params.append(f"%{index_filter}%")
    if desc_filter:
        query += " AND description ILIKE ?"
        params.append(f"%{desc_filter}%")
    query += " ORDER BY alarm_date DESC, alarm_time DESC LIMIT 5000"
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
app = dash.Dash(__name__)

# Upload Component Style - UPDATED to look like actionable buttons
upload_btn_style = {
    'display': 'inline-block',
    'width': '140px',
    'padding': '8px',
    'lineHeight': '16px',
    'border': '1px solid #475569',
    'borderRadius': '4px',
    'textAlign': 'center',
    'cursor': 'pointer',
    'backgroundColor': '#334155',
    'color': '#f1f5f9',
    'fontSize': '12px',
    'fontWeight': '600',
    'margin': '0 5px',
    'boxShadow': '0 1px 2px rgba(0,0,0,0.2)'
}

app.layout = html.Div(style={'fontFamily': 'Segoe UI, Arial', 'backgroundColor': '#f4f7f9', 'minHeight': '100vh'}, children=[
    # State Stores
    dcc.Store(id='session-store'),
    dcc.Store(id='details-store'),
    dcc.Store(id='moves-store'),
    # Config Stores
    dcc.Store(id='current-db-path', data=DEFAULT_DB_PATH),
    dcc.Store(id='whitelist-data-store', data=load_default_whitelist()),
    dcc.Store(id='date-range-store'),  # To store DB specific min/max dates

    # Header
    html.Div(style={'backgroundColor': '#1e293b', 'padding': '20px', 'color': 'white', 'display': 'flex', 'justifyContent': 'space-between', 'alignItems': 'center'}, children=[
        html.Div([
            html.H1("MMBF Tool", style={
                    'margin': '0', 'fontSize': '28px', 'fontWeight': 'bold'}),
            html.P("Validated Forensic Logic - Asset Analysis Period",
                   style={'margin': '5px 0 0 0', 'opacity': '0.8'})
        ]),
        html.Div(style={'display': 'flex', 'gap': '10px', 'alignItems': 'center'}, children=[
            # Config Area
            html.Div(style={'display': 'flex', 'flexDirection': 'column', 'alignItems': 'flex-end', 'marginRight': '20px'}, children=[
                html.Label("Configuration Source", style={
                           'fontSize': '10px', 'color': '#94a3b8', 'fontWeight': 'bold', 'marginBottom': '4px'}),
                html.Div(style={'display': 'flex'}, children=[
                    dcc.Upload(id='upload-db', children=html.Div(
                        ["📂 Select DB File"]), style=upload_btn_style, multiple=False),
                    dcc.Upload(id='upload-whitelist', children=html.Div(
                        ["📋 Select Whitelist"]), style=upload_btn_style, multiple=False)
                ]),
                html.Div(id='config-status', children="Default Configuration Loaded", style={
                         'fontSize': '10px', 'color': '#64748b', 'marginTop': '5px', 'fontStyle': 'italic'})
            ]),
            # Controls
            html.Div([html.Label("Analysis Period:", style={'fontSize': '12px', 'color': '#94a3b8', 'display': 'block'}),
                      dcc.DatePickerRange(id='date-picker', style={'fontSize': '12px'})]),
            html.Div([html.Label("Asset Identifier:", style={'fontSize': '12px', 'color': '#94a3b8', 'display': 'block'}),
                      dcc.Dropdown(id='crane-selector', options=[{'label': c, 'value': c} for c in CRANE_LIST], value='RMG05', clearable=False, style={'width': '120px', 'color': '#1e293b'})])
        ])
    ]),

    # Main Content
    dcc.Tabs(id="tabs-main", value='tab-audit', children=[
        dcc.Tab(label='Forensic Audit', value='tab-audit', children=[
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
                          dash_table.DataTable(id='session-table', sort_action="native", filter_action="native", row_selectable="single", page_size=10, style_header={'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'}, style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '10px'}, style_data_conditional=[{'if': {'column_id': 'mmbf_tag', 'filter_query': '{mmbf_tag} eq "Yes"'}, 'backgroundColor': '#fee2e2', 'color': '#b91c1c', 'fontWeight': 'bold'}, {'if': {'filter_query': '{is_whitelisted} eq "True"'}, 'backgroundColor': '#fef9c3'}])]),
                html.Div([html.H3("2. Internal Fault Analysis (Session Focused)", style={'color': '#1e293b', 'marginBottom': '10px'}),
                          dash_table.DataTable(id='detail-table', sort_action="native", filter_action="native", editable=True, page_size=10, style_header={'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'}, style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '10px'}, style_data_conditional=[{'if': {'filter_query': '{is_whitelisted} eq "True"'}, 'backgroundColor': '#fef9c3'}], dropdown={'mmbf_tick': {'options': [{'label': 'YES', 'value': True}, {'label': 'NO', 'value': False}]}})])
            ])
        ]),
        dcc.Tab(label='Data Explorer', value='tab-explorer', children=[
            html.Div(style={'padding': '20px', 'display': 'flex', 'gap': '20px'}, children=[
                html.Div(style={'flex': '2'}, children=[
                    html.Div(style={'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'marginBottom': '20px', 'display': 'flex', 'gap': '20px', 'alignItems': 'flex-end'}, children=[
                        html.Div([html.Label("Search Index:", style={'fontSize': '12px'}), dcc.Input(
                            id='explorer-index-input', type='text', placeholder='Index...', style={'padding': '8px', 'borderRadius': '4px', 'border': '1px solid #ddd'})]),
                        html.Div([html.Label("Search Description:", style={'fontSize': '12px'}), dcc.Input(
                            id='explorer-desc-input', type='text', placeholder='Keyword...', style={'padding': '8px', 'borderRadius': '4px', 'border': '1px solid #ddd', 'width': '300px'})]),
                        html.Button("Apply Filter", id="explorer-btn", style={
                                    'backgroundColor': '#1e293b', 'color': 'white', 'padding': '8px 20px', 'borderRadius': '4px', 'border': 'none', 'cursor': 'pointer'})
                    ]),
                    html.Div([html.H3("Raw Alarm Logs (Latest 5000 Entries)"), dash_table.DataTable(id='explorer-table', sort_action="native", filter_action="native", page_size=20, style_header={
                             'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'}, style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '8px'}, style_data_conditional=[{'if': {'filter_query': '{is_whitelisted} eq "True"'}, 'backgroundColor': '#fef9c3'}])])
                ]),
                html.Div(style={'flex': '1'}, children=[
                    html.Div([html.H3("Active Whitelist"), html.P("Loaded from CSV", style={'fontSize': '11px', 'color': '#64748b'}),
                              dash_table.DataTable(id='whitelist-display-table', columns=[{"name": "Index", "id": "alarm_index"}, {"name": "Description", "id": "description"}], page_size=20, style_header={'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'}, style_cell={'textAlign': 'left', 'fontSize': '11px', 'padding': '10px', 'whiteSpace': 'normal', 'height': 'auto'})])
                ])
            ])
        ])
    ]),
    dcc.Download(id="download-pdf-report")
])

# --- CALLBACKS ---

# 1. Config Callback: Handles File Uploads


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

    # Handle DB Upload
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

    # Handle Whitelist Upload
    if ctx.triggered and 'upload-whitelist' in ctx.triggered[0]['prop_id'] and wl_content:
        try:
            content_type, content_string = wl_content.split(',')
            current_wl_data = parse_whitelist_content(
                content_type, content_string)
            status_msg = f"Whitelist Updated: {wl_name} ({len(current_wl_data)} items)"
        except Exception as e:
            status_msg = f"Whitelist Load Error: {e}"

    # Recalculate Date Range for the active DB
    min_date, max_date = get_db_date_range(current_db_path)

    return current_db_path, current_wl_data, status_msg, min_date, max_date, min_date, max_date

# 2. Main Data Callback


@app.callback(
    [Output('session-store', 'data'), Output('details-store', 'data'), Output('moves-store', 'data'),
     Output('kpi-moves-val', 'children'), Output('kpi-mmbf-count', 'children'), Output('mmbf-value', 'children'), Output('session-table', 'selected_rows')],
    [Input('crane-selector', 'value'), Input('date-picker', 'start_date'), Input('date-picker', 'end_date'),
     Input('save-moves-btn', 'n_clicks'), Input('current-db-path', 'data'), Input('whitelist-data-store', 'data')],
    [State('manual-move-input', 'value')]
)
def update_crane_and_moves(crane_id, start_date, end_date, n_clicks, db_path, whitelist_data, manual_val):
    ctx = dash.callback_context
    # Handle Manual Move Override
    if ctx.triggered and 'save-moves-btn' in ctx.triggered[0]['prop_id'] and manual_val is not None:
        con = get_db_con(db_path, read_only=False)
        if con:
            con.execute("INSERT OR REPLACE INTO manual_move_overrides (unit_id, manual_count) VALUES (?, ?)", [
                        crane_id, manual_val])
            con.close()

    # Process Whitelist Indices
    whitelist_indices = {int(x['alarm_index'])
                         for x in whitelist_data} if whitelist_data else set()

    moves = get_refined_move_count(crane_id, start_date, end_date, db_path)
    df_s, details = get_maintenance_sessions(
        crane_id, start_date, end_date, db_path, whitelist_indices)

    mmbf_count = len(df_s[df_s['mmbf_tag'] == 'Yes']) if not df_s.empty else 0
    mmbf_val = f"{(mmbf_count / (moves / 1000)):.2f}" if moves > 0 else "0.00"

    return (df_s.to_dict('records') if not df_s.empty else [], details, moves, f"{moves:,}", str(mmbf_count), mmbf_val, [0] if not df_s.empty else [])

# 3. Table Column Updater


@app.callback([Output('session-table', 'columns'), Output('session-table', 'data')], [Input('session-store', 'data')])
def update_table_data(data):
    cols = [{"name": i, "id": j} for i, j in [("ID", "session_id"), ("Start", "start_timestamp"), ("End", "end_timestamp"), (
        "Duration (min)", "session_duration_mins"), ("Index", "primary_index"), ("Primary Root Cause", "primary_issue"), ("MMBF?", "mmbf_tag")]]
    return cols, data or []

# 4. Details Updater


@app.callback([Output('detail-table', 'columns'), Output('detail-table', 'data')], [Input('session-table', 'selected_rows'), State('session-table', 'data'), State('details-store', 'data')])
def update_details(selected, session_data, details):
    if not selected or not session_data:
        return [], []
    sid = str(session_data[selected[0]]['session_id'])
    rows = details.get(sid, [])
    cols = [
        {"name": "First Active", "id": "first_occurrence"},
        {"name": "Idx", "id": "alarm_index"},
        {"name": "Class", "id": "alarm_class"},
        {"name": "Fault", "id": "description"},
        {"name": "Occ", "id": "occurrence_count"},
        {"name": "Mins", "id": "total_duration_mins"},
        {"name": "MMBF?", "id": "mmbf_tick",
            "presentation": "dropdown", "editable": True}
    ]
    return cols, rows

# 5. MMBF Sync/Save


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

# 6. Explorer Tab


@app.callback([Output('explorer-table', 'columns'), Output('explorer-table', 'data'), Output('whitelist-display-table', 'data')],
              [Input('tabs-main', 'value'), Input('explorer-btn', 'n_clicks'), Input('crane-selector', 'value'), Input('date-picker',
                                                                                                                       'start_date'), Input('date-picker', 'end_date'), Input('current-db-path', 'data'), Input('whitelist-data-store', 'data')],
              [State('explorer-index-input', 'value'), State('explorer-desc-input', 'value')])
def update_explorer_tab(tab, n, crane_id, start, end, db_path, whitelist_data, idx_filter, desc_filter):
    if tab != 'tab-explorer':
        return [], [], whitelist_data or []

    whitelist_indices = {int(x['alarm_index'])
                         for x in whitelist_data} if whitelist_data else set()
    df_logs = get_explorer_logs(
        crane_id, start, end, idx_filter, desc_filter, db_path, whitelist_indices)

    if df_logs.empty:
        return [], [], whitelist_data or []

    cols = [{"name": i.replace('_', ' ').title(), "id": i}
            for i in df_logs.columns if i != 'is_whitelisted']
    return cols, df_logs.to_dict('records'), whitelist_data or []

# 7. PDF Report


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
        0, 7, f"Total Moves: {total_moves:,} | Failures per 1000 Moves: {mmbf_val}", ln=True)
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
            pdf.cell(15, 6, "Index", 1, 0, 'C', True)
            pdf.cell(115, 6, "Fault Description", 1, 0, 'C', True)
            pdf.cell(15, 6, "Class", 1, 0, 'C', True)
            pdf.cell(15, 6, "Occ", 1, 0, 'C', True)
            pdf.cell(30, 6, "Total Duration (min)", 1, 1, 'C', True)

            pdf.set_font("Helvetica", "", 7)
            for f in faults:
                is_this_mmbf = f.get('mmbf_tick', False)
                fill = True if is_this_mmbf else False
                if is_this_mmbf:
                    pdf.set_fill_color(*HIGHLIGHT_COLOR)
                if pdf.get_y() > 275:
                    pdf.add_page()
                pdf.cell(15, 6, str(f['alarm_index']), 1, 0, 'C', fill)
                pdf.cell(115, 6, sanitize_str(
                    str(f['description'])[:85]), 1, 0, 'L', fill)
                pdf.cell(15, 6, str(f['alarm_class']), 1, 0, 'C', fill)
                pdf.cell(15, 6, str(f['occurrence_count']), 1, 0, 'C', fill)
                pdf.cell(30, 6, str(f['total_duration_mins']), 1, 1, 'C', fill)
        else:
            pdf.set_font("Helvetica", "I", 7)
            pdf.cell(
                0, 6, "No specific fault events identified during this window.", 1, 1)
        pdf.ln(6)

    return dcc.send_bytes(pdf.output(dest='S').encode('latin-1'), f"{crane_id}_MMBF_Report.pdf")


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
