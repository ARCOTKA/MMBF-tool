import dash
from dash import Input, Output, State, dcc
import pandas as pd
import plotly.express as px
import os
import base64
import math

# Import Logic and UI Modules
# mmbf_logic now exposes the class and some helpers
from mmbf_logic import ForensicAnalyzer, BASE_DIR, DEFAULT_MIN_DURATION, load_default_whitelist, parse_whitelist_content, generate_pdf_report_bytes, MANUAL_MODE_INDEX, PAGE_SIZE
import mmbf_ui as ui

# --- INITIALIZATION ---
app = dash.Dash(__name__, title="MMBF Tool")
server = app.server

# Load Layout from UI Module
app.layout = ui.get_layout()

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

    # Initialize whitelist if empty on first load
    if not current_wl_data:
        current_wl_data = load_default_whitelist()

    if ctx.triggered and 'upload-db' in ctx.triggered[0]['prop_id'] and db_content:
        try:
            content_type, content_string = db_content.split(',')
            decoded = base64.b64decode(content_string)
            temp_path = os.path.join(BASE_DIR, f'temp_loaded_{db_name}')
            with open(temp_path, 'wb') as f:
                f.write(decoded)
            current_db_path = temp_path

            # Use class context to initialize tables
            with ForensicAnalyzer(current_db_path, read_only=False) as analyzer:
                analyzer.init_metadata_tables()

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

    # Use class context to get date range
    with ForensicAnalyzer(current_db_path) as analyzer:
        min_date, max_date = analyzer.get_db_date_range()

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

    # Open Analyzer Context
    with ForensicAnalyzer(db_path, read_only=False) as analyzer:
        if ctx.triggered and 'save-moves-btn' in ctx.triggered[0]['prop_id'] and manual_val is not None:
            analyzer.set_manual_override(crane_id, manual_val)

        whitelist_indices = {int(x['alarm_index'])
                             for x in whitelist_data} if whitelist_data else set()

        moves = analyzer.get_refined_move_count(crane_id, start_date, end_date)
        df_s, details = analyzer.get_maintenance_sessions(
            crane_id, start_date, end_date, whitelist_indices, min_duration)

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

    with ForensicAnalyzer(db_path, read_only=False) as analyzer:
        if ticked_fault:
            analyzer.update_forensic_metadata(
                crane_id, start_ts, True, ticked_fault['alarm_index'], ticked_fault['description'])
        else:
            analyzer.update_forensic_metadata(crane_id, start_ts, False, 0, "")

    for row in session_store:
        if str(row['session_id']) == sid:
            row['mmbf_tag'] = 'Yes' if ticked_fault else 'No'
            if ticked_fault:
                row['primary_issue'], row['primary_index'] = ticked_fault['description'], ticked_fault['alarm_index']
    mmbf_count = sum(1 for r in session_store if r['mmbf_tag'] == 'Yes')
    mmbf_val = f"{(mmbf_count / (total_moves / 1000)):.2f}" if total_moves > 0 else "0.00"
    return session_store, mmbf_val, str(mmbf_count)


@app.callback(
    [Output('transient-table', 'data'), Output('transient-raw-store', 'data'),
     Output('nuisance-table', 'data'), Output('critical-table', 'data')],
    [Input('tabs-main', 'value'), Input('transient-scope-toggle', 'value'),
     Input('nuisance-scope-toggle',
           'value'), Input('critical-scope-toggle', 'value'),
     Input('crane-selector', 'value'), Input('date-picker', 'start_date'), Input('date-picker', 'end_date')],
    [State('current-db-path', 'data'), State('whitelist-data-store', 'data'),
     State('session-store', 'data'), State('details-store', 'data')]
)
def update_insights_tab_data(tab, trans_scope, nuis_scope, crit_scope, crane_id, start, end, db_path, whitelist_data, session_data, details_data):
    if tab != 'tab-insights':
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update

    whitelist_indices = {int(x['alarm_index'])
                         for x in whitelist_data} if whitelist_data else set()

    with ForensicAnalyzer(db_path) as analyzer:
        summary_df, raw_df = analyzer.get_transient_faults(
            crane_id, start, end, whitelist_indices, only_whitelist=False)

    raw_records = []
    if not raw_df.empty:
        df_store = raw_df.copy()
        df_store['start_ts'] = df_store['start_ts'].astype(str)
        raw_records = df_store.to_dict('records')

    # Insights Generation
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
        grp = df_crit.groupby(['alarm_index', 'description', 'is_whitelisted'])
        for (idx, desc, wl), g in grp:
            sessions = sorted(g['session_id'].unique())
            freq = len(sessions)
            critical_table_data.append({
                'alarm_index': idx, 'description': desc, 'frequency': freq,
                'sessions': ", ".join(map(str, sessions)), 'is_whitelisted': wl
            })
        critical_table_data.sort(key=lambda x: x['frequency'], reverse=True)

    nuisance_data = []
    critical_map = {row['alarm_index']: row['frequency']
                    for row in critical_table_data}

    if not summary_df.empty:
        chatter_counts = summary_df[['alarm_index', 'description',
                                     'frequency', 'avg_duration_sec', 'is_whitelisted']].copy()
        chatter_counts['stop_count'] = chatter_counts['alarm_index'].map(
            critical_map).fillna(0)
        nuisance_df = chatter_counts[chatter_counts['stop_count'] == 0].copy()
        nuisance_df = nuisance_df.sort_values('frequency', ascending=False)
        nuisance_data = nuisance_df.to_dict('records')

    if nuis_scope == 'WL':
        nuisance_data = [row for row in nuisance_data if row.get(
            'is_whitelisted') == 'True']
    if crit_scope == 'WL':
        critical_table_data = [
            row for row in critical_table_data if row.get('is_whitelisted') == 'True']
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

    df_raw = pd.DataFrame(raw_data)
    df_raw = df_raw[df_raw['alarm_index'] == idx].copy()

    if df_raw.empty:
        return {}, f"No detail data for {desc}"

    df_raw['start_ts'] = pd.to_datetime(df_raw['start_ts'])
    df_raw.set_index('start_ts', inplace=True)
    df_resampled = df_raw.resample('h').size().reset_index(name='count')

    fig = px.bar(
        df_resampled, x='start_ts', y='count',
        title=f"Chatter Frequency: {desc} ({idx})",
        labels={'start_ts': 'Time', 'count': 'Fault Count (per Hour)'}
    )
    fig.update_layout(bargap=0.1, margin=dict(l=40, r=40, t=40, b=40))
    fig.update_traces(marker_color='#f59e0b')
    return fig, f"Trend Analysis for: {desc}"


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

    with ForensicAnalyzer(db_path) as analyzer:
        df_logs = analyzer.get_explorer_logs(crane_id, start, end, idx_filter,
                                             desc_filter, whitelist_indices, only_whitelist=only_whitelist)

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
    # Logic delegated to mmbf_logic to keep Main clean
    pdf_bytes = generate_pdf_report_bytes(
        session_data, details_data, crane_id, total_moves, start_date, end_date, mmbf_val)
    if pdf_bytes:
        return dcc.send_bytes(pdf_bytes, f"{crane_id}_MMBF_Report.pdf")
    return dash.no_update


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
