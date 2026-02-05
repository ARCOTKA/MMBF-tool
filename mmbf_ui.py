from dash import dcc, html, dash_table
from mmbf_logic import DEFAULT_DB_PATH, CRANE_LIST, PAGE_SIZE, DEFAULT_MIN_DURATION

# --- STYLING CONSTANTS ---
FIXED_TABLE_STYLE = {
    'textAlign': 'left',
    'fontSize': '11px',
    'padding': '8px',
    'whiteSpace': 'normal',
    'height': 'auto',
    'verticalAlign': 'top'
}

upload_btn_style = {
    'display': 'inline-block', 'width': '140px', 'padding': '8px', 'lineHeight': '16px',
    'border': '1px solid #475569', 'borderRadius': '4px', 'textAlign': 'center', 'cursor': 'pointer',
    'backgroundColor': '#334155', 'color': '#f1f5f9', 'fontSize': '12px', 'fontWeight': '600',
    'margin': '0 5px', 'boxShadow': '0 1px 2px rgba(0,0,0,0.2)'
}


def get_layout():
    return html.Div(style={'fontFamily': 'Segoe UI, Arial', 'backgroundColor': '#f4f7f9', 'minHeight': '100vh'}, children=[
        dcc.Store(id='session-store'),
        dcc.Store(id='details-store'),
        dcc.Store(id='moves-store'),
        dcc.Store(id='transient-raw-store'),
        dcc.Store(id='current-db-path', data=DEFAULT_DB_PATH),
        dcc.Store(id='whitelist-data-store'),
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
                          dcc.Input(id='min-duration-input', type='number', value=DEFAULT_MIN_DURATION, min=0, step=1, style={'width': '100px', 'color': '#1e293b', 'borderRadius': '4px', 'border': 'none', 'padding': '4px'})])
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
                                  dash_table.DataTable(id='session-table', sort_action="native", filter_action="native", row_selectable="single", page_size=10, style_header={'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'},
                                  style_cell=FIXED_TABLE_STYLE,
                                  style_table={
                                      'minHeight': '350px', 'overflowX': 'auto'},
                                  style_cell_conditional=[
                                      {'if': {'column_id': 'primary_issue'},
                                          'width': '350px'},
                                      {'if': {'column_id': 'session_id'},
                                          'width': '80px'},
                                      {'if': {'column_id': 'session_duration_mins'},
                                          'width': '120px'}
                                  ],
                                  style_data_conditional=[{'if': {'column_id': 'mmbf_tag', 'filter_query': '{mmbf_tag} eq "Yes"'}, 'backgroundColor': '#fee2e2', 'color': '#b91c1c', 'fontWeight': 'bold'}])]),
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
                            dash_table.DataTable(id='detail-table', sort_action="native", filter_action="native", editable=True, page_size=10, style_header={'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'},
                                                 style_cell=FIXED_TABLE_STYLE,
                                                 style_table={
                                                     'minHeight': '350px', 'overflowX': 'auto'},
                                                 style_cell_conditional=[
                                {'if': {'column_id': 'description'},
                                    'width': '400px'},
                                {'if': {'column_id': 'alarm_index'}, 'width': '80px'},
                                {'if': {'column_id': 'total_duration_mins'},
                                    'width': '100px'}
                            ],
                                dropdown={'mmbf_tick': {'options': [{'label': 'YES', 'value': True}, {'label': 'NO', 'value': False}]}})
                        ])
                    ])
                ]))
            ]),

            # TAB 2: INSIGHTS
            dcc.Tab(label='Insights & Predictive', value='tab-insights', children=[
                dcc.Loading(id="loading-transient", type="default", color="#1e293b", children=html.Div(style={'padding': '20px', 'minHeight': '800px'}, children=[

                    # --- INSIGHTS SECTION ---
                    html.Div(style={'marginBottom': '30px'}, children=[
                        html.H2("Maintenance Strategy Insights", style={
                                'color': '#1e293b', 'marginTop': 0}),
                        html.Div(style={'display': 'flex', 'gap': '20px'}, children=[
                            # Table 1: Nuisance Alarms
                            html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'minHeight': '550px'}, children=[
                                html.H3("⚠️ Nuisance Alarms (High Chatter, No Stops)", style={
                                        'fontSize': '16px', 'fontWeight': 'bold', 'color': '#d97706'}),
                                html.P("Frequent alarms that almost never result in maintenance.", style={
                                       'fontSize': '12px', 'color': '#64748b'}),
                                html.Div(style={'marginBottom': '10px'}, children=[
                                    html.Label("Filter:", style={
                                               'fontSize': '12px', 'fontWeight': 'bold', 'marginRight': '5px'}),
                                    dcc.RadioItems(id='nuisance-scope-toggle', options=[{'label': ' All', 'value': 'ALL'}, {
                                                   'label': ' Whitelist', 'value': 'WL'}], value='WL', inline=True, style={'fontSize': '12px', 'display': 'inline-block'})
                                ]),
                                dash_table.DataTable(
                                    id='nuisance-table', sort_action="native", page_size=8,
                                    style_header={
                                        'backgroundColor': '#f59e0b', 'color': 'white', 'fontWeight': 'bold'},
                                    style_cell=FIXED_TABLE_STYLE,
                                    style_table={
                                        'minHeight': '400px', 'overflowX': 'auto'},
                                    style_cell_conditional=[
                                        {'if': {'column_id': 'description'}, 'width': '250px'}],
                                    style_data_conditional=[{'if': {
                                        'filter_query': '{is_whitelisted} eq "True"'}, 'fontWeight': 'bold', 'fontStyle': 'italic', 'color': '#0369a1'}],
                                    columns=[{"name": "Idx", "id": "alarm_index"}, {"name": "Description", "id": "description"}, {
                                        "name": "Freq", "id": "frequency"}, {"name": "Avg Clear Time (sec)", "id": "avg_duration_sec"}]
                                )
                            ]),
                            # Table 2: Critical Failures
                            html.Div(style={'flex': 1, 'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '8px', 'boxShadow': '0 1px 3px rgba(0,0,0,0.1)', 'minHeight': '550px'}, children=[
                                html.H3("🛑 Critical Failures (Major Stops)", style={
                                        'fontSize': '16px', 'fontWeight': 'bold', 'color': '#dc2626'}),
                                html.P("Top faults that certainly result in downtime (From Internal Fault Analysis).", style={
                                       'fontSize': '12px', 'color': '#64748b'}),
                                html.Div(style={'marginBottom': '10px'}, children=[
                                    html.Label("Filter:", style={
                                               'fontSize': '12px', 'fontWeight': 'bold', 'marginRight': '5px'}),
                                    dcc.RadioItems(id='critical-scope-toggle', options=[{'label': ' All', 'value': 'ALL'}, {
                                                   'label': ' Whitelist', 'value': 'WL'}], value='WL', inline=True, style={'fontSize': '12px', 'display': 'inline-block'})
                                ]),
                                dash_table.DataTable(
                                    id='critical-table', sort_action="native", page_size=8,
                                    style_header={
                                        'backgroundColor': '#ef4444', 'color': 'white', 'fontWeight': 'bold'},
                                    style_cell=FIXED_TABLE_STYLE,
                                    style_table={
                                        'minHeight': '400px', 'overflowX': 'auto'},
                                    style_cell_conditional=[
                                        {'if': {'column_id': 'description'}, 'width': '250px'}],
                                    style_data_conditional=[{'if': {
                                        'filter_query': '{is_whitelisted} eq "True"'}, 'fontWeight': 'bold', 'fontStyle': 'italic', 'color': '#0369a1'}],
                                    columns=[{"name": "Idx", "id": "alarm_index"}, {"name": "Description", "id": "description"}, {
                                        "name": "Frequency", "id": "frequency"}, {"name": "Sessions", "id": "sessions"}]
                                )
                            ])
                        ])
                    ]),

                    # --- TRANSIENT SECTION ---
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
                        html.Div(style={'flex': 1, 'minHeight': '550px'}, children=[
                            html.H3("Fault Frequency Table", style={
                                    'fontSize': '16px', 'fontWeight': 'bold', 'marginBottom': '10px'}),
                            dash_table.DataTable(
                                id='transient-table', sort_action="native", filter_action="native", row_selectable="single", page_size=8,
                                style_header={
                                    'backgroundColor': '#f59e0b', 'color': 'white', 'fontWeight': 'bold'},
                                style_cell=FIXED_TABLE_STYLE,
                                style_table={'minHeight': '500px',
                                             'overflowX': 'auto'},
                                style_cell_conditional=[
                                    {'if': {'column_id': 'description'}, 'width': '300px'}],
                                style_data_conditional=[{'if': {
                                    'column_id': 'avg_duration_sec', 'filter_query': '{avg_duration_sec} < 1'}, 'color': '#d97706', 'fontWeight': 'bold'}],
                                columns=[
                                    {"name": "Index", "id": "alarm_index"}, {
                                        "name": "Description", "id": "description"},
                                    {"name": "Frequency (Count)", "id": "frequency"}, {
                                        "name": "Avg Dur (s)", "id": "avg_duration_sec"},
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
                                             'backgroundColor': '#dc2626', 'color': 'white', 'fontWeight': 'bold'},
                                             style_cell=FIXED_TABLE_STYLE,
                                             style_table={
                                                 'minHeight': '600px', 'overflowX': 'auto'},
                                             style_cell_conditional=[
                                                 {'if': {'column_id': 'description'}, 'width': '350px'}]
                                             )
                    ])
                ]))
            ])
        ]),
        dcc.Download(id="download-pdf-report")
    ])
