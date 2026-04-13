// FlowTrust — frontend (v2: потоковый терминал, DLL viewer, rootkit, файловый менеджер, VT)
'use strict';

const { invoke } = window.__TAURI__.tauri;
const { open }   = window.__TAURI__.shell;
const { listen } = window.__TAURI__.event;
const appWindow  = window.__TAURI__.window.appWindow;

// ══════════════════════════════════════════════════════════════════════════════
// ── i18n ──────────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const TR = {
  ru: {
    tab_analysis:'АНАЛИЗ', tab_network:'СЕТЬ', tab_startup:'АВТОЗАГРУЗКА',
    tab_forensics:'ФОРЕНЗИКА', tab_settings:'НАСТРОЙКИ', tab_about:'О ПРОГРАММЕ',
    tab_unlock:'РАЗБЛОКИРОВКА', tab_tools:'ИНСТРУМЕНТЫ',
    tab_filemanager:'ФАЙЛЫ',
    header_total:'Процессов', header_critical:'Критичных', header_threats:'Угроз',
    refresh:'↻ ОБНОВИТЬ', auto_off:'АВТО: ВЫКЛ', auto_on:'АВТО: ВКЛ',
    tree_view:'🌳 ДЕРЕВО', export_btn:'↓ ЭКСПОРТ',
    shown:'Показано', connections:'Соединений', startup_records:'Записей', threats_count:'Угроз',
    scan:'↻ СКАНИРОВАТЬ',
    search_proc:'Поиск по имени, PID, пользователю...',
    search_net:'Поиск по процессу, адресу, порту...',
    search_startup:'Поиск по имени, команде...',
    search_forensics:'Поиск по процессу, угрозе...',
    col_pid:'PID', col_process:'ПРОЦЕСС', col_user:'ПОЛЬЗОВАТЕЛЬ', col_status:'СТАТУС',
    col_cpu:'CPU', col_mem:'ПАМЯТЬ', col_name:'ИМЯ', col_hive:'КУСТ',
    col_regkey:'КЛЮЧ / ЗАДАЧА', col_command:'КОМАНДА', col_proto:'ПРОТОКОЛ',
    col_local:'ЛОКАЛЬНЫЙ', col_remote:'УДАЛЁННЫЙ', col_state:'СОСТОЯНИЕ',
    col_threat:'ТИП УГРОЗЫ', col_severity:'КРИТИЧНОСТЬ', col_risk:'РИСК', col_desc:'ОПИСАНИЕ',
    col_source:'ИСТОЧНИК', col_restriction:'ОГРАНИЧЕНИЕ', col_rest_desc:'ОПИСАНИЕ ОГРАНИЧЕНИЯ',
    col_rest_status:'СТАТУС',
    detail_path:'ПУТЬ', detail_sig:'ПОДПИСЬ', chart_history:'ИСТОРИЯ НАГРУЗКИ',
    kill_btn:'⊘ ЗАВЕРШИТЬ ПРОЦЕСС', ctx_open_location:'📂 ОТКРЫТЬ РАСПОЛОЖЕНИЕ',
    dll_view_btn:'📦 ПРОСМОТР DLL',
    uncrit_btn:'🛡 СНЯТЬ КРИТИЧНОСТЬ',
    uncrit_checking:'Проверка критичности...',
    uncrit_is_critical:'⚠ Процесс помечен как критичный. При завершении — BSOD.',
    uncrit_not_critical:'✓ Процесс не критичен.',
    uncrit_success:'✓ Критичность снята. Теперь процесс можно завершить без BSOD.',
    uncrit_error:'Ошибка: ',
    uncrit_no_access:'Нет доступа для проверки (требуется администратор)',
    sig_checking:'ПРОВЕРКА...', sig_trusted:'✓ ПОДПИСАН', sig_untrusted:'✗ НЕ ПОДПИСАН', sig_unknown:'? НЕИЗВЕСТНО',
    status_critical:'Критичный', status_system:'Система', status_suspicious:'Подозрит.', status_secure:'Безопасен',
    status_critical_long:'Критичный', status_system_long:'Система', status_suspicious_long:'Подозрительный', status_secure_long:'Безопасен',
    wait_refresh:'Нажмите ОБНОВИТЬ для загрузки соединений',
    wait_scan:'Нажмите СКАНИРОВАТЬ для анализа угроз',
    wait_startup:'Нажмите ОБНОВИТЬ',
    wait_first:'Ожидание первого обновления...',
    loading:'Получение данных...', loading_registry:'Чтение реестра...', loading_net:'Загрузка...', loading_threats:'Анализ угроз...',
    no_processes:'Процессы не найдены', no_connections:'Нет данных', no_entries:'Записей нет', no_threats:'Угроз не обнаружено',
    error:'Ошибка', initializing:'Инициализация...',
    status_active:'АКТИВЕН', footer_critical:'Критичных', footer_threats:'Угроз', footer_total:'Всего',
    ctx_details:'Подробнее', ctx_kill:'Завершить процесс', ctx_copy_pid:'Копировать PID', ctx_copy_path:'Копировать путь',
    ctx_uncrit:'🛡 Снять критичность',
    ctx_edit:'Изменить параметр', ctx_delete_entry:'Удалить параметр', ctx_delete_file:'Удалить файл', ctx_refresh:'Обновить',
    ctx_kill_conn:'✕ Разорвать соединение',
    threat_masq:'Маскировка', threat_sus_path:'Подозр. путь', threat_no_img:'Нет образа', threat_unsigned:'Без подписи',
    sev_critical:'КРИТИЧНО', sev_high:'ВЫСОКИЙ', sev_medium:'СРЕДНИЙ', sev_low:'НИЗКИЙ',
    settings_general:'ОБЩИЕ', settings_masquerade:'МАСКИРОВКА', settings_lang:'ЯЗЫК / LANGUAGE',
    settings_always_on_top:'Поверх всех окон', settings_always_on_top_desc:'Приложение отображается поверх других окон',
    settings_check_updates:'Проверять обновления при запуске', settings_check_updates_desc:'Автоматическая проверка новых версий',
    settings_notify:'Уведомления об угрозах', settings_notify_desc:'Уведомление при обнаружении новых угроз в форензике',
    settings_rotate_name:'Периодически менять заголовок окна', settings_rotate_name_desc:'Каждые 90 секунд заголовок окна меняется — для обхода мониторинга',
    settings_minimize_tray:'Сворачивать в трей', settings_minimize_tray_desc:'При закрытии окна скрыть в системный трей',
    settings_analysis:'АНАЛИЗ ПРОЦЕССОВ', settings_export_sec:'ЭКСПОРТ',
    settings_auto_refresh:'Автообновление', settings_auto_refresh_desc:'Автоматически обновлять список процессов',
    settings_refresh_interval:'Интервал обновления', settings_refresh_interval_desc:'Период автообновления в секундах',
    settings_show_signed:'Подписанные в форензике', settings_show_signed_desc:'Показывать процессы с подписью в форензике',
    settings_auto_scan:'Автосканирование угроз', settings_auto_scan_desc:'Запускать форензику при открытии вкладки',
    settings_export_format:'Формат экспорта', settings_export_format_desc:'Формат файла при экспорте данных',
    about_desc:'FlowTrust — профессиональный инструмент мониторинга процессов и форензики для Windows. Анализирует запущенные процессы, сетевые соединения, записи автозагрузки и выявляет потенциальные угрозы безопасности.',
    donate_btn:'❤ ПОДДЕРЖАТЬ РАЗРАБОТЧИКА', tg_contact:'✈ TELEGRAM @Jimmy_Hawkins', tg_channel:'📢 TELEGRAM-КАНАЛ',
    af_processes:'Мониторинг процессов с деревом зависимостей и графиками CPU/RAM',
    af_network:'Анализ сетевых соединений TCP/UDP в реальном времени',
    af_startup:'Управление записями автозагрузки реестра Windows',
    af_forensics:'Форензика: проверка цифровых подписей и детектирование угроз',
    updated_at:'Обновлено', upd_no_updates:'Обновлений нет. Установлена последняя версия.',
    confirm_kill:'Завершить', pid:'PID', confirm_del_entry:'Удалить запись автозагрузки',
    confirm_del_file:'Удалить файл с диска', export_path_prompt:'Сохранить отчёт как:',
    export_ok:'Отчёт сохранён:', export_err:'Ошибка сохранения:',
    new_threats_title:'FlowTrust — Новые угрозы', new_threats_body:'обнаружено угроз',
    unlock_check:'⟳ ПРОВЕРИТЬ СТАТУС', unlock_all:'🔓 РАЗБЛОКИРОВАТЬ ВСЕ', unlock_selected:'✓ РАЗБЛОКИРОВАТЬ ВЫБРАННЫЕ',
    rest_active:'АКТИВНО', rest_removed:'СНЯТО', rest_unknown:'НЕИЗВЕСТНО',
    unlock_checking:'Проверка...', unlock_done:'Снято', unlock_ok:'Снято успешно', unlock_err:'Ошибка снятия',
    tool_sfc:'🛡 SFC /scannow', tool_mbr:'💾 Восстановить MBR', tool_bcd:'⚙ Перестроить BCD',
    tool_accessibility:'🔑 Восстановить sethc / utilman', tool_logonui:'🖥 Восстановить LogonUI',
    tool_fonts:'🔤 Починить шрифты', tool_uac:'🛡 Включить UAC', tool_assoc:'🔗 Восстановить ассоциации файлов',
    tool_keyboard:'⌨ Восстановить клавиатуру', tool_mouse:'🖱 Восстановить мышь',
    tool_hosts:'📄 Сбросить Hosts-файл', tool_proxy:'🌐 Сбросить прокси',
    tool_running:'Выполнение...', tool_clear:'✕ ОЧИСТИТЬ ВЫВОД',
    tool_output:'ВЫВОД', tools_browser:'БРАУЗЕР', tool_browser_open:'🌐 ОТКРЫТЬ',
    tools_integrity:'ЦЕЛОСТНОСТЬ СИСТЕМЫ', tools_system:'НАСТРОЙКИ СИСТЕМЫ',
    tools_rootkit:'ОБНАРУЖЕНИЕ РУТКИТОВ', tools_dll:'ПРОСМОТР DLL ПРОЦЕССА',
    tool_hidden_procs:'🔍 Найти скрытые процессы', tool_hidden_result:'РЕЗУЛЬТАТ СКАНИРОВАНИЯ',
    tools_rootkit_hint:'Сравнивает TlHelp32 и PSAPI, затем brute-force сканирует PID 4–65535. Скрытым считается процесс с видимым путём к образу, но отсутствующий в стандартных списках.',
    tools_dll_hint:'Введите PID процесса и нажмите «ЗАГРУЗИТЬ DLL». Можно также нажать «ПРОСМОТР DLL» в панели деталей процесса — PID подставится автоматически. Требуются права администратора для системных процессов.',
    dll_load_btn:'📦 ЗАГРУЗИТЬ DLL',
    su_all:'ВСЕ', su_registry:'РЕЕСТР', su_winlogon:'WINLOGON', su_appinit:'APPINIT', su_tasks:'ЗАДАЧИ',
    src_registry_run:'Run', src_registry_run_once:'RunOnce', src_winlogon:'Winlogon',
    src_app_init_dlls:'AppInit', src_scheduled_task:'Задача',
    fo_vt_btn:'🔎 VirusTotal', fo_quarantine_btn:'📦 Карантин', fo_delete_btn:'✕ Удалить',
    fo_vt_loading:'⏳ Хэш...', fo_quarantine_ok:'Перемещено в карантин:', fo_quarantine_err:'Ошибка карантина:',
    fo_no_selection:'Выберите строку в таблице угроз',
    fm_new_folder:'+ Папка', fm_copy:'Копировать', fm_paste:'Вставить', fm_delete:'Удалить', fm_rename:'Переим.',
    fm_select_drive:'Выберите диск', fm_loading:'Загрузка...', fm_error:'Ошибка', fm_empty:'Папка пуста',
    fm_confirm_delete:'Удалить?', fm_new_folder_prompt:'Имя новой папки:',
    fm_rename_prompt:'Новое имя:', fm_copied:'Скопировано в буфер',
    fm_search_empty:'Ничего не найдено', fm_status_dirs:'папок', fm_status_files:'файлов',
    fm_items:'элем.',
    fm_ctx_open_dir:'📂 Открыть', fm_ctx_open_file:'▶ Открыть расположение',
    fm_ctx_copy:'⎘ Копировать', fm_ctx_rename:'✎ Переименовать',
    fm_ctx_delete:'✕ Удалить', fm_ctx_vt:'🔎 VirusTotal',
  },
  en: {
    tab_analysis:'ANALYSIS', tab_network:'NETWORK', tab_startup:'STARTUP',
    tab_forensics:'FORENSICS', tab_settings:'SETTINGS', tab_about:'ABOUT',
    tab_unlock:'UNBLOCK', tab_tools:'TOOLS',
    tab_filemanager:'FILES',
    header_total:'Processes', header_critical:'Critical', header_threats:'Threats',
    refresh:'↻ REFRESH', auto_off:'AUTO: OFF', auto_on:'AUTO: ON',
    tree_view:'🌳 TREE', export_btn:'↓ EXPORT',
    shown:'Shown', connections:'Connections', startup_records:'Entries', threats_count:'Threats',
    scan:'↻ SCAN',
    search_proc:'Search by name, PID, user...',
    search_net:'Search by process, address, port...',
    search_startup:'Search by name, command...',
    search_forensics:'Search by process, threat...',
    col_pid:'PID', col_process:'PROCESS', col_user:'USER', col_status:'STATUS',
    col_cpu:'CPU', col_mem:'MEMORY', col_name:'NAME', col_hive:'HIVE',
    col_regkey:'KEY / TASK', col_command:'COMMAND', col_proto:'PROTOCOL',
    col_local:'LOCAL', col_remote:'REMOTE', col_state:'STATE',
    col_threat:'THREAT TYPE', col_severity:'SEVERITY', col_risk:'RISK', col_desc:'DESCRIPTION',
    col_source:'SOURCE', col_restriction:'RESTRICTION', col_rest_desc:'DESCRIPTION',
    col_rest_status:'STATUS',
    detail_path:'PATH', detail_sig:'SIGNATURE', chart_history:'LOAD HISTORY',
    kill_btn:'⊘ TERMINATE PROCESS', ctx_open_location:'📂 OPEN LOCATION',
    dll_view_btn:'📦 VIEW DLLs',
    uncrit_btn:'🛡 REMOVE CRITICALITY',
    uncrit_checking:'Checking criticality...',
    uncrit_is_critical:'⚠ Process is marked as critical. Terminating it will cause BSOD.',
    uncrit_not_critical:'✓ Process is not critical.',
    uncrit_success:'✓ Criticality removed. The process can now be terminated without BSOD.',
    uncrit_error:'Error: ',
    uncrit_no_access:'No access to check (admin required)',
    sig_checking:'CHECKING...', sig_trusted:'✓ SIGNED', sig_untrusted:'✗ UNSIGNED', sig_unknown:'? UNKNOWN',
    status_critical:'Critical', status_system:'System', status_suspicious:'Suspicious', status_secure:'Secure',
    status_critical_long:'Critical', status_system_long:'System', status_suspicious_long:'Suspicious', status_secure_long:'Secure',
    wait_refresh:'Click REFRESH to load connections',
    wait_scan:'Click SCAN to analyze threats',
    wait_startup:'Click REFRESH',
    wait_first:'Waiting for first refresh...',
    loading:'Fetching data...', loading_registry:'Reading registry...', loading_net:'Loading...', loading_threats:'Analyzing threats...',
    no_processes:'No processes found', no_connections:'No data', no_entries:'No entries', no_threats:'No threats detected',
    error:'Error', initializing:'Initializing...',
    status_active:'ACTIVE', footer_critical:'Critical', footer_threats:'Threats', footer_total:'Total',
    ctx_details:'Details', ctx_kill:'Terminate process', ctx_copy_pid:'Copy PID', ctx_copy_path:'Copy path',
    ctx_uncrit:'🛡 Remove criticality',
    ctx_edit:'Edit entry', ctx_delete_entry:'Delete entry', ctx_delete_file:'Delete file', ctx_refresh:'Refresh',
    ctx_kill_conn:'✕ Kill connection',
    threat_masq:'Masquerading', threat_sus_path:'Suspicious path', threat_no_img:'No image', threat_unsigned:'Unsigned',
    sev_critical:'CRITICAL', sev_high:'HIGH', sev_medium:'MEDIUM', sev_low:'LOW',
    settings_general:'GENERAL', settings_masquerade:'MASQUERADE', settings_lang:'ЯЗЫК / LANGUAGE',
    settings_always_on_top:'Always on top', settings_always_on_top_desc:'Window stays on top of other windows',
    settings_check_updates:'Check for updates on startup', settings_check_updates_desc:'Automatically check for new versions',
    settings_notify:'Threat notifications', settings_notify_desc:'Notify when new threats are detected',
    settings_rotate_name:'Rotate window title', settings_rotate_name_desc:'Changes window title every 90 seconds to avoid monitoring',
    settings_minimize_tray:'Minimize to tray', settings_minimize_tray_desc:'Hide to system tray when window is closed',
    settings_analysis:'PROCESS ANALYSIS', settings_export_sec:'EXPORT',
    settings_auto_refresh:'Auto refresh', settings_auto_refresh_desc:'Automatically refresh process list',
    settings_refresh_interval:'Refresh interval', settings_refresh_interval_desc:'Auto-refresh period in seconds',
    settings_show_signed:'Signed in forensics', settings_show_signed_desc:'Show signed processes in forensics results',
    settings_auto_scan:'Auto-scan threats', settings_auto_scan_desc:'Run forensics when switching to the tab',
    settings_export_format:'Export format', settings_export_format_desc:'File format when exporting data',
    about_desc:'FlowTrust — professional process monitoring and forensics tool for Windows.',
    donate_btn:'❤ SUPPORT DEVELOPER', tg_contact:'✈ TELEGRAM @Jimmy_Hawkins', tg_channel:'📢 TELEGRAM CHANNEL',
    af_processes:'Process monitoring with dependency tree and CPU/RAM charts',
    af_network:'Real-time TCP/UDP network connection analysis',
    af_startup:'Windows registry autostart management',
    af_forensics:'Forensics: digital signature verification and threat detection',
    updated_at:'Updated', upd_no_updates:'No updates. Latest version installed.',
    confirm_kill:'Terminate', pid:'PID', confirm_del_entry:'Delete startup entry',
    confirm_del_file:'Delete file from disk', export_path_prompt:'Save report as:',
    export_ok:'Report saved:', export_err:'Save error:',
    new_threats_title:'FlowTrust — Threats detected', new_threats_body:'threats found',
    unlock_check:'⟳ CHECK STATUS', unlock_all:'🔓 UNLOCK ALL', unlock_selected:'✓ UNLOCK SELECTED',
    rest_active:'ACTIVE', rest_removed:'REMOVED', rest_unknown:'UNKNOWN',
    unlock_checking:'Checking...', unlock_done:'Removed', unlock_ok:'Removed successfully', unlock_err:'Error removing',
    tool_sfc:'🛡 SFC /scannow', tool_mbr:'💾 Restore MBR', tool_bcd:'⚙ Rebuild BCD',
    tool_accessibility:'🔑 Restore sethc / utilman', tool_logonui:'🖥 Restore LogonUI',
    tool_fonts:'🔤 Repair fonts', tool_uac:'🛡 Enable UAC', tool_assoc:'🔗 Restore file associations',
    tool_keyboard:'⌨ Restore keyboard', tool_mouse:'🖱 Restore mouse',
    tool_hosts:'📄 Reset Hosts file', tool_proxy:'🌐 Reset proxy',
    tool_running:'Running...', tool_clear:'✕ CLEAR OUTPUT',
    tool_output:'OUTPUT', tools_browser:'BROWSER', tool_browser_open:'🌐 OPEN',
    tools_integrity:'SYSTEM INTEGRITY', tools_system:'SYSTEM SETTINGS',
    tools_rootkit:'ROOTKIT DETECTION', tools_dll:'PROCESS DLL VIEWER',
    tool_hidden_procs:'🔍 Find hidden processes', tool_hidden_result:'SCAN RESULT',
    tools_rootkit_hint:'Compares TlHelp32 and PSAPI, then brute-force scans PIDs 4–65535. A process is considered hidden when it has a visible image path but is absent from standard enumeration lists.',
    tools_dll_hint:'Enter the process PID and click "LOAD DLLs". You can also click "DLL VIEW" in the process detail panel — the PID will be filled in automatically. Admin rights are required for system processes.',
    dll_load_btn:'📦 LOAD DLLs',
    su_all:'ALL', su_registry:'REGISTRY', su_winlogon:'WINLOGON', su_appinit:'APPINIT', su_tasks:'TASKS',
    src_registry_run:'Run', src_registry_run_once:'RunOnce', src_winlogon:'Winlogon',
    src_app_init_dlls:'AppInit', src_scheduled_task:'Task',
    fo_vt_btn:'🔎 VirusTotal', fo_quarantine_btn:'📦 Quarantine', fo_delete_btn:'✕ Delete',
    fo_vt_loading:'⏳ Hash...', fo_quarantine_ok:'Moved to quarantine:', fo_quarantine_err:'Quarantine error:',
    fo_no_selection:'Select a row in the threats table',
    fm_new_folder:'+ Folder', fm_copy:'Copy', fm_paste:'Paste', fm_delete:'Delete', fm_rename:'Rename',
    fm_select_drive:'Select a drive', fm_loading:'Loading...', fm_error:'Error', fm_empty:'Folder is empty',
    fm_confirm_delete:'Delete?', fm_new_folder_prompt:'New folder name:',
    fm_rename_prompt:'New name:', fm_copied:'Copied to clipboard',
    fm_search_empty:'Nothing found', fm_status_dirs:'folders', fm_status_files:'files',
    fm_items:'items',
    fm_ctx_open_dir:'📂 Open', fm_ctx_open_file:'▶ Open location',
    fm_ctx_copy:'⎘ Copy', fm_ctx_rename:'✎ Rename',
    fm_ctx_delete:'✕ Delete', fm_ctx_vt:'🔎 VirusTotal',
  }
};

let lang = localStorage.getItem('ft-lang') || 'ru';
const t = k => TR[lang][k] || TR.ru[k] || k;

function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const k = el.dataset.i18n;
    if (TR[lang][k] !== undefined) el.textContent = TR[lang][k];
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    const k = el.dataset.i18nPh;
    if (TR[lang][k]) el.placeholder = TR[lang][k];
  });
  document.getElementById('lang-btn').textContent = lang === 'ru' ? 'EN' : 'RU';
  document.querySelectorAll('.lang-choice').forEach(b => {
    b.classList.toggle('active', b.dataset.lang === lang);
  });
}

function setLang(newLang) {
  lang = newLang;
  localStorage.setItem('ft-lang', lang);
  applyI18n();
  renderTable(); renderNetTable(); renderStartupTable(); renderForensicsTable(); renderUnlockTable();
  // Фикс i18n бага: обновить строку статуса обновлений
  const updEl = document.getElementById('update-status');
  if (updEl && updEl.style.display !== 'none') updEl.textContent = t('upd_no_updates');
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Настройки ─────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const SETTINGS_KEY = 'ft-settings';
const cfg = Object.assign({
  alwaysOnTop: false, checkUpdates: true, notifyThreats: false, rotateName: false,
  minimizeTray: false, autoRefresh: false, refreshInterval: 5,
  showSigned: false, autoScan: false,
  exportFormat: 'json',
}, (() => { try { return JSON.parse(localStorage.getItem(SETTINGS_KEY)) || {}; } catch { return {}; } })());
function saveCfg() { localStorage.setItem(SETTINGS_KEY, JSON.stringify(cfg)); }

// ── Смена заголовка окна ──────────────────────────────────────────────────────

const UNICODE_RANGES = [
  [0x30A0, 0x30FF], [0x0391, 0x03C9], [0x0400, 0x045F],
  [0x2200, 0x22FF], [0x2600, 0x26FF], [0x4E00, 0x4E7F],
];
function randomUnicodeTitle() {
  const len   = 6 + Math.floor(Math.random() * 10);
  const range = UNICODE_RANGES[Math.floor(Math.random() * UNICODE_RANGES.length)];
  let s = '';
  for (let i = 0; i < len; i++) {
    const cp = range[0] + Math.floor(Math.random() * (range[1] - range[0] + 1));
    s += String.fromCodePoint(cp);
    if (i > 0 && i % 4 === 0) s += ' ';
  }
  return s.trim();
}
let titleRotateTimer = null;
function startTitleRotation() {
  if (titleRotateTimer) return;
  appWindow.setTitle(randomUnicodeTitle());
  titleRotateTimer = setInterval(() => appWindow.setTitle(randomUnicodeTitle()), 90000);
}
function stopTitleRotation() {
  clearInterval(titleRotateTimer); titleRotateTimer = null;
  appWindow.setTitle('FlowTrust');
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Состояние ─────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const state = {
  processes: [], filtered: [],
  sortCol: 'memory_mb', sortDir: 'desc',
  searchQuery: '', loading: false, autoRefresh: null,
  selectedProc: null, treeMode: false,
  procHistory: {},
  connections: [], netFiltered: [],
  netSortCol: 'state', netSortDir: 'asc',
  netSearchQuery: '', netLoading: false,
  startupEntries: [], startupFiltered: [],
  startupSearch: '', startupLoading: false,
  startupSourceFilter: 'all',
  threats: [], threatsFiltered: [],
  threatSearch: '', threatLoading: false,
  selectedThreatPath: '',
  prevThreatCount: 0,
};

const MAX_MEM_MB    = 4096;
const AUTO_INTERVAL = 5000;
const HISTORY_LEN   = 30;

// ══════════════════════════════════════════════════════════════════════════════
// ── DOM ───────────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const el = {
  tbody:           document.getElementById('process-tbody'),
  searchInput:     document.getElementById('search-input'),
  countDisplay:    document.getElementById('proc-count'),
  refreshBtn:      document.getElementById('refresh-btn'),
  autoBtn:         document.getElementById('auto-refresh-btn'),
  treeBtn:         document.getElementById('tree-view-btn'),
  exportProcBtn:   document.getElementById('export-proc-btn'),
  lastRefresh:     document.getElementById('last-refresh'),
  tabs:            document.querySelectorAll('.tab-btn'),
  panels:          document.querySelectorAll('.tab-panel'),
  detailPanel:     document.getElementById('detail-panel'),
  detailClose:     document.getElementById('detail-close'),
  dName:           document.getElementById('detail-name'),
  dPid:            document.getElementById('d-pid'),
  dStatus:         document.getElementById('d-status'),
  dUser:           document.getElementById('d-user'),
  dPath:           document.getElementById('d-path'),
  dSig:            document.getElementById('d-sig'),
  dCpu:            document.getElementById('d-cpu'),
  dMem:            document.getElementById('d-mem'),
  dKillBtn:        document.getElementById('d-kill-btn'),
  dOpenLocBtn:     document.getElementById('d-open-loc-btn'),
  dDllBtn:         document.getElementById('d-dll-btn'),
  dUncritBtn:      document.getElementById('d-uncrit-btn'),
  dUncritStatus:   document.getElementById('d-uncrit-status'),
  cpuChart:        document.getElementById('d-cpu-chart'),
  memChart:        document.getElementById('d-mem-chart'),
  netTbody:        document.getElementById('net-tbody'),
  netSearch:       document.getElementById('net-search'),
  netCount:        document.getElementById('net-count'),
  netRefreshBtn:   document.getElementById('net-refresh-btn'),
  startupTbody:    document.getElementById('startup-tbody'),
  startupSearch:   document.getElementById('startup-search'),
  startupCount:    document.getElementById('startup-count'),
  startupRefreshBtn: document.getElementById('startup-refresh-btn'),
  forensicsTbody:  document.getElementById('forensics-tbody'),
  forensicsSearch: document.getElementById('forensics-search'),
  forensicsCount:  document.getElementById('forensics-count'),
  forensicsRefreshBtn: document.getElementById('forensics-refresh-btn'),
  exportThreatsBtn: document.getElementById('export-threats-btn'),
  langBtn:         document.getElementById('lang-btn'),
  ctxMenu:         document.getElementById('ctx-menu'),
  sAlwaysOnTop:    document.getElementById('s-always-on-top'),
  sCheckUpdates:   document.getElementById('s-check-updates'),
  sNotifyThreats:  document.getElementById('s-notify-threats'),
  sRotateName:     document.getElementById('s-rotate-name'),
  donateBtn:       document.getElementById('donate-btn'),
  tgBtn:           document.getElementById('tg-btn'),
  tgChannelBtn:    document.getElementById('tg-channel-btn'),
};

// ══════════════════════════════════════════════════════════════════════════════
// ── Навигация ─────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

el.tabs.forEach(btn => {
  btn.addEventListener('click', () => {
    el.tabs.forEach(t => t.classList.remove('active'));
    el.panels.forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    const panel = document.getElementById('panel-' + btn.dataset.tab);
    if (panel) panel.classList.add('active');
    if (btn.dataset.tab === 'filemanager' && !fmState.currentPath) fmLoadDrives();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// ── Контекстное меню (глобальное) ─────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

let ctxCallback = null;
function showCtxMenu(e, items) {
  e.preventDefault(); e.stopPropagation();
  el.ctxMenu.innerHTML = items.map(item =>
    item.sep ? '<div class="ctx-separator"></div>' :
    `<div class="ctx-item${item.danger ? ' ctx-danger' : ''}" data-action="${item.action}">${escHtml(item.label)}</div>`
  ).join('');
  el.ctxMenu.querySelectorAll('.ctx-item').forEach(node => {
    node.addEventListener('click', () => {
      el.ctxMenu.style.display = 'none';
      if (ctxCallback) ctxCallback(node.dataset.action);
    });
  });
  const x = Math.min(e.clientX, window.innerWidth  - 210);
  const y = Math.min(e.clientY, window.innerHeight - (items.length * 32 + 16));
  el.ctxMenu.style.left    = Math.max(4, x) + 'px';
  el.ctxMenu.style.top     = Math.max(4, y) + 'px';
  el.ctxMenu.style.display = 'block';
}
document.addEventListener('click',       () => { el.ctxMenu.style.display = 'none'; });
document.addEventListener('contextmenu', e  => { if (!el.ctxMenu.contains(e.target)) el.ctxMenu.style.display = 'none'; });

// ══════════════════════════════════════════════════════════════════════════════
// ── Утилиты ───────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function formatMem(mb) {
  return mb >= 1024 ? (mb/1024).toFixed(1)+' GB' : mb.toFixed(0)+' MB';
}
function applySort(arr, col, dir) {
  return arr.sort((a, b) => {
    let av = a[col], bv = b[col];
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    if (av < bv) return dir === 'asc' ? -1 :  1;
    if (av > bv) return dir === 'asc' ?  1 : -1;
    return 0;
  });
}
function updateSortHeaders(selector, sortCol, sortDir, attr) {
  document.querySelectorAll(selector).forEach(th => {
    th.classList.remove('sort-asc', 'sort-desc');
    if (th.getAttribute(attr) === sortCol)
      th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
  });
}
function copyToClipboard(text) { navigator.clipboard.writeText(text).catch(() => {}); }

// ══════════════════════════════════════════════════════════════════════════════
// ── Sparkline-графики ─────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

function drawSparkline(canvas, data, color, max) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  if (!data || data.length < 2) return;
  const step = w / (data.length - 1);
  ctx.beginPath(); ctx.strokeStyle = color; ctx.lineWidth = 1.5;
  data.forEach((v, i) => {
    const x = i * step, y = h - (Math.min(v, max) / max) * (h - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.lineTo((data.length - 1) * step, h); ctx.lineTo(0, h); ctx.closePath();
  ctx.fillStyle = color.replace(')', ',0.15)').replace('rgb', 'rgba'); ctx.fill();
}
function updateSparklines(proc) {
  if (!state.procHistory[proc.pid]) state.procHistory[proc.pid] = { cpu: [], mem: [] };
  const h = state.procHistory[proc.pid];
  h.cpu.push(proc.cpu_percent); h.mem.push(proc.memory_mb);
  if (h.cpu.length > HISTORY_LEN) h.cpu.shift();
  if (h.mem.length > HISTORY_LEN) h.mem.shift();
  drawSparkline(el.cpuChart, h.cpu, 'rgb(160,32,240)',   100);
  drawSparkline(el.memChart, h.mem, 'rgb(68,204,136)', MAX_MEM_MB);
}

// ══════════════════════════════════════════════════════════════════════════════
// ── ANALYSIS ──────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

document.querySelectorAll('th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.col;
    state.sortDir = (state.sortCol === col && state.sortDir === 'desc') ? 'asc' : 'desc';
    state.sortCol = col;
    updateSortHeaders('th[data-col]', state.sortCol, state.sortDir, 'data-col');
    applyFilterAndSort(); renderTable();
  });
});
el.searchInput.addEventListener('input', () => {
  state.searchQuery = el.searchInput.value.toLowerCase().trim();
  applyFilterAndSort(); renderTable();
});
el.treeBtn.addEventListener('click', () => {
  state.treeMode = !state.treeMode;
  el.treeBtn.style.color      = state.treeMode ? 'var(--status-secure)' : '';
  el.treeBtn.style.borderColor= state.treeMode ? 'rgba(68,204,136,0.6)' : '';
  applyFilterAndSort(); renderTable();
});

function buildProcessTree(procs) {
  const byPid = new Map(procs.map(p => [p.pid, {...p, _children: []}]));
  const roots = [];
  for (const p of byPid.values()) {
    const parent = byPid.get(p.parent_pid);
    if (parent && p.pid !== p.parent_pid) parent._children.push(p);
    else roots.push(p);
  }
  return roots;
}
function flattenTree(nodes, depth = 0, result = []) {
  for (const node of nodes) {
    result.push({...node, _depth: depth});
    if (node._children?.length) flattenTree(node._children, depth + 1, result);
  }
  return result;
}
function applyFilterAndSort() {
  let list = state.processes;
  if (state.searchQuery) {
    list = list.filter(p =>
      p.name.toLowerCase().includes(state.searchQuery) ||
      p.user.toLowerCase().includes(state.searchQuery) ||
      String(p.pid).includes(state.searchQuery)
    );
  }
  if (state.treeMode) {
    state.filtered = flattenTree(buildProcessTree(list));
  } else {
    state.filtered = applySort([...list], state.sortCol, state.sortDir);
  }
}

function renderTable() {
  if (state.loading) {
    el.tbody.innerHTML = `<tr><td colspan="7"><div class="state-overlay"><div class="spinner"></div><div class="label">${t('loading')}</div></div></td></tr>`;
    return;
  }
  if (!state.filtered.length) {
    el.tbody.innerHTML = `<tr><td colspan="7"><div class="state-overlay"><div class="icon">⬡</div><div class="label">${t('no_processes')}</div></div></td></tr>`;
    return;
  }
  el.tbody.innerHTML = state.filtered.map(p => buildProcRow(p)).join('');
  el.tbody.querySelectorAll('.kill-btn').forEach(btn =>
    btn.addEventListener('click', e => {
      e.stopPropagation();
      killProcess(Number(btn.dataset.pid), btn.dataset.name);
    })
  );
  el.tbody.querySelectorAll('tr[data-pid]').forEach(row => {
    row.addEventListener('click', () => {
      el.tbody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');
      const proc = state.processes.find(p => p.pid === Number(row.dataset.pid));
      if (proc) openDetail(proc);
    });
    row.addEventListener('contextmenu', e => {
      const proc = state.processes.find(p => p.pid === Number(row.dataset.pid));
      if (!proc) return;
      ctxCallback = action => handleProcCtxAction(action, proc);
      const menuItems = [
        { action:'details',   label: t('ctx_details') },
        { sep: true },
        { action:'open_loc',  label: t('ctx_open_location') },
        { action:'copy_pid',  label: t('ctx_copy_pid') },
        { action:'copy_path', label: t('ctx_copy_path') },
        { sep: true },
        ...(proc.status === 'critical' ? [{ action:'uncrit', label: t('ctx_uncrit') }] : []),
        { action:'kill',      label: t('ctx_kill'), danger: true },
      ];
      showCtxMenu(e, menuItems);
    });
  });
  el.countDisplay.innerHTML = `<span>${state.filtered.length}</span> / ${state.processes.length}`;
}

async function handleProcCtxAction(action, proc) {
  switch (action) {
    case 'details':   openDetail(proc); break;
    case 'open_loc':
      if (proc.path) await invoke('open_file_location', { path: proc.path }).catch(e => alert(e));
      break;
    case 'copy_pid':  copyToClipboard(String(proc.pid)); break;
    case 'copy_path': copyToClipboard(proc.path || proc.name); break;
    case 'uncrit':    await handleUncritCtx(proc); break;
    case 'kill':      killProcess(proc.pid, proc.name); break;
  }
}

async function handleUncritCtx(proc) {
  try {
    await invoke('set_process_critical', { pid: proc.pid, critical: false });
    alert(`[${proc.name}] ${t('uncrit_success')}`);
    // Если детальная панель открыта для этого процесса — обновляем UI
    if (state.selectedProc?.pid === proc.pid) {
      if (el.dUncritBtn) el.dUncritBtn.style.display = 'none';
      if (el.dUncritStatus) {
        el.dUncritStatus.style.display = '';
        el.dUncritStatus.className = 'detail-uncrit-status uncrit-ok';
        el.dUncritStatus.textContent = t('uncrit_success');
      }
      if (el.dKillBtn) el.dKillBtn.disabled = false;
    }
  } catch (err) {
    alert(`[${proc.name}] ${t('uncrit_error')}${err}`);
  }
}

function buildProcRow(p) {
  const depth  = p._depth || 0;
  const indent = depth > 0 ? `<span class="tree-indent" style="display:inline-block;width:${depth*14}px"></span>` : '';
  const cpuW   = Math.min(p.cpu_percent, 100).toFixed(1);
  const memW   = Math.min((p.memory_mb / MAX_MEM_MB) * 100, 100).toFixed(1);
  const sel    = state.selectedProc?.pid === p.pid ? 'selected' : '';
  return `
  <tr data-pid="${p.pid}" class="${p.status==='critical'?'critical-row':''} ${sel}">
    <td class="td-pid">${p.pid}</td>
    <td class="td-name" title="${escHtml(p.path||p.name)}">${indent}${escHtml(p.name)}</td>
    <td class="td-user" title="${escHtml(p.user)}">${escHtml(p.user)}</td>
    <td><span class="status-badge badge-${p.status}">${t('status_'+p.status)}</span></td>
    <td><div class="metric-cell"><div class="metric-bar-bg"><div class="metric-bar cpu-bar" style="width:${cpuW}%"></div></div><span class="metric-val">${p.cpu_percent.toFixed(2)}%</span></div></td>
    <td><div class="metric-cell"><div class="metric-bar-bg"><div class="metric-bar mem-bar" style="width:${memW}%"></div></div><span class="metric-val">${formatMem(p.memory_mb)}</span></div></td>
    <td><button class="kill-btn" data-pid="${p.pid}" data-name="${escHtml(p.name)}" ${p.status==='critical'?'disabled':''}>KILL</button></td>
  </tr>`;
}

async function loadProcesses() {
  if (state.loading) return;
  state.loading = true; el.refreshBtn.classList.add('loading'); renderTable();
  try {
    const procs = await invoke('get_processes');
    state.loading = false; el.refreshBtn.classList.remove('loading');
    state.processes = procs; applyFilterAndSort(); renderTable(); updateStatusBar();
    if (state.selectedProc) {
      const up = procs.find(p => p.pid === state.selectedProc.pid);
      if (up) { refreshDetailValues(up); updateSparklines(up); }
    }
    el.lastRefresh.textContent = t('updated_at') + ': ' + new Date().toLocaleTimeString('ru-RU');
  } catch (err) {
    state.loading = false; el.refreshBtn.classList.remove('loading');
    el.tbody.innerHTML = `<tr><td colspan="7"><div class="state-overlay"><div class="icon">⚠</div><div class="label">${t('error')}: ${escHtml(String(err))}</div></div></td></tr>`;
  }
}

async function killProcess(pid, name) {
  if (!confirm(`${t('confirm_kill')} "${name}" (${t('pid')}: ${pid})?`)) return;
  try {
    await invoke('kill_process', { pid });
    state.processes = state.processes.filter(p => p.pid !== pid);
    delete state.procHistory[pid];
    applyFilterAndSort(); renderTable(); updateStatusBar();
    if (state.selectedProc?.pid === pid) closeDetail();
  } catch (err) { alert(`${t('error')}: ${err}`); }
}

el.refreshBtn.addEventListener('click', loadProcesses);
let autoEnabled = false;
el.autoBtn.addEventListener('click', () => {
  autoEnabled = !autoEnabled;
  el.autoBtn.textContent  = autoEnabled ? t('auto_on')  : t('auto_off');
  el.autoBtn.style.color       = autoEnabled ? 'var(--status-secure)' : '';
  el.autoBtn.style.borderColor = autoEnabled ? 'rgba(68,204,136,0.6)' : '';
  if (autoEnabled) state.autoRefresh = setInterval(loadProcesses, AUTO_INTERVAL);
  else clearInterval(state.autoRefresh);
});
el.exportProcBtn.addEventListener('click', () => exportData(state.processes, 'flowtrust-processes'));

function updateStatusBar() {
  const crit = state.processes.filter(p => p.status === 'critical').length;
  document.getElementById('critical-count').textContent = crit;
  document.getElementById('total-count').textContent    = state.processes.length;
  document.getElementById('hdr-total').textContent      = state.processes.length;
  document.getElementById('hdr-critical').textContent   = crit;
}

// ── Detail panel ─────────────────────────────────────────────────────────────

function openDetail(proc) {
  state.selectedProc = proc;
  el.detailPanel.classList.add('open');
  refreshDetailValues(proc); updateSparklines(proc);
  el.dSig.innerHTML = `<span class="sig-badge sig-unknown">${t('sig_checking')}</span>`;
  if (proc.path) {
    invoke('check_signature', { path: proc.path }).then(sig => {
      if (state.selectedProc?.pid !== proc.pid) return;
      const cls  = { TRUSTED:'sig-trusted', UNTRUSTED:'sig-untrusted', UNKNOWN:'sig-unknown' }[sig] ?? 'sig-unknown';
      const text = { TRUSTED:t('sig_trusted'), UNTRUSTED:t('sig_untrusted'), UNKNOWN:t('sig_unknown') }[sig] ?? t('sig_unknown');
      el.dSig.innerHTML = `<span class="sig-badge ${cls}">${text}</span>`;
    });
  } else {
    el.dSig.innerHTML = '<span class="sig-badge sig-unknown">N/A</span>';
  }
  // Проверяем критичность асинхронно
  checkUncritBtn(proc);
}

function checkUncritBtn(proc) {
  if (!el.dUncritBtn || !el.dUncritStatus) return;
  // Показываем кнопку только для процессов с нашим статусом "critical"
  if (proc.status === 'critical') {
    el.dUncritBtn.style.display = '';
    el.dUncritBtn.disabled = false;
    el.dUncritBtn.textContent = t('uncrit_btn');
    el.dUncritStatus.style.display = '';
    el.dUncritStatus.className = 'detail-uncrit-status uncrit-warning';
    el.dUncritStatus.textContent = t('uncrit_is_critical');
  } else {
    el.dUncritBtn.style.display = 'none';
    el.dUncritStatus.style.display = 'none';
  }
}

function refreshDetailValues(proc) {
  el.dName.textContent = proc.name;
  el.dPid.textContent  = proc.pid;
  el.dUser.textContent = proc.user;
  el.dPath.textContent = proc.path || '(недоступно)';
  el.dStatus.innerHTML = `<span class="status-badge badge-${proc.status}">${t('status_'+proc.status+'_long')}</span>`;
  el.dCpu.textContent  = proc.cpu_percent.toFixed(2) + '%';
  el.dMem.textContent  = formatMem(proc.memory_mb);
  el.dKillBtn.disabled = proc.status === 'critical';
  state.selectedProc   = proc;
}

function closeDetail() {
  el.detailPanel.classList.remove('open'); state.selectedProc = null;
  document.querySelectorAll('#process-tbody tr.selected').forEach(r => r.classList.remove('selected'));
}

el.detailClose.addEventListener('click', closeDetail);
el.dKillBtn.addEventListener('click', () => { if (state.selectedProc) killProcess(state.selectedProc.pid, state.selectedProc.name); });
el.dOpenLocBtn.addEventListener('click', async () => {
  if (state.selectedProc?.path) await invoke('open_file_location', { path: state.selectedProc.path }).catch(e => alert(e));
});
el.dDllBtn?.addEventListener('click', () => {
  if (!state.selectedProc) return;
  document.getElementById('dll-pid-input').value = state.selectedProc.pid;
  // Переключить на вкладку инструментов
  document.querySelector('[data-tab="tools"]')?.click();
  loadDlls(state.selectedProc.pid);
});

el.dUncritBtn?.addEventListener('click', async () => {
  if (!state.selectedProc) return;
  const pid = state.selectedProc.pid;
  el.dUncritBtn.disabled = true;
  el.dUncritBtn.textContent = '...';
  el.dUncritStatus.style.display = 'none';
  try {
    await invoke('set_process_critical', { pid, critical: false });
    el.dUncritBtn.style.display = 'none';
    el.dUncritStatus.style.display = '';
    el.dUncritStatus.className = 'detail-uncrit-status uncrit-ok';
    el.dUncritStatus.textContent = t('uncrit_success');
    // Снимаем блокировку кнопки "Завершить" если процесс был критичным
    if (el.dKillBtn) el.dKillBtn.disabled = false;
  } catch (err) {
    el.dUncritBtn.disabled = false;
    el.dUncritBtn.textContent = t('uncrit_btn');
    el.dUncritStatus.style.display = '';
    el.dUncritStatus.className = 'detail-uncrit-status uncrit-error';
    el.dUncritStatus.textContent = t('uncrit_error') + err;
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ── NETWORK ───────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

el.netSearch.addEventListener('input', () => {
  state.netSearchQuery = el.netSearch.value.toLowerCase().trim();
  applyNetFilter(); renderNetTable();
});
document.querySelectorAll('th[data-net-col]').forEach(th =>
  th.addEventListener('click', () => {
    const col = th.getAttribute('data-net-col');
    state.netSortDir = state.netSortCol === col && state.netSortDir === 'desc' ? 'asc' : 'desc';
    state.netSortCol = col;
    updateSortHeaders('th[data-net-col]', col, state.netSortDir, 'data-net-col');
    applyNetFilter(); renderNetTable();
  })
);
function applyNetFilter() {
  let list = state.connections;
  if (state.netSearchQuery) {
    list = list.filter(c =>
      c.process_name.toLowerCase().includes(state.netSearchQuery) ||
      c.local_addr.includes(state.netSearchQuery) ||
      c.remote_addr.includes(state.netSearchQuery) ||
      String(c.local_port).includes(state.netSearchQuery) ||
      String(c.pid).includes(state.netSearchQuery)
    );
  }
  state.netFiltered = applySort([...list], state.netSortCol, state.netSortDir);
}
function renderNetTable() {
  if (state.netLoading) {
    el.netTbody.innerHTML = `<tr><td colspan="6"><div class="state-overlay"><div class="spinner"></div><div class="label">${t('loading_net')}</div></div></td></tr>`;
    return;
  }
  if (!state.netFiltered.length) {
    const msg = state.connections.length ? t('no_connections') : t('wait_refresh');
    el.netTbody.innerHTML = `<tr><td colspan="6"><div class="state-overlay"><div class="icon">⬡</div><div class="label">${msg}</div></div></td></tr>`;
    return;
  }
  el.netTbody.innerHTML = state.netFiltered.map((c, idx) => {
    const stCls  = { ESTABLISHED:'tcp-established', LISTEN:'tcp-listen', CLOSE_WAIT:'tcp-close-wait', FIN_WAIT1:'tcp-fin-wait', FIN_WAIT2:'tcp-fin-wait' }[c.state] ?? (c.protocol==='udp'?'udp-badge':'');
    const stLbl  = c.protocol === 'udp' ? 'LISTEN (UDP)' : c.state;
    const remote = c.remote_addr && c.remote_port ? `${escHtml(c.remote_addr)}:${c.remote_port}` : '—';
    return `<tr data-net-idx="${idx}">
      <td class="td-pid">${c.pid}</td>
      <td class="td-name" title="${escHtml(c.process_name)}">${escHtml(c.process_name)}</td>
      <td><span class="proto-badge proto-${c.protocol}">${c.protocol.toUpperCase()}</span></td>
      <td class="td-user">${escHtml(c.local_addr)}:${c.local_port}</td>
      <td class="td-user">${remote}</td>
      <td><span class="${stCls}">${stLbl}</span></td>
    </tr>`;
  }).join('');
  el.netTbody.querySelectorAll('tr[data-net-idx]').forEach(row => {
    row.addEventListener('contextmenu', e => {
      const conn = state.netFiltered[Number(row.dataset.netIdx)];
      if (!conn) return;
      const items = [
        { action:'copy_addr', label: `Копировать ${conn.remote_addr}:${conn.remote_port}` },
      ];
      if (conn.protocol === 'tcp' && conn.state === 'ESTABLISHED') {
        items.push({ sep: true });
        items.push({ action:'kill_conn', label: t('ctx_kill_conn'), danger: true });
      }
      ctxCallback = async action => {
        if (action === 'copy_addr') copyToClipboard(`${conn.remote_addr}:${conn.remote_port}`);
        if (action === 'kill_conn') {
          try {
            await invoke('kill_tcp_connection', {
              localAddr: conn.local_addr, localPort: conn.local_port,
              remoteAddr: conn.remote_addr, remotePort: conn.remote_port,
            });
            state.connections = state.connections.filter(c =>
              !(c.local_addr === conn.local_addr && c.local_port === conn.local_port)
            );
            applyNetFilter(); renderNetTable();
          } catch (err) { alert(`${t('error')}: ${err}`); }
        }
      };
      showCtxMenu(e, items);
    });
  });
  el.netCount.innerHTML = `<span>${state.netFiltered.length}</span> / ${state.connections.length}`;
}
async function loadConnections() {
  if (state.netLoading) return;
  state.netLoading = true; el.netRefreshBtn.classList.add('loading'); renderNetTable();
  try {
    const conns = await invoke('get_connections');
    state.netLoading = false; el.netRefreshBtn.classList.remove('loading');
    state.connections = conns; applyNetFilter(); renderNetTable();
  } catch (err) {
    state.netLoading = false; el.netRefreshBtn.classList.remove('loading');
    el.netTbody.innerHTML = `<tr><td colspan="6"><div class="state-overlay"><div class="icon">⚠</div><div class="label">${t('error')}: ${escHtml(String(err))}</div></div></td></tr>`;
  }
}
el.netRefreshBtn.addEventListener('click', loadConnections);

// ══════════════════════════════════════════════════════════════════════════════
// ── STARTUP ───────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

document.querySelectorAll('.subtab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.startupSourceFilter = btn.dataset.subtab;
    applyStartupFilter(); renderStartupTable();
  });
});
el.startupSearch.addEventListener('input', () => {
  state.startupSearch = el.startupSearch.value.toLowerCase().trim();
  applyStartupFilter(); renderStartupTable();
});
function applyStartupFilter() {
  let list = state.startupEntries;
  if (state.startupSourceFilter !== 'all') {
    list = list.filter(e => {
      const src = e.source || '';
      if (state.startupSourceFilter === 'registry') return src.startsWith('registry');
      if (state.startupSourceFilter === 'winlogon') return src === 'winlogon';
      if (state.startupSourceFilter === 'appinit')  return src === 'app_init_dlls';
      if (state.startupSourceFilter === 'tasks')    return src === 'scheduled_task';
      return true;
    });
  }
  if (state.startupSearch) {
    list = list.filter(e =>
      e.name.toLowerCase().includes(state.startupSearch) ||
      e.command.toLowerCase().includes(state.startupSearch)
    );
  }
  state.startupFiltered = list;
}

const SRC_LABELS = () => ({
  registry_run:      t('src_registry_run'),
  registry_run_once: t('src_registry_run_once'),
  winlogon:          t('src_winlogon'),
  app_init_dlls:     t('src_app_init_dlls'),
  scheduled_task:    t('src_scheduled_task'),
});

function renderStartupTable() {
  if (state.startupLoading) {
    el.startupTbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="spinner"></div><div class="label">${t('loading_registry')}</div></div></td></tr>`;
    return;
  }
  if (!state.startupFiltered.length) {
    const msg = state.startupEntries.length ? t('no_entries') : t('wait_startup');
    el.startupTbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="icon">⬡</div><div class="label">${msg}</div></div></td></tr>`;
    return;
  }
  const sl = SRC_LABELS();
  el.startupTbody.innerHTML = state.startupFiltered.map((e, idx) => `
  <tr class="${e.suspicious ? 'critical-row' : ''}" data-su-idx="${idx}">
    <td class="td-name" title="${escHtml(e.name)}">${escHtml(e.name)}</td>
    <td><span class="hive-${e.source}">${sl[e.source] ?? escHtml(e.source)}</span></td>
    <td class="td-user" title="${escHtml(e.location)}" style="font-size:10px">${escHtml(e.location)}</td>
    <td class="detail-path" title="${escHtml(e.command)}" style="font-size:11px">${escHtml(e.command)}</td>
    <td>${e.suspicious ? '<span class="startup-sus">⚠ ПОДОЗРИТ.</span>' : '<span class="startup-ok">OK</span>'}</td>
  </tr>`).join('');

  el.startupTbody.querySelectorAll('tr[data-su-idx]').forEach(row => {
    row.addEventListener('contextmenu', e => {
      const entry = state.startupFiltered[Number(row.dataset.suIdx)];
      if (!entry) return;
      ctxCallback = action => handleStartupCtxAction(action, entry);
      showCtxMenu(e, [
        { action:'edit',         label: t('ctx_edit') },
        { action:'delete_entry', label: t('ctx_delete_entry'), danger: true },
        { action:'delete_file',  label: t('ctx_delete_file'),  danger: true },
        { sep: true },
        { action:'open_loc',     label: t('ctx_open_location') },
        { sep: true },
        { action:'refresh',      label: t('ctx_refresh') },
      ]);
    });
  });
  el.startupCount.innerHTML = `<span>${state.startupFiltered.length}</span> / ${state.startupEntries.length}`;
}

async function handleStartupCtxAction(action, entry) {
  switch (action) {
    case 'edit': {
      const newCmd = prompt(`${t('ctx_edit')} "${entry.name}":`, entry.command);
      if (newCmd === null || newCmd === entry.command) return;
      try {
        await invoke('edit_startup_entry_cmd', { name: entry.name, hive: entry.hive, location: entry.location, newCommand: newCmd });
        await loadStartup();
      } catch (err) { alert(`${t('error')}: ${err}`); }
      break;
    }
    case 'delete_entry': {
      if (!confirm(`${t('confirm_del_entry')} "${entry.name}"?`)) return;
      try {
        await invoke('delete_startup_entry_cmd', { name: entry.name, hive: entry.hive, location: entry.location });
        await loadStartup();
      } catch (err) { alert(`${t('error')}: ${err}`); }
      break;
    }
    case 'delete_file': {
      const pathMatch = entry.command.match(/^"([^"]+)"|^(\S+)/);
      const filePath  = pathMatch ? (pathMatch[1] || pathMatch[2]) : '';
      if (!filePath) { alert(t('error') + ': путь не найден'); return; }
      if (!confirm(`${t('confirm_del_file')}?\n${filePath}`)) return;
      try {
        await invoke('delete_file_at_path', { path: filePath });
        await loadStartup();
      } catch (err) { alert(`${t('error')}: ${err}`); }
      break;
    }
    case 'open_loc': {
      const pathMatch = entry.command.match(/^"([^"]+)"|^(\S+)/);
      const filePath  = pathMatch ? (pathMatch[1] || pathMatch[2]) : '';
      if (!filePath) return;
      await invoke('open_file_location', { path: filePath }).catch(e => alert(e));
      break;
    }
    case 'refresh': await loadStartup(); break;
  }
}

async function loadStartup() {
  if (state.startupLoading) return;
  state.startupLoading = true; el.startupRefreshBtn.classList.add('loading'); renderStartupTable();
  try {
    const entries = await invoke('get_startup_full_cmd');
    state.startupLoading = false; el.startupRefreshBtn.classList.remove('loading');
    state.startupEntries = entries; applyStartupFilter(); renderStartupTable();
  } catch (err) {
    state.startupLoading = false; el.startupRefreshBtn.classList.remove('loading');
    el.startupTbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="icon">⚠</div><div class="label">${t('error')}: ${escHtml(String(err))}</div></div></td></tr>`;
  }
}
el.startupRefreshBtn.addEventListener('click', loadStartup);

// ══════════════════════════════════════════════════════════════════════════════
// ── FORENSICS ─────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

el.forensicsSearch.addEventListener('input', () => {
  state.threatSearch = el.forensicsSearch.value.toLowerCase().trim();
  applyThreatFilter(); renderForensicsTable();
});

// Сортировка с переключением направления
let foSortCol = '', foSortDir = 'asc';
document.querySelectorAll('th[data-fo-col]').forEach(th =>
  th.addEventListener('click', () => {
    const col = th.getAttribute('data-fo-col');
    if (foSortCol === col) foSortDir = foSortDir === 'asc' ? 'desc' : 'asc';
    else { foSortCol = col; foSortDir = 'asc'; }
    document.querySelectorAll('th[data-fo-col]').forEach(h => {
      h.textContent = h.textContent.replace(/ [↑↓]$/, '');
      if (h.getAttribute('data-fo-col') === col)
        h.textContent += foSortDir === 'asc' ? ' ↑' : ' ↓';
    });
    state.threatsFiltered = applySort([...state.threatsFiltered], col, foSortDir);
    renderForensicsTable();
  })
);
document.getElementById('fo-check-all')?.addEventListener('change', e => {
  document.querySelectorAll('.fo-ck').forEach(ck => { ck.checked = e.target.checked; });
});

function applyThreatFilter() {
  let list = state.threats;
  if (state.threatSearch) {
    list = list.filter(x =>
      x.process_name.toLowerCase().includes(state.threatSearch) ||
      x.description.toLowerCase().includes(state.threatSearch) ||
      x.threat_type.toLowerCase().includes(state.threatSearch)
    );
  }
  state.threatsFiltered = list;
}

const THREAT_LABELS = () => ({
  MASQUERADING:    t('threat_masq'),
  SUSPICIOUS_PATH: t('threat_sus_path'),
  NO_IMAGE:        t('threat_no_img'),
  UNSIGNED:        t('threat_unsigned'),
});
const SEV_LABELS = () => ({
  CRITICAL: t('sev_critical'), HIGH: t('sev_high'), MEDIUM: t('sev_medium'), LOW: t('sev_low'),
});
const SEV_CLS = { CRITICAL:'sev-critical', HIGH:'sev-high', MEDIUM:'sev-medium', LOW:'sev-low' };

// Риск в % на основе типа угрозы + критичности
function threatRisk(x) {
  const sevScore = { CRITICAL:100, HIGH:75, MEDIUM:45, LOW:20 };
  const typeBonus = { MASQUERADING:15, SUSPICIOUS_PATH:5, NO_IMAGE:10, UNSIGNED:0 };
  const sev  = (x.severity || '').toUpperCase();
  const type = (x.threat_type || '').replace(/-/g,'_').toUpperCase();
  return Math.min(100, (sevScore[sev] ?? 20) + (typeBonus[type] ?? 0));
}

function riskBarHtml(pct) {
  const cls = pct >= 90 ? 'fo-risk-crit' : pct >= 60 ? 'fo-risk-high' : pct >= 35 ? 'fo-risk-medium' : 'fo-risk-low';
  return `<div class="fo-risk-bar">
    <div class="fo-risk-track"><div class="fo-risk-fill ${cls}" style="width:${pct}%"></div></div>
    <span class="fo-risk-pct">${pct}%</span>
  </div>`;
}

function renderForensicsTable() {
  if (state.threatLoading) {
    el.forensicsTbody.innerHTML = `<tr><td colspan="8"><div class="state-overlay"><div class="spinner"></div><div class="label">${t('loading_threats')}</div></div></td></tr>`;
    return;
  }
  if (!state.threatsFiltered.length) {
    const msg = state.threats.length ? t('no_threats') : t('wait_scan');
    el.forensicsTbody.innerHTML = `<tr><td colspan="8"><div class="state-overlay"><div class="icon">${state.threats.length ? '✓' : '⬡'}</div><div class="label">${msg}</div></div></td></tr>`;
    return;
  }
  const tl = THREAT_LABELS(), sl = SEV_LABELS();
  el.forensicsTbody.innerHTML = state.threatsFiltered.map((x, idx) => {
    const ttype = x.threat_type.replace(/-/g,'_').toUpperCase();
    const sev   = x.severity.toUpperCase();
    const risk  = threatRisk(x);
    const pathShort = x.path ? x.path.replace(/^.*[\\\/]/, '') : '—';
    return `<tr data-fo-idx="${idx}" data-path="${escHtml(x.path || '')}">
      <td class="col-fo-ck"><input type="checkbox" class="fo-ck" data-idx="${idx}"></td>
      <td class="td-pid">${x.pid}</td>
      <td class="td-name" title="${escHtml(x.process_name)}">${escHtml(x.process_name)}</td>
      <td><span class="threat-badge threat-${(x.threat_type||'').toLowerCase().replace(/-/g,'_')}">${tl[ttype] ?? x.threat_type}</span></td>
      <td><span class="${SEV_CLS[sev]??'sev-low'}">${sl[sev]??sev}</span></td>
      <td>${riskBarHtml(risk)}</td>
      <td class="td-user" title="${escHtml(x.description)}">${escHtml(x.description)}</td>
      <td class="detail-path" title="${escHtml(x.path)}">${escHtml(pathShort)}</td>
    </tr>`;
  }).join('');

  el.forensicsTbody.querySelectorAll('tr[data-fo-idx]').forEach(row => {
    // Одиночный клик — выделение
    row.addEventListener('click', (e) => {
      if (e.target.type === 'checkbox') return;
      el.forensicsTbody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');
      state.selectedThreatPath = row.dataset.path;
    });
    // Контекстное меню
    row.addEventListener('contextmenu', e => {
      e.preventDefault();
      const path = row.dataset.path;
      const idx  = Number(row.dataset.foIdx);
      const x    = state.threatsFiltered[idx];
      if (!x) return;
      state.selectedThreatPath = path;
      ctxCallback = async action => {
        if (action === 'fo_vt') {
          if (!path) return;
          try {
            const hash = await invoke('compute_sha256', { path });
            await invoke('open_browser_window', { url: `https://www.virustotal.com/gui/file/${hash}` });
          } catch (err) { alert(`${t('error')}: ${err}`); }
        } else if (action === 'fo_quarantine') {
          try {
            const dest = await invoke('quarantine_file_cmd', { path });
            await loadForensics();
            alert(`${t('fo_quarantine_ok')} ${dest}`);
          } catch (err) { alert(`${t('fo_quarantine_err')} ${err}`); }
        } else if (action === 'fo_delete') {
          if (!confirm(`${t('confirm_del_file')}?\n${path}`)) return;
          try { await invoke('delete_file_at_path', { path }); await loadForensics(); }
          catch (err) { alert(`${t('error')}: ${err}`); }
        } else if (action === 'fo_copy_path') {
          navigator.clipboard.writeText(path).catch(() => {});
        }
      };
      showCtxMenu(e, [
        { action:'fo_vt',        label: '🔎 VirusTotal (SHA-256)' },
        { action:'fo_copy_path', label: '📋 Копировать путь' },
        { sep: true },
        { action:'fo_quarantine',label: '📦 В карантин', },
        { action:'fo_delete',    label: '✕ Удалить файл', danger: true },
      ]);
    });
  });

  el.forensicsCount.textContent = state.threatsFiltered.length;
  document.getElementById('hdr-threats').textContent  = state.threats.length;
  document.getElementById('threat-count').textContent = state.threats.length;
}

async function loadForensics() {
  if (state.threatLoading) return;
  state.threatLoading = true; el.forensicsRefreshBtn.classList.add('loading'); renderForensicsTable();
  try {
    const threats = await invoke('get_threats');
    state.threatLoading = false; el.forensicsRefreshBtn.classList.remove('loading');
    if (cfg.notifyThreats && threats.length > state.prevThreatCount && state.prevThreatCount > 0) {
      sendNotification(t('new_threats_title'), `${threats.length} ${t('new_threats_body')}`);
    }
    state.prevThreatCount = threats.length;
    state.threats = threats; applyThreatFilter(); renderForensicsTable();
  } catch (err) {
    state.threatLoading = false; el.forensicsRefreshBtn.classList.remove('loading');
    el.forensicsTbody.innerHTML = `<tr><td colspan="7"><div class="state-overlay"><div class="icon">⚠</div><div class="label">${t('error')}: ${escHtml(String(err))}</div></div></td></tr>`;
  }
}
el.forensicsRefreshBtn.addEventListener('click', loadForensics);
el.exportThreatsBtn.addEventListener('click', () => exportData(state.threats, 'flowtrust-threats'));

// ── VirusTotal ────────────────────────────────────────────────────────────────

document.getElementById('fo-vt-btn')?.addEventListener('click', async () => {
  // Приоритет: чекбоксы → выделенная строка
  const checked = getCheckedThreatPaths();
  const paths = checked.length ? checked : (state.selectedThreatPath ? [state.selectedThreatPath] : []);
  if (!paths.length) { alert(t('fo_no_selection')); return; }
  const btn = document.getElementById('fo-vt-btn');
  btn.disabled = true; btn.textContent = t('fo_vt_loading');
  try {
    for (const path of paths) {
      const hash = await invoke('compute_sha256', { path });
      await invoke('open_browser_window', { url: `https://www.virustotal.com/gui/file/${hash}` });
    }
  } catch (err) { alert(`${t('error')}: ${err}`); }
  finally { btn.disabled = false; btn.textContent = t('fo_vt_btn'); }
});

// ── Карантин ──────────────────────────────────────────────────────────────────

document.getElementById('fo-quarantine-btn')?.addEventListener('click', async () => {
  const paths = getCheckedThreatPaths();
  if (!paths.length) { alert(t('fo_no_selection')); return; }
  for (const p of paths) {
    try {
      const dest = await invoke('quarantine_file_cmd', { path: p });
      alert(`${t('fo_quarantine_ok')} ${dest}`);
    } catch (err) { alert(`${t('fo_quarantine_err')} ${err}`); }
  }
  await loadForensics();
});

// ── Удалить файл ──────────────────────────────────────────────────────────────

document.getElementById('fo-delete-btn')?.addEventListener('click', async () => {
  const paths = getCheckedThreatPaths();
  if (!paths.length) { alert(t('fo_no_selection')); return; }
  if (!confirm(`${t('confirm_del_file')}?\n${paths.join('\n')}`)) return;
  for (const p of paths) {
    try { await invoke('delete_file_at_path', { path: p }); }
    catch (err) { alert(`${t('error')}: ${err}`); }
  }
  await loadForensics();
});

function getSelectedThreatPath() {
  if (state.selectedThreatPath) return state.selectedThreatPath;
  alert(t('fo_no_selection')); return '';
}

function getCheckedThreatPaths() {
  return [...document.querySelectorAll('.fo-ck:checked')]
    .map(ck => {
      const idx = Number(ck.dataset.idx);
      return state.threatsFiltered[idx]?.path;
    })
    .filter(Boolean);
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Уведомления ───────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

async function requestNotificationPermission() {
  if ('Notification' in window && Notification.permission === 'default') {
    await Notification.requestPermission();
  }
}
function sendNotification(title, body) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  new Notification(title, { body });
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Экспорт ───────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

async function exportData(data, baseName) {
  const path = prompt(t('export_path_prompt'), `C:\\Desktop\\${baseName}-${Date.now()}.json`);
  if (!path) return;
  try {
    await invoke('export_report', { path, content: JSON.stringify(data, null, 2) });
    alert(`${t('export_ok')} ${path}`);
  } catch (err) { alert(`${t('export_err')} ${err}`); }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── НАСТРОЙКИ ─────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

function syncSettingsUI() {
  el.sAlwaysOnTop.checked   = cfg.alwaysOnTop;
  el.sCheckUpdates.checked  = cfg.checkUpdates;
  el.sNotifyThreats.checked = cfg.notifyThreats;
  el.sRotateName.checked    = cfg.rotateName;
  const sMinTray    = document.getElementById('s-minimize-tray');
  const sAutoRef    = document.getElementById('s-auto-refresh');
  const sRefInt     = document.getElementById('s-refresh-interval');
  const sShowSigned = document.getElementById('s-show-signed');
  const sAutoScan   = document.getElementById('s-auto-scan');
  const sExpFmt     = document.getElementById('s-export-format');
  if (sMinTray)    sMinTray.checked           = cfg.minimizeTray;
  if (sAutoRef)    sAutoRef.checked           = cfg.autoRefresh;
  if (sRefInt)     sRefInt.value              = String(cfg.refreshInterval);
  if (sShowSigned) sShowSigned.checked        = cfg.showSigned;
  if (sAutoScan)   sAutoScan.checked          = cfg.autoScan;
  if (sExpFmt)     sExpFmt.value              = cfg.exportFormat;
}
el.sAlwaysOnTop.addEventListener('change', async () => {
  cfg.alwaysOnTop = el.sAlwaysOnTop.checked; saveCfg();
  await invoke('set_always_on_top', { onTop: cfg.alwaysOnTop }).catch(() => {});
});
el.sCheckUpdates.addEventListener('change', () => { cfg.checkUpdates = el.sCheckUpdates.checked; saveCfg(); });
el.sNotifyThreats.addEventListener('change', async () => {
  cfg.notifyThreats = el.sNotifyThreats.checked; saveCfg();
  if (cfg.notifyThreats) await requestNotificationPermission();
});
el.sRotateName.addEventListener('change', () => {
  cfg.rotateName = el.sRotateName.checked; saveCfg();
  cfg.rotateName ? startTitleRotation() : stopTitleRotation();
});
// Новые настройки
document.getElementById('s-minimize-tray')?.addEventListener('change', e => { cfg.minimizeTray = e.target.checked; saveCfg(); });
document.getElementById('s-auto-refresh')?.addEventListener('change', e => { cfg.autoRefresh = e.target.checked; saveCfg(); applyAutoRefresh(); });
document.getElementById('s-refresh-interval')?.addEventListener('change', e => { cfg.refreshInterval = Number(e.target.value); saveCfg(); applyAutoRefresh(); });
document.getElementById('s-show-signed')?.addEventListener('change', e => { cfg.showSigned = e.target.checked; saveCfg(); });
document.getElementById('s-auto-scan')?.addEventListener('change', e => { cfg.autoScan = e.target.checked; saveCfg(); });
document.getElementById('s-export-format')?.addEventListener('change', e => { cfg.exportFormat = e.target.value; saveCfg(); });

let autoRefreshTimer = null;
function applyAutoRefresh() {
  if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
  if (cfg.autoRefresh) {
    autoRefreshTimer = setInterval(() => {
      if (document.querySelector('.tab-btn.active')?.dataset.tab === 'analysis') loadProcesses();
    }, cfg.refreshInterval * 1000);
  }
}
document.querySelectorAll('.lang-choice').forEach(btn => {
  btn.addEventListener('click', () => setLang(btn.dataset.lang));
});
function checkUpdates() {
  const updEl = document.getElementById('update-status');
  if (!updEl) return;
  updEl.style.display = 'block';
  updEl.className     = 'update-status ok';
  updEl.textContent   = t('upd_no_updates');
}

// ══════════════════════════════════════════════════════════════════════════════
// ── О ПРОГРАММЕ ───────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

el.donateBtn.addEventListener('click',    () => open('https://www.donationalerts.com/r/alexseldon'));
el.tgBtn.addEventListener('click',        () => open('https://t.me/Jimmy_Hawkins'));
el.tgChannelBtn.addEventListener('click', () => open('https://t.me/TG_barnaya_stoyka'));
el.langBtn.addEventListener('click', () => setLang(lang === 'ru' ? 'en' : 'ru'));

// ══════════════════════════════════════════════════════════════════════════════
// ── РАЗБЛОКИРОВКА ─────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const RESTRICTIONS = [
  // ── Базовые политики ────────────────────────────────────────────────────────
  { id:'no_taskmgr',    nameRu:'Диспетчер задач',          nameEn:'Task Manager',         descRu:'Блокировка Диспетчера задач',            descEn:'Task Manager blocked',        hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',     value:'DisableTaskMgr',              action:'delete' },
  { id:'no_regedit',    nameRu:'Редактор реестра',         nameEn:'Registry Editor',      descRu:'Запрет regedit',                         descEn:'Regedit blocked',             hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',     value:'DisableRegistryTools',        action:'delete' },
  { id:'no_cmd',        nameRu:'Командная строка',         nameEn:'Command Prompt',       descRu:'Блокировка cmd.exe',                     descEn:'CMD blocked',                 hive:'hkcu', key:'Software\\Policies\\Microsoft\\Windows\\System',                     value:'DisableCMD',                  action:'delete' },
  { id:'no_run',        nameRu:'Диалог «Выполнить»',      nameEn:'Run Dialog',           descRu:'Скрытие Win+R',                          descEn:'Run dialog hidden',           hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',   value:'NoRun',                       action:'delete' },
  { id:'no_controlpanel', nameRu:'Панель управления',     nameEn:'Control Panel',        descRu:'Запрет панели управления',               descEn:'Control panel blocked',       hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',   value:'NoControlPanel',              action:'delete' },
  { id:'no_lock',       nameRu:'Блокировка (Win+L)',       nameEn:'Lock Screen',          descRu:'Запрет блокировки экрана',               descEn:'Lock screen blocked',         hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',     value:'DisableLockWorkstation',      action:'delete' },
  { id:'no_changepasswd',nameRu:'Смена пароля',            nameEn:'Change Password',      descRu:'Запрет смены пароля',                    descEn:'Password change disabled',    hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',     value:'DisableChangePassword',       action:'delete' },
  { id:'wallpaper_lock', nameRu:'Изменение обоев',         nameEn:'Wallpaper change',     descRu:'Запрет смены фона рабочего стола',       descEn:'Wallpaper change blocked',    hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop', value:'NoChangingWallpaper',      action:'delete' },
  { id:'no_desktop',    nameRu:'Скрытие рабочего стола',  nameEn:'Desktop hidden',       descRu:'Скрытие ярлыков рабочего стола',         descEn:'Desktop icons hidden',        hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',   value:'NoDesktop',                   action:'delete' },
  { id:'no_ctrlaltdel', nameRu:'Ctrl+Alt+Del',             nameEn:'Ctrl+Alt+Del',         descRu:'Блокировка Ctrl+Alt+Del',                descEn:'Ctrl+Alt+Del blocked',        hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',     value:'DisableCAD',                  action:'delete' },
  { id:'no_tasksw',     nameRu:'Alt+Tab',                  nameEn:'Alt+Tab',              descRu:'Блокировка переключения задач',          descEn:'Alt+Tab blocked',             hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',   value:'NoWindowsHotKeys',            action:'delete' },
  { id:'no_msconfig',   nameRu:'MSConfig',                 nameEn:'MSConfig',             descRu:'Блокировка msconfig.exe',                descEn:'MSConfig blocked',            hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',     value:'DisableMSConfig',             action:'delete' },
  // ── UAC и брандмауэр ──────────────────────────────────────────────────────
  { id:'uac_off',       nameRu:'UAC отключён',             nameEn:'UAC disabled',         descRu:'Контроль учётных записей отключён',      descEn:'UAC is off',                  hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',     value:'EnableLUA',                   action:'set_dword:1' },
  { id:'no_firewall',   nameRu:'Брандмауэр (политика)',   nameEn:'Firewall (policy)',    descRu:'Брандмауэр отключён через GPO',          descEn:'Firewall disabled via policy',hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile',     value:'EnableFirewall',              action:'set_dword:1' },
  { id:'no_update',     nameRu:'Центр обновления',         nameEn:'Windows Update',       descRu:'Автообновление Windows отключено',       descEn:'Windows Update disabled',     hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU',           value:'NoAutoUpdate',                action:'delete' },
  // ── Windows Defender ──────────────────────────────────────────────────────
  { id:'wd_disabled',   nameRu:'Windows Defender (GPO)',  nameEn:'WD disabled (GPO)',    descRu:'Defender отключён через политику',       descEn:'Defender disabled via policy',hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows Defender',                     value:'DisableAntiSpyware',          action:'delete' },
  { id:'wd_rt_off',     nameRu:'WD: Защита в реальном времени', nameEn:'WD Realtime off',descRu:'Реальное время защиты отключено',        descEn:'WD realtime protection off',  hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection', value:'DisableRealtimeMonitoring',   action:'delete' },
  // ── Прокси ────────────────────────────────────────────────────────────────
  { id:'proxy_on',      nameRu:'Принудительный прокси',   nameEn:'Forced proxy',         descRu:'Включён прокси-сервер (ProxyEnable=1)', descEn:'Proxy server enabled',        hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',     value:'ProxyEnable',                 action:'set_dword:0' },
  // ── Безопасный режим ──────────────────────────────────────────────────────
  { id:'safe_mode_shell',nameRu:'Shell безопасного режима',nameEn:'Safe mode shell',     descRu:'AlternateShell в SafeBoot переопределён',descEn:'SafeBoot AlternateShell overridden',hive:'hklm', key:'SYSTEM\\CurrentControlSet\\Control\\SafeBoot',             value:'AlternateShell',              action:'delete' },
  // ── Ремап клавиатуры ──────────────────────────────────────────────────────
  { id:'scancode_hklm', nameRu:'Ремап клавиатуры (HKLM)', nameEn:'Keyboard remap (HKLM)',descRu:'Scancode Map (HKLM) — ремап клавиш',   descEn:'Key remapping via HKLM',      hive:'hklm', key:'SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout',                 value:'Scancode Map',                action:'delete' },
  { id:'scancode_hkcu', nameRu:'Ремап клавиатуры (HKCU)', nameEn:'Keyboard remap (HKCU)',descRu:'Scancode Map (HKCU) — ремап клавиш',   descEn:'Key remapping via HKCU',      hive:'hkcu', key:'Keyboard Layout',                                                      value:'Scancode Map',                action:'delete' },
  { id:'mouse_swap',    nameRu:'Кнопки мыши поменяны',    nameEn:'Mouse buttons swapped',descRu:'Левая и правая кнопки мыши поменяны',  descEn:'Mouse buttons swapped',       hive:'hkcu', key:'Control Panel\\Mouse',                                                 value:'SwapMouseButtons',            action:'set_dword:0' },
  // ── Контекстное меню ──────────────────────────────────────────────────────
  { id:'no_context_menu',nameRu:'Контекстное меню',        nameEn:'Context menu',         descRu:'Контекстное меню рабочего стола скрыто',descEn:'Desktop context menu hidden', hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',   value:'NoViewContextMenu',           action:'delete' },
  // ── LogonUI ───────────────────────────────────────────────────────────────
  { id:'bad_shell',     nameRu:'Shell (Winlogon)',         nameEn:'Shell (Winlogon)',     descRu:'Shell в Winlogon — не explorer.exe',    descEn:'Shell in Winlogon overridden',hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',           value:'Shell',                       action:'delete' },

  // ── Image File Execution Options (IFEO) — перехват запуска ────────────────
  { id:'ifeo_taskmgr',  nameRu:'IFEO: Taskmgr',           nameEn:'IFEO: Taskmgr',        descRu:'Диспетчер задач перехвачен через IFEO', descEn:'Task Manager hijacked via IFEO',      hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe',  value:'Debugger', action:'delete' },
  { id:'ifeo_regedit',  nameRu:'IFEO: Regedit',           nameEn:'IFEO: Regedit',        descRu:'Regedit перехвачен через IFEO',         descEn:'Regedit hijacked via IFEO',           hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\regedit.exe',   value:'Debugger', action:'delete' },
  { id:'ifeo_cmd',      nameRu:'IFEO: CMD',               nameEn:'IFEO: CMD',            descRu:'CMD перехвачен через IFEO',             descEn:'CMD hijacked via IFEO',               hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\cmd.exe',        value:'Debugger', action:'delete' },
  { id:'ifeo_mmc',      nameRu:'IFEO: MMC',               nameEn:'IFEO: MMC',            descRu:'MMC (снастки) перехвачен через IFEO',   descEn:'MMC hijacked via IFEO',               hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mmc.exe',        value:'Debugger', action:'delete' },
  { id:'ifeo_powershell',nameRu:'IFEO: PowerShell',       nameEn:'IFEO: PowerShell',     descRu:'PowerShell перехвачен через IFEO',      descEn:'PowerShell hijacked via IFEO',        hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\powershell.exe', value:'Debugger', action:'delete' },

  // ── Windows Script Host ───────────────────────────────────────────────────
  { id:'wsh_off_hklm',  nameRu:'WSH отключён (HKLM)',     nameEn:'WSH disabled (HKLM)',  descRu:'Windows Script Host заблокирован',      descEn:'WSH blocked system-wide',             hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows Script Host\\Settings',                                            value:'Enabled',  action:'set_dword:1' },
  { id:'wsh_off_hkcu',  nameRu:'WSH отключён (HKCU)',     nameEn:'WSH disabled (HKCU)',  descRu:'Windows Script Host заблокирован (user)',descEn:'WSH blocked for current user',        hive:'hkcu', key:'Software\\Microsoft\\Windows Script Host\\Settings',                                            value:'Enabled',  action:'set_dword:1' },

  // ── Проводник — скрытие файлов ────────────────────────────────────────────
  { id:'hide_ext',      nameRu:'Скрытие расширений',      nameEn:'Hide extensions',      descRu:'Расширения файлов скрыты в проводнике', descEn:'File extensions hidden in Explorer',  hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced',                              value:'HideFileExt',     action:'set_dword:0' },
  { id:'hide_super',    nameRu:'Скрытие защищ. файлов',   nameEn:'Hide protected files', descRu:'Скрыты защищённые системные файлы',    descEn:'Protected OS files hidden',           hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced',                              value:'ShowSuperHidden', action:'set_dword:1' },
  { id:'hide_hidden',   nameRu:'Скрытие скрытых файлов',  nameEn:'Hide hidden files',    descRu:'Скрытые файлы не показываются',        descEn:'Hidden files not shown',              hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced',                              value:'Hidden',          action:'set_dword:1' },
  { id:'no_folder_opt', nameRu:'Параметры папок',         nameEn:'Folder options',       descRu:'Параметры папок заблокированы',        descEn:'Folder options blocked',              hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',                              value:'NoFolderOptions', action:'delete' },

  // ── PowerShell / Скрипты ──────────────────────────────────────────────────
  { id:'ps_restricted', nameRu:'PowerShell: политика',   nameEn:'PS: ExecutionPolicy',  descRu:'ExecutionPolicy ограничена GPO',        descEn:'PS ExecutionPolicy restricted via GPO',hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell',                                           value:'ExecutionPolicy', action:'delete' },
  { id:'ps_no_script',  nameRu:'PowerShell: скрипты',    nameEn:'PS: script block',     descRu:'Блокировка скриптов через HKLM',       descEn:'PowerShell scripting blocked',        hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging',                       value:'EnableScriptBlockLogging', action:'delete' },

  // ── System Restore ────────────────────────────────────────────────────────
  { id:'no_sr',         nameRu:'Восстановление системы',  nameEn:'System Restore',       descRu:'System Restore отключён через GPO',    descEn:'System Restore disabled via policy',  hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore',                                     value:'DisableSR',       action:'delete' },
  { id:'no_config_sr',  nameRu:'Настройка SR',            nameEn:'Configure SR',         descRu:'Настройка System Restore заблокирована',descEn:'SR config blocked',                  hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore',                                     value:'DisableConfig',   action:'delete' },

  // ── Windows Installer ─────────────────────────────────────────────────────
  { id:'no_msi',        nameRu:'Windows Installer',       nameEn:'Windows Installer',    descRu:'Windows Installer отключён',           descEn:'Windows Installer disabled',          hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',                                            value:'DisableMSI',      action:'delete' },

  // ── Логон-уведомления (Ransomware) ───────────────────────────────────────
  { id:'logon_notice',  nameRu:'Логон-сообщение',         nameEn:'Logon notice',         descRu:'Сообщение при входе (LegalNotice)',     descEn:'Login notice text set (ransomware)',  hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',                                   value:'LegalNoticeText', action:'delete' },
  { id:'logon_caption', nameRu:'Заголовок логон-сообщ.',  nameEn:'Logon caption',        descRu:'Заголовок сообщения при входе',        descEn:'Login notice caption set',            hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',                                   value:'LegalNoticeCaption', action:'delete' },

  // ── AutoAdminLogon ────────────────────────────────────────────────────────
  { id:'auto_logon',    nameRu:'Автовход (AutoAdminLogon)',nameEn:'AutoAdminLogon',       descRu:'Настроен автоматический вход в Windows',descEn:'Auto-login configured',              hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',                                   value:'AutoAdminLogon',  action:'delete' },

  // ── Windows Defender дополнительно ────────────────────────────────────────
  { id:'wd_cloud_off',  nameRu:'WD: Облачная защита',     nameEn:'WD: Cloud protection', descRu:'Облачная защита Defender отключена',   descEn:'WD cloud protection off',             hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet',                                      value:'SpynetReporting', action:'delete' },
  { id:'wd_behavior',   nameRu:'WD: Поведенческий анализ',nameEn:'WD: Behavior monitor', descRu:'Поведенческий мониторинг отключён',    descEn:'WD behavior monitoring off',          hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection',                        value:'DisableBehaviorMonitoring', action:'delete' },
  { id:'wd_ioav_off',   nameRu:'WD: Проверка загрузок',   nameEn:'WD: Download scan',    descRu:'Проверка загруженных файлов отключена',descEn:'WD download scanning off',            hive:'hklm', key:'SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection',                        value:'DisableIOAVProtection', action:'delete' },

  // ── Панель задач / Рабочий стол ───────────────────────────────────────────
  { id:'no_taskbar',    nameRu:'Панель задач',             nameEn:'Taskbar',              descRu:'Панель задач заблокирована',           descEn:'Taskbar access blocked',              hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',                              value:'NoSetTaskbar',    action:'delete' },
  { id:'no_start_menu', nameRu:'Меню Пуск',               nameEn:'Start menu',           descRu:'Меню Пуск заблокировано',              descEn:'Start menu blocked',                  hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',                              value:'NoStartMenuSubFolders', action:'delete' },
  { id:'no_disp_cpl',   nameRu:'Параметры экрана',        nameEn:'Display settings',     descRu:'Параметры экрана заблокированы',       descEn:'Display settings blocked',            hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',                                value:'NoDispCPL',       action:'delete' },

  // ── Автозапуск (Autorun) ──────────────────────────────────────────────────
  { id:'autorun_on',    nameRu:'Автозапуск дисков',       nameEn:'Autorun drives',       descRu:'Autorun включён через политику',       descEn:'Autorun enabled via policy',          hive:'hklm', key:'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer',                              value:'NoDriveTypeAutoRun', action:'set_dword:0xff' },

  // ── Безопасность сети ─────────────────────────────────────────────────────
  { id:'no_smb_sign',   nameRu:'SMB: отключена подпись',  nameEn:'SMB: signing off',     descRu:'Подпись SMB-пакетов отключена',        descEn:'SMB packet signing disabled',         hive:'hklm', key:'SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters',                           value:'RequireSecuritySignature', action:'set_dword:1' },

  // ── Event Viewer / Инструменты ────────────────────────────────────────────
  { id:'no_event_viewer',nameRu:'Просмотр событий',       nameEn:'Event Viewer',         descRu:'Event Viewer заблокирован',            descEn:'Event Viewer blocked',                hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',                                value:'DisableEventViewer', action:'delete' },
  { id:'no_devmgr',     nameRu:'Диспетчер устройств',     nameEn:'Device Manager',       descRu:'Диспетчер устройств заблокирован',     descEn:'Device Manager blocked',              hive:'hkcu', key:'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',                                value:'NoDevMgrPage',    action:'delete' },
];

const unlockState = {};
let unlockSortCol = null;
let unlockSortDir = 'asc';

function renderUnlockTable() {
  const tbody = document.getElementById('unlock-tbody');
  if (!tbody) return;

  let rows = RESTRICTIONS.map(r => ({
    r,
    name:   lang === 'ru' ? r.nameRu : r.nameEn,
    desc:   lang === 'ru' ? r.descRu : r.descEn,
    status: unlockState[r.id] || 'unknown',
  }));

  if (unlockSortCol) {
    const statusOrder = { active: 0, checking: 1, unknown: 2, removed: 3 };
    rows.sort((a, b) => {
      let av, bv;
      if (unlockSortCol === 'name')   { av = a.name.toLowerCase();   bv = b.name.toLowerCase(); }
      else if (unlockSortCol === 'desc')   { av = a.desc.toLowerCase();   bv = b.desc.toLowerCase(); }
      else { av = statusOrder[a.status] ?? 2; bv = statusOrder[b.status] ?? 2; }
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return unlockSortDir === 'asc' ? cmp : -cmp;
    });
  }

  tbody.innerHTML = rows.map(({ r, name, desc, status }) => {
    const badgeCls   = { active:'rest-badge-active', removed:'rest-badge-ok', unknown:'rest-badge-unknown', checking:'rest-badge-unknown' }[status] || 'rest-badge-unknown';
    const badgeLabel = { active:t('rest_active'), removed:t('rest_removed'), unknown:t('rest_unknown'), checking:t('unlock_checking') }[status] || status;
    return `<tr data-rest-id="${escHtml(r.id)}">
      <td class="col-ck"><input type="checkbox" class="rest-ck" data-rid="${escHtml(r.id)}"></td>
      <td>${escHtml(name)}</td>
      <td class="td-user">${escHtml(desc)}</td>
      <td><span class="rest-badge ${badgeCls}">${badgeLabel}</span></td>
    </tr>`;
  }).join('');

  // Обновляем стрелки сортировки в заголовках
  document.querySelectorAll('#unlock-table th[data-sort]').forEach(th => {
    th.classList.toggle('sort-asc',  th.dataset.sort === unlockSortCol && unlockSortDir === 'asc');
    th.classList.toggle('sort-desc', th.dataset.sort === unlockSortCol && unlockSortDir === 'desc');
  });

  updateUnlockCount();
}
function updateUnlockCount() {
  const el_cnt = document.getElementById('unlock-status-count');
  if (!el_cnt) return;
  const active  = Object.values(unlockState).filter(v => v === 'active').length;
  const removed = Object.values(unlockState).filter(v => v === 'removed').length;
  el_cnt.innerHTML = `<span style="color:var(--status-suspicious)">${active}</span> активных · <span style="color:var(--status-secure)">${removed}</span> снятых`;
}
async function checkAllRestrictions() {
  const btn = document.getElementById('unlock-check-btn');
  if (btn) btn.classList.add('loading');
  for (const r of RESTRICTIONS) unlockState[r.id] = 'checking';
  renderUnlockTable();
  for (const r of RESTRICTIONS) {
    try {
      if (r.action === 'delete') {
        // Читаем DWORD: -1 = не существует (снято), 0 = явно отключено (снято), 1+ = активно
        const val = await invoke('reg_read_dword_cmd', { hive: r.hive, key: r.key, valueName: r.value });
        unlockState[r.id] = (val > 0) ? 'active' : 'removed';
      } else if (r.action.startsWith('set_dword:')) {
        const target = parseInt(r.action.split(':')[1]);
        const val    = await invoke('reg_read_dword_cmd', { hive: r.hive, key: r.key, valueName: r.value });
        // val === -1 → не существует → значение по умолчанию → ограничение снято
        unlockState[r.id] = (val !== -1 && val !== target) ? 'active' : 'removed';
      }
    } catch { unlockState[r.id] = 'unknown'; }
  }
  if (btn) btn.classList.remove('loading');
  renderUnlockTable();
}
async function unlockRestriction(r) {
  try {
    if (r.action === 'delete') {
      await invoke('reg_delete_value_cmd', { hive: r.hive, key: r.key, valueName: r.value });
    } else if (r.action.startsWith('set_dword:')) {
      const data = parseInt(r.action.split(':')[1]);
      await invoke('reg_set_dword_cmd', { hive: r.hive, key: r.key, valueName: r.value, data });
    }
    unlockState[r.id] = 'removed';
  } catch { unlockState[r.id] = 'unknown'; }
}
async function unlockAll() {
  const btn = document.getElementById('unlock-all-btn');
  if (btn) btn.classList.add('loading');
  for (const r of RESTRICTIONS) if (unlockState[r.id] === 'active') await unlockRestriction(r);
  if (btn) btn.classList.remove('loading');
  renderUnlockTable();
}
async function unlockSelected() {
  const checked = [...document.querySelectorAll('.rest-ck:checked')].map(c => c.dataset.rid);
  if (!checked.length) return;
  const btn = document.getElementById('unlock-sel-btn');
  if (btn) btn.classList.add('loading');
  for (const id of checked) {
    const r = RESTRICTIONS.find(x => x.id === id);
    if (r) await unlockRestriction(r);
  }
  if (btn) btn.classList.remove('loading');
  renderUnlockTable();
}
document.getElementById('unlock-check-all')?.addEventListener('change', e => {
  document.querySelectorAll('.rest-ck').forEach(ck => { ck.checked = e.target.checked; });
});
document.getElementById('unlock-check-btn')?.addEventListener('click',  checkAllRestrictions);
document.getElementById('unlock-all-btn')?.addEventListener('click',    unlockAll);
document.getElementById('unlock-sel-btn')?.addEventListener('click',    unlockSelected);

document.querySelectorAll('#unlock-table th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (unlockSortCol === col) {
      unlockSortDir = unlockSortDir === 'asc' ? 'desc' : 'asc';
    } else {
      unlockSortCol = col;
      unlockSortDir = 'asc';
    }
    renderUnlockTable();
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// ── ИНСТРУМЕНТЫ ───────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const toolOutput = document.getElementById('tool-output');
function toolLog(text) {
  if (!toolOutput) return;
  const ts = new Date().toLocaleTimeString('ru-RU');
  toolOutput.textContent += `\n[${ts}]\n${text}\n`;
  toolOutput.scrollTop = toolOutput.scrollHeight;
}
function toolClear() { if (toolOutput) toolOutput.textContent = ''; }

async function runTool(invokeCmd, args, btnId) {
  const btn = document.getElementById(btnId);
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  const origText = btn ? btn.textContent : '';
  if (btn) btn.textContent = t('tool_running');
  try {
    const result = typeof args === 'undefined'
      ? await invoke(invokeCmd)
      : await invoke(invokeCmd, args);
    toolLog(typeof result === 'string' ? result : JSON.stringify(result, null, 2));
  } catch (err) { toolLog(`[ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; btn.textContent = origText; } }
}

document.getElementById('t-sfc')?.addEventListener('click',           () => runTool('recovery_sfc',           undefined,  't-sfc'));
document.getElementById('t-mbr')?.addEventListener('click',           () => runTool('recovery_fix_mbr',       undefined,  't-mbr'));
document.getElementById('t-bcd')?.addEventListener('click',           () => runTool('recovery_rebuild_bcd',   undefined,  't-bcd'));
document.getElementById('t-accessibility')?.addEventListener('click', () => runTool('recovery_accessibility', undefined,  't-accessibility'));
document.getElementById('t-fonts')?.addEventListener('click',         () => runTool('recovery_fonts',         undefined,  't-fonts'));
document.getElementById('t-assoc')?.addEventListener('click',         () => runTool('recovery_file_assoc',    undefined,  't-assoc'));

document.getElementById('t-logonui')?.addEventListener('click', async () => {
  const btn = document.getElementById('t-logonui');
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  try { await invoke('recovery_logonui'); toolLog('[OK] LogonUI восстановлен'); }
  catch (err) { toolLog(`[ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
});
document.getElementById('t-uac')?.addEventListener('click', async () => {
  const btn = document.getElementById('t-uac');
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  try { await invoke('recovery_uac'); toolLog('[OK] UAC включён'); }
  catch (err) { toolLog(`[ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
});
document.getElementById('t-keyboard')?.addEventListener('click', async () => {
  const btn = document.getElementById('t-keyboard');
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  try { await invoke('recovery_keyboard'); toolLog('[OK] Раскладка клавиатуры восстановлена'); }
  catch (err) { toolLog(`[ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
});
document.getElementById('t-mouse')?.addEventListener('click', async () => {
  const btn = document.getElementById('t-mouse');
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  try { await invoke('recovery_mouse'); toolLog('[OK] Настройки мыши восстановлены'); }
  catch (err) { toolLog(`[ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
});

// Сбросить hosts-файл
document.getElementById('t-hosts')?.addEventListener('click', async () => {
  const btn = document.getElementById('t-hosts');
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  try {
    const result = await invoke('terminal_run', {
      cmd: 'echo 127.0.0.1 localhost > %WINDIR%\\System32\\drivers\\etc\\hosts & echo ::1 localhost >> %WINDIR%\\System32\\drivers\\etc\\hosts',
      powershell: false
    });
    toolLog('[OK] Hosts-файл сброшен\n' + result);
  } catch (err) { toolLog(`[ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
});

// Сбросить прокси
document.getElementById('t-proxy')?.addEventListener('click', async () => {
  const btn = document.getElementById('t-proxy');
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  try {
    const result = await invoke('terminal_run', {
      cmd: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /f & netsh winhttp reset proxy',
      powershell: false
    });
    toolLog('[OK] Прокси сброшен\n' + result);
  } catch (err) { toolLog(`[ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
});

document.getElementById('tool-clear-btn')?.addEventListener('click', toolClear);

// ── Встроенный браузер ────────────────────────────────────────────────────────

document.getElementById('t-browser')?.addEventListener('click', async () => {
  const urlInput = document.getElementById('browser-url');
  const url = urlInput?.value.trim();
  if (!url) return;
  try { await invoke('open_browser_window', { url }); }
  catch (err) { toolLog(`[Браузер ERROR] ${err}`); }
});
document.querySelectorAll('.bm-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const url = btn.dataset.url;
    const urlInput = document.getElementById('browser-url');
    if (urlInput) urlInput.value = url;
    try { await invoke('open_browser_window', { url }); }
    catch (err) { toolLog(`[Браузер ERROR] ${err}`); }
  });
});

// ── Rootkit detection ─────────────────────────────────────────────────────────

document.getElementById('t-hidden-procs')?.addEventListener('click', async () => {
  const btn    = document.getElementById('t-hidden-procs');
  const result = document.getElementById('rootkit-result');
  const tbody  = document.getElementById('rootkit-tbody');
  if (btn) { btn.classList.add('loading'); btn.disabled = true; }
  try {
    const procs = await invoke('find_hidden_processes');
    if (result) result.style.display = 'block';
    if (!procs.length) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:12px;color:var(--status-secure)">✓ Скрытых процессов не обнаружено</td></tr>`;
    } else {
      tbody.innerHTML = procs.map(p => `<tr class="critical-row">
        <td>${p.pid}</td>
        <td class="detail-path">${escHtml(p.path || '—')}</td>
        <td><span class="${p.in_tlhelp ? 'startup-ok' : 'startup-sus'}">${p.in_tlhelp ? '✓' : '✗'}</span></td>
        <td><span class="${p.in_psapi  ? 'startup-ok' : 'startup-sus'}">${p.in_psapi  ? '✓' : '✗'}</span></td>
        <td class="td-user">${escHtml(p.reason)}</td>
      </tr>`).join('');
    }
  } catch (err) { toolLog(`[Rootkit ERROR] ${err}`); }
  finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
});
document.getElementById('rootkit-clear-btn')?.addEventListener('click', () => {
  const result = document.getElementById('rootkit-result');
  if (result) result.style.display = 'none';
});

// ── DLL viewer ────────────────────────────────────────────────────────────────

async function loadDlls(pid) {
  if (!pid) return;
  const result = document.getElementById('dll-result');
  const tbody  = document.getElementById('dll-tbody');
  if (result) result.style.display = 'block';
  tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:8px"><div class="spinner" style="margin:auto"></div></td></tr>`;
  try {
    const dlls = await invoke('get_process_dlls', { pid: Number(pid) });
    if (!dlls.length) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:12px">Нет данных (нет доступа?)</td></tr>`;
    } else {
      tbody.innerHTML = dlls.map(d => `<tr>
        <td class="td-name">${escHtml(d.name)}</td>
        <td class="detail-path" title="${escHtml(d.path)}" style="font-size:10px">${escHtml(d.path)}</td>
        <td style="font-family:monospace;font-size:10px">0x${d.base.toString(16).toUpperCase()}</td>
        <td>${(d.size/1024).toFixed(0)} KB</td>
      </tr>`).join('');
    }
  } catch (err) { tbody.innerHTML = `<tr><td colspan="4">[ERROR] ${escHtml(String(err))}</td></tr>`; }
}
document.getElementById('t-dll-load')?.addEventListener('click', () => {
  const pid = document.getElementById('dll-pid-input')?.value;
  if (!pid) return;
  loadDlls(Number(pid));
});


// ══════════════════════════════════════════════════════════════════════════════
// ── ФАЙЛОВЫЙ МЕНЕДЖЕР ─────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const fmState = {
  currentPath: '',
  entries:     [],
  selected:    new Set(),
  clipboard:   null,
  searchQuery: '',
};

function fmSetStatus(msg) {
  const s = document.getElementById('fm-status');
  if (s) s.textContent = msg;
}

function fmUpdateBreadcrumb(path) {
  const bc = document.getElementById('fm-breadcrumb');
  if (!bc) return;
  if (!path) {
    bc.innerHTML = `<span class="fm-breadcrumb-item fm-bc-root" data-path="">Этот ПК</span>`;
    return;
  }
  const parts = path.replace(/[\\/]+$/, '').split(/[\\/]/);
  let built = '';
  const items = parts.map((part, i) => {
    if (i === 0) built = part + '\\';
    else built += part + (i < parts.length - 1 ? '\\' : '');
    const p = built;
    return `<span class="fm-breadcrumb-sep">›</span><span class="fm-breadcrumb-item" data-path="${escHtml(p)}">${escHtml(part)}</span>`;
  });
  bc.innerHTML = `<span class="fm-breadcrumb-item fm-bc-root" data-path="">Этот ПК</span>${items.join('')}`;
  bc.querySelectorAll('.fm-breadcrumb-item').forEach(el => {
    el.addEventListener('click', () => {
      const p = el.dataset.path;
      if (p === '') fmLoadDrives();
      else fmNavigate(p);
    });
  });
}

async function fmLoadDrives() {
  const tbody  = document.getElementById('fm-tbody');
  const drives = document.getElementById('fm-drives');
  fmState.currentPath = '';
  fmState.selected.clear();
  fmUpdateBreadcrumb('');

  // Быстрый доступ
  const quick = document.getElementById('fm-quick');
  const home  = (await invoke('get_app_dir').catch(() => '')) || '';
  if (quick) {
    const quickPaths = [
      { label: 'Рабочий стол', icon: '🖥', path: `${home}\\..\\..\\Desktop` },
      { label: 'Загрузки',     icon: '⬇', path: `${home}\\..\\..\\Downloads` },
      { label: 'Документы',    icon: '📄', path: `${home}\\..\\..\\Documents` },
    ];
    quick.innerHTML = quickPaths.map(q =>
      `<div class="fm-quick-item" data-path="${escHtml(q.path)}">
        <span class="fm-quick-icon">${q.icon}</span>${escHtml(q.label)}
      </div>`).join('');
    quick.querySelectorAll('.fm-quick-item').forEach(el =>
      el.addEventListener('click', () => fmNavigate(el.dataset.path)));
  }

  try {
    const list = await invoke('fm_get_drives');
    if (drives) {
      drives.innerHTML = list.map(d => {
        const usedPct  = d.total > 0 ? Math.round((1 - d.free / d.total) * 100) : 0;
        const barCls   = usedPct >= 90 ? 'danger' : usedPct >= 75 ? 'warn' : '';
        const freeStr  = formatFileSize(d.free);
        const totalStr = formatFileSize(d.total);
        const icon     = d.letter.startsWith('C') ? '💻' : d.letter.startsWith('D') ? '💿' : '💽';
        return `<div class="fm-drive-item" data-path="${escHtml(d.letter + '\\')}">
          <div class="fm-drive-top">
            <span class="fm-drive-icon">${icon}</span>
            <div class="fm-drive-info">
              <div class="fm-drive-letter">${escHtml(d.letter)}</div>
              <div class="fm-drive-label">${escHtml(d.label || 'Локальный диск')}</div>
            </div>
          </div>
          ${d.total > 0 ? `<div class="fm-drive-bar-wrap"><div class="fm-drive-bar ${barCls}" style="width:${usedPct}%"></div></div>
          <div class="fm-drive-space">${freeStr} / ${totalStr}</div>` : ''}
        </div>`;
      }).join('');
      drives.querySelectorAll('.fm-drive-item').forEach(item => {
        item.addEventListener('click', () => {
          drives.querySelectorAll('.fm-drive-item').forEach(d => d.classList.remove('active'));
          item.classList.add('active');
          fmNavigate(item.dataset.path);
        });
      });
    }
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="icon" style="font-size:48px">⊞</div><div class="label">${t('fm_select_drive')}</div></div></td></tr>`;
    }
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="icon">⚠</div><div class="label">${escHtml(String(err))}</div></div></td></tr>`;
  }
}

async function fmNavigate(path) {
  const tbody = document.getElementById('fm-tbody');
  fmState.currentPath = path;
  fmState.selected.clear();
  fmState.searchQuery = '';
  const searchEl = document.getElementById('fm-search');
  if (searchEl) searchEl.value = '';
  fmUpdateBreadcrumb(path);

  // Подсветить активный диск
  const driveLetter = path.match(/^([A-Za-z]:)/)?.[1]?.toUpperCase();
  document.querySelectorAll('.fm-drive-item').forEach(d => {
    d.classList.toggle('active', d.dataset.path?.startsWith(driveLetter || '__none__'));
  });

  if (tbody) tbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="spinner"></div><div class="label">${t('fm_loading')}</div></div></td></tr>`;
  try {
    const entries = await invoke('fm_list_dir', { path });
    fmState.entries = entries;
    fmRenderEntries();
    const dirs  = entries.filter(e => e.is_dir).length;
    const files = entries.length - dirs;
    fmSetStatus(`${dirs} ${t('fm_status_dirs')}, ${files} ${t('fm_status_files')}`);
    document.getElementById('fm-count').textContent = entries.length + ' ' + t('fm_items');
  } catch (err) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="icon">🔒</div><div class="label">${escHtml(String(err))}</div></div></td></tr>`;
    fmSetStatus('Нет доступа');
  }
}

function fmRenderEntries() {
  const tbody = document.getElementById('fm-tbody');
  if (!tbody) return;
  let entries = fmState.entries;
  if (fmState.searchQuery) {
    const q = fmState.searchQuery.toLowerCase();
    entries = entries.filter(e => e.name.toLowerCase().includes(q));
  }
  if (!entries.length) {
    tbody.innerHTML = `<tr><td colspan="5"><div class="state-overlay"><div class="icon">⬡</div><div class="label">${fmState.searchQuery ? t('fm_search_empty') : t('fm_empty')}</div></div></td></tr>`;
    return;
  }
  tbody.innerHTML = entries.map((e, idx) => {
    const icon    = e.is_dir ? '📁' : fileIcon(e.ext);
    const selCls  = fmState.selected.has(idx) ? 'selected' : '';
    const hidCls  = e.hidden ? 'fm-hidden' : '';
    const sizeStr = e.is_dir ? '' : formatFileSize(e.size);
    const attrs   = [
      e.hidden   ? `<span class="fm-attr-h" title="Скрытый">H</span>` : '',
      e.system   ? `<span class="fm-attr-s" title="Системный">S</span>` : '',
      e.readonly ? `<span class="fm-attr-r" title="Только чтение">R</span>` : '',
    ].filter(Boolean).join('');
    const nameCls = e.is_dir ? 'fm-td-name fm-dir-name' : 'fm-td-name';
    return `<tr class="${selCls} ${hidCls}" data-idx="${idx}" data-path="${escHtml(e.path)}" data-isdir="${e.is_dir}">
      <td class="fm-td-icon">${icon}</td>
      <td class="${nameCls}" title="${escHtml(e.path)}">${escHtml(e.name)}</td>
      <td class="fm-td-size">${sizeStr}</td>
      <td class="fm-td-date">${escHtml(e.modified)}</td>
      <td class="fm-td-attr">${attrs}</td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('tr[data-idx]').forEach(row => {
    row.addEventListener('click', ev => {
      const idx = Number(row.dataset.idx);
      if (!ev.ctrlKey) fmState.selected.clear();
      fmState.selected.has(idx) ? fmState.selected.delete(idx) : fmState.selected.add(idx);
      // Без перерендера — просто меняем класс
      tbody.querySelectorAll('tr[data-idx]').forEach(r =>
        r.classList.toggle('selected', fmState.selected.has(Number(r.dataset.idx))));
      const selCount = fmState.selected.size;
      if (selCount > 0) fmSetStatus(`Выбрано: ${selCount} элем.`);
    });
    row.addEventListener('dblclick', () => {
      if (row.dataset.isdir === 'true') fmNavigate(row.dataset.path);
    });
    row.addEventListener('contextmenu', ev => {
      ev.preventDefault();
      const entry = fmState.entries[Number(row.dataset.idx)];
      if (!entry) return;
      // Выделить строку
      if (!fmState.selected.has(Number(row.dataset.idx))) {
        fmState.selected.clear();
        fmState.selected.add(Number(row.dataset.idx));
        tbody.querySelectorAll('tr[data-idx]').forEach(r =>
          r.classList.toggle('selected', fmState.selected.has(Number(r.dataset.idx))));
      }
      ctxCallback = action => handleFmCtxAction(action, entry);
      const menu = [
        { action:'open',    label: entry.is_dir ? t('fm_ctx_open_dir') : t('fm_ctx_open_file') },
        { sep: true },
        { action:'copy',    label: t('fm_ctx_copy') },
        { action:'rename',  label: t('fm_ctx_rename') },
      ];
      if (!entry.is_dir) {
        menu.push({ sep: true });
        menu.push({ action:'vt', label: t('fm_ctx_vt') });
      }
      menu.push({ sep: true });
      menu.push({ action:'delete', label: t('fm_ctx_delete'), danger: true });
      showCtxMenu(ev, menu);
    });
  });
}

async function handleFmCtxAction(action, entry) {
  switch (action) {
    case 'open':
      if (entry.is_dir) fmNavigate(entry.path);
      else await invoke('open_file_location', { path: entry.path }).catch(e => alert(e));
      break;
    case 'copy':
      fmState.clipboard = { paths: [entry.path], mode: 'copy' };
      document.getElementById('fm-paste-btn').disabled = false;
      fmSetStatus(`${t('fm_copied')}: ${entry.name}`);
      break;
    case 'rename': {
      const newName = prompt(t('fm_rename_prompt'), entry.name);
      if (!newName || newName === entry.name) break;
      try {
        await invoke('fm_rename', { src: entry.path, newName });
        await fmNavigate(fmState.currentPath);
      } catch (err) { alert(`${t('error')}: ${err}`); }
      break;
    }
    case 'vt':
      try {
        const hash = await invoke('compute_sha256', { path: entry.path });
        await invoke('open_browser_window', { url: `https://www.virustotal.com/gui/file/${hash}` });
      } catch (err) { alert(`${t('error')}: ${err}`); }
      break;
    case 'delete':
      if (!confirm(`${t('fm_confirm_delete')}\n${entry.name}`)) break;
      try {
        await invoke('fm_delete_path', { path: entry.path });
        await fmNavigate(fmState.currentPath);
      } catch (err) { alert(`${t('error')}: ${err}`); }
      break;
  }
}

// Поиск в файловом менеджере
document.getElementById('fm-search')?.addEventListener('input', e => {
  fmState.searchQuery = e.target.value.trim();
  fmRenderEntries();
});

function fileIcon(ext) {
  const iconMap = {
    exe:'⚙', dll:'🔩', sys:'🔧', bat:'📜', cmd:'📜', ps1:'💙',
    txt:'📄', log:'📋', ini:'⚙', cfg:'⚙', xml:'📑', json:'📑',
    zip:'📦', rar:'📦', '7z':'📦', tar:'📦', gz:'📦',
    jpg:'🖼', jpeg:'🖼', png:'🖼', gif:'🖼', bmp:'🖼',
    mp3:'🎵', wav:'🎵', mp4:'🎬', avi:'🎬', mkv:'🎬',
    pdf:'📕', doc:'📝', docx:'📝', xls:'📊', xlsx:'📊',
    lnk:'🔗', url:'🔗',
  };
  return iconMap[ext] || '📄';
}

function formatFileSize(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024*1024) return `${(bytes/1024).toFixed(1)} KB`;
  if (bytes < 1024*1024*1024) return `${(bytes/1024/1024).toFixed(1)} MB`;
  return `${(bytes/1024/1024/1024).toFixed(2)} GB`;
}

document.getElementById('fm-root-btn')?.addEventListener('click',    fmLoadDrives);
document.getElementById('fm-refresh-btn')?.addEventListener('click', () => {
  if (fmState.currentPath) fmNavigate(fmState.currentPath); else fmLoadDrives();
});
document.getElementById('fm-up-btn')?.addEventListener('click', () => {
  if (!fmState.currentPath) { fmLoadDrives(); return; }
  const norm  = fmState.currentPath.replace(/[\\/]+$/, '');
  const parts = norm.split(/[\\/]/);
  if (parts.length <= 1) { fmLoadDrives(); return; }
  parts.pop();
  const parent = parts.length === 1 ? parts[0] + '\\' : parts.join('\\');
  fmNavigate(parent);
});
document.getElementById('fm-newfolder-btn')?.addEventListener('click', async () => {
  if (!fmState.currentPath) return;
  const name = prompt(t('fm_new_folder_prompt'));
  if (!name) return;
  const newPath = fmState.currentPath.replace(/[\\/]+$/, '') + '\\' + name;
  try {
    await invoke('fm_create_dir', { path: newPath });
    await fmNavigate(fmState.currentPath);
  } catch (err) { alert(`${t('error')}: ${err}`); }
});
document.getElementById('fm-delete-btn')?.addEventListener('click', async () => {
  const toDelete = [...fmState.selected].map(i => fmState.entries[i]).filter(Boolean);
  if (!toDelete.length) return;
  if (!confirm(`${t('fm_confirm_delete')}\n${toDelete.map(e=>e.name).join('\n')}`)) return;
  for (const entry of toDelete) {
    try { await invoke('fm_delete_path', { path: entry.path }); }
    catch (err) { alert(`${t('error')}: ${err}`); }
  }
  await fmNavigate(fmState.currentPath);
});
document.getElementById('fm-copy-btn')?.addEventListener('click', () => {
  const toCopy = [...fmState.selected].map(i => fmState.entries[i]).filter(Boolean);
  if (!toCopy.length) return;
  fmState.clipboard = { paths: toCopy.map(e => e.path), mode: 'copy' };
  document.getElementById('fm-paste-btn').disabled = false;
  fmSetStatus(`${t('fm_copied')}: ${toCopy.length} ${t('fm_items')}`);
});
document.getElementById('fm-paste-btn')?.addEventListener('click', async () => {
  if (!fmState.clipboard || !fmState.currentPath) return;
  for (const src of fmState.clipboard.paths) {
    try {
      if (fmState.clipboard.mode === 'copy') await invoke('fm_copy', { src, dstDir: fmState.currentPath });
      else                                   await invoke('fm_move', { src, dstDir: fmState.currentPath });
    } catch (err) { alert(`${t('error')}: ${err}`); }
  }
  fmState.clipboard = null;
  document.getElementById('fm-paste-btn').disabled = true;
  await fmNavigate(fmState.currentPath);
});
document.getElementById('fm-rename-btn')?.addEventListener('click', async () => {
  const sel = [...fmState.selected];
  if (sel.length !== 1) return;
  const entry = fmState.entries[sel[0]];
  if (!entry) return;
  const newName = prompt(t('fm_rename_prompt'), entry.name);
  if (!newName || newName === entry.name) return;
  try {
    await invoke('fm_rename', { src: entry.path, newName });
    await fmNavigate(fmState.currentPath);
  } catch (err) { alert(`${t('error')}: ${err}`); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ── Инициализация ─────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

function init() {
  const aboutCopy = document.getElementById('about-copy');
  if (aboutCopy) aboutCopy.textContent = `© ${new Date().getFullYear()} FlowTrust · Rust + Tauri`;

  applyI18n();
  syncSettingsUI();

  if (cfg.alwaysOnTop) invoke('set_always_on_top', { onTop: true }).catch(() => {});
  if (cfg.rotateName)  startTitleRotation();
  if (cfg.notifyThreats) requestNotificationPermission();
  if (cfg.checkUpdates) checkUpdates();

  updateSortHeaders('th[data-col]', state.sortCol, state.sortDir, 'data-col');
  renderUnlockTable();
  loadProcesses();
}

init();
