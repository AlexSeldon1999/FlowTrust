// Модуль сетевых соединений через IP Helper API (iphlpapi.dll)
// GetExtendedTcpTable / GetExtendedUdpTable с флагом OWNER_PID.

use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable,
    MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_CLOSE_WAIT, MIB_TCP_STATE_CLOSING,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_FIN_WAIT1,
    MIB_TCP_STATE_FIN_WAIT2, MIB_TCP_STATE_LAST_ACK, MIB_TCP_STATE_LISTEN,
    MIB_TCP_STATE_SYN_RCVD, MIB_TCP_STATE_SYN_SENT, MIB_TCP_STATE_TIME_WAIT,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID,  MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

// ── Типы ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Protocol { Tcp, Udp }

#[derive(Debug, Clone)]
pub enum TcpState {
    Listen, SynSent, SynReceived, Established,
    FinWait1, FinWait2, CloseWait, Closing,
    LastAck, TimeWait, Closed, DeleteTcb, Unknown,
}

impl TcpState {
    /// dwState из MIB_TCPROW_OWNER_PID — u32, а константы MIB_TCP_STATE_* — i32.
    fn from_raw(v: u32) -> Self {
        let v = v as i32;
        if      v == MIB_TCP_STATE_LISTEN.0     { TcpState::Listen }
        else if v == MIB_TCP_STATE_SYN_SENT.0   { TcpState::SynSent }
        else if v == MIB_TCP_STATE_SYN_RCVD.0   { TcpState::SynReceived }
        else if v == MIB_TCP_STATE_ESTAB.0       { TcpState::Established }
        else if v == MIB_TCP_STATE_FIN_WAIT1.0   { TcpState::FinWait1 }
        else if v == MIB_TCP_STATE_FIN_WAIT2.0   { TcpState::FinWait2 }
        else if v == MIB_TCP_STATE_CLOSE_WAIT.0  { TcpState::CloseWait }
        else if v == MIB_TCP_STATE_CLOSING.0     { TcpState::Closing }
        else if v == MIB_TCP_STATE_LAST_ACK.0    { TcpState::LastAck }
        else if v == MIB_TCP_STATE_TIME_WAIT.0   { TcpState::TimeWait }
        else if v == MIB_TCP_STATE_CLOSED.0      { TcpState::Closed }
        else if v == MIB_TCP_STATE_DELETE_TCB.0  { TcpState::DeleteTcb }
        else                                      { TcpState::Unknown }
    }
}

// Сериализуем TcpState как читаемую строку
impl Serialize for TcpState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let label = match self {
            TcpState::Listen      => "LISTEN",
            TcpState::SynSent     => "SYN_SENT",
            TcpState::SynReceived => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1    => "FIN_WAIT1",
            TcpState::FinWait2    => "FIN_WAIT2",
            TcpState::CloseWait   => "CLOSE_WAIT",
            TcpState::Closing     => "CLOSING",
            TcpState::LastAck     => "LAST_ACK",
            TcpState::TimeWait    => "TIME_WAIT",
            TcpState::Closed      => "CLOSED",
            TcpState::DeleteTcb   => "DELETE_TCB",
            TcpState::Unknown     => "UNKNOWN",
        };
        s.serialize_str(label)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub pid:          u32,
    pub process_name: String,
    pub protocol:     Protocol,
    pub local_addr:   String,
    pub local_port:   u16,
    pub remote_addr:  String,
    pub remote_port:  u16,
    pub state:        TcpState,
}

// Ручная сериализация, чтобы state шёл как строка (TcpState уже impl Serialize выше)
impl Serialize for ConnectionInfo {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("ConnectionInfo", 8)?;
        st.serialize_field("pid",          &self.pid)?;
        st.serialize_field("process_name", &self.process_name)?;
        st.serialize_field("protocol",     &self.protocol)?;
        st.serialize_field("local_addr",   &self.local_addr)?;
        st.serialize_field("local_port",   &self.local_port)?;
        st.serialize_field("remote_addr",  &self.remote_addr)?;
        st.serialize_field("remote_port",  &self.remote_port)?;
        st.serialize_field("state",        &self.state)?;
        st.end()
    }
}

// ── Утилиты ───────────────────────────────────────────────────────────────────

/// u32 big-endian (сетевой порядок байт) → строка IPv4
fn ip4(raw: u32) -> String {
    Ipv4Addr::from(raw.to_be()).to_string()
}

/// Порт из network byte order (raw u32) → u16 host order
fn port(raw: u32) -> u16 {
    (raw as u16).swap_bytes()
}

// ── TCP ───────────────────────────────────────────────────────────────────────

unsafe fn tcp_connections(pid_to_name: &HashMap<u32, String>) -> Vec<ConnectionInfo> {
    // Шаг 1: узнаём нужный размер буфера
    let mut size: u32 = 0;
    GetExtendedTcpTable(
        None, &mut size, false,
        AF_INET.0 as u32,
        TCP_TABLE_OWNER_PID_ALL, 0,
    );
    if size == 0 { return vec![]; }

    let mut buf = vec![0u8; size as usize];

    // Шаг 2: получаем данные; возвращает u32 (0 = NO_ERROR)
    let err = GetExtendedTcpTable(
        Some(buf.as_mut_ptr() as *mut _), &mut size, false,
        AF_INET.0 as u32,
        TCP_TABLE_OWNER_PID_ALL, 0,
    );
    if err != 0 { return vec![]; }

    let table   = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
    let count   = table.dwNumEntries as usize;
    let row_ptr = table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID;

    (0..count).map(|i| {
        let r = &*row_ptr.add(i);
        let pid = r.dwOwningPid;
        ConnectionInfo {
            pid,
            process_name: pid_to_name.get(&pid).cloned().unwrap_or_default(),
            protocol:    Protocol::Tcp,
            local_addr:  ip4(r.dwLocalAddr),
            local_port:  port(r.dwLocalPort),
            remote_addr: ip4(r.dwRemoteAddr),
            remote_port: port(r.dwRemotePort),
            state:       TcpState::from_raw(r.dwState),
        }
    }).collect()
}

// ── UDP ───────────────────────────────────────────────────────────────────────

unsafe fn udp_listeners(pid_to_name: &HashMap<u32, String>) -> Vec<ConnectionInfo> {
    let mut size: u32 = 0;
    GetExtendedUdpTable(
        None, &mut size, false,
        AF_INET.0 as u32,
        UDP_TABLE_OWNER_PID, 0,
    );
    if size == 0 { return vec![]; }

    let mut buf = vec![0u8; size as usize];

    let err = GetExtendedUdpTable(
        Some(buf.as_mut_ptr() as *mut _), &mut size, false,
        AF_INET.0 as u32,
        UDP_TABLE_OWNER_PID, 0,
    );
    if err != 0 { return vec![]; }

    let table   = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
    let count   = table.dwNumEntries as usize;
    let row_ptr = table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID;

    (0..count).map(|i| {
        let r = &*row_ptr.add(i);
        let pid = r.dwOwningPid;
        ConnectionInfo {
            pid,
            process_name: pid_to_name.get(&pid).cloned().unwrap_or_default(),
            protocol:    Protocol::Udp,
            local_addr:  ip4(r.dwLocalAddr),
            local_port:  port(r.dwLocalPort),
            remote_addr: String::new(),
            remote_port: 0,
            state:       TcpState::Unknown,
        }
    }).collect()
}

// ── Разрыв TCP-соединения ─────────────────────────────────────────────────────

/// Принудительно закрывает TCP-соединение через SetTcpEntry(DELETE_TCB).
/// Принимает адреса/порты в HOST-byte-order.
pub fn kill_tcp_connection(
    local_addr:  &str,
    local_port:  u16,
    remote_addr: &str,
    remote_port: u16,
) -> Result<(), String> {
    use std::net::Ipv4Addr;
    use windows::Win32::NetworkManagement::IpHelper::{MIB_TCPROW_LH, MIB_TCPROW_LH_0, SetTcpEntry};

    let la: Ipv4Addr = local_addr.parse()
        .map_err(|_| format!("Неверный локальный адрес: {}", local_addr))?;
    let ra: Ipv4Addr = remote_addr.parse()
        .map_err(|_| format!("Неверный удалённый адрес: {}", remote_addr))?;

    // Windows хранит адреса в little-endian, порты — в big-endian (network byte order)
    let local_addr_raw  = u32::from_ne_bytes(la.octets());
    let remote_addr_raw = u32::from_ne_bytes(ra.octets());
    let local_port_raw  = (local_port  as u32).swap_bytes() >> 16;
    let remote_port_raw = (remote_port as u32).swap_bytes() >> 16;

    let row = MIB_TCPROW_LH {
        Anonymous:     MIB_TCPROW_LH_0 { dwState: MIB_TCP_STATE_DELETE_TCB.0 as u32 },
        dwLocalAddr:   local_addr_raw,
        dwLocalPort:   local_port_raw,
        dwRemoteAddr:  remote_addr_raw,
        dwRemotePort:  remote_port_raw,
    };

    unsafe {
        let ret = SetTcpEntry(&row);
        if ret != 0 {
            Err(format!("SetTcpEntry вернул код ошибки: {}", ret))
        } else {
            Ok(())
        }
    }
}

// ── Публичная функция ─────────────────────────────────────────────────────────

pub fn get_connections(pid_to_name: HashMap<u32, String>) -> Vec<ConnectionInfo> {
    unsafe {
        let mut result = tcp_connections(&pid_to_name);
        result.extend(udp_listeners(&pid_to_name));

        // Сортировка: ESTABLISHED → LISTEN (TCP) → остальной TCP → UDP
        result.sort_by(|a, b| {
            let rank = |c: &ConnectionInfo| match (&c.protocol, &c.state) {
                (Protocol::Tcp, TcpState::Established) => 0,
                (Protocol::Tcp, TcpState::Listen)      => 1,
                (Protocol::Tcp, _)                     => 2,
                (Protocol::Udp, _)                     => 3,
            };
            rank(a).cmp(&rank(b)).then(a.process_name.cmp(&b.process_name))
        });

        result
    }
}
