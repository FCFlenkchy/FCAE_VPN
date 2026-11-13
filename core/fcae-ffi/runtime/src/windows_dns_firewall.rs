use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::{UuidCreate, RPC_C_AUTHN_WINNT, RPC_S_UUID_LOCAL_ONLY};

use crate::error::{CoreError, Result};

fn checked(code: u32, operation: &str) -> Result<()> {
    if code == 0 { return Ok(()); }
    Err(CoreError::Internal(format!("Windows DNS protection: {operation} failed (0x{code:08x})")))
}

// The dynamic session owns all filters and can be moved between supervisor threads.
pub(crate) struct DnsFirewall { engine: usize }

impl DnsFirewall {
    pub(crate) fn install(interface_index: u32, mut interface_luid: u64) -> Result<Self> {
        let mut session = FWPM_SESSION0::default();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine: HANDLE = ptr::null_mut();
        checked(unsafe { FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT, ptr::null(), &session, &mut engine) }, "open filtering engine")?;
        let guard = Self { engine: engine as usize };
        let engine = guard.engine as HANDLE;
        let mut sublayer_key = GUID::default();
        let uuid_status = unsafe { UuidCreate(&mut sublayer_key) };
        if uuid_status != 0 && uuid_status != RPC_S_UUID_LOCAL_ONLY {
            return Err(CoreError::Internal(format!("Windows DNS protection: create sublayer ID failed ({uuid_status})")));
        }
        checked(unsafe { FwpmTransactionBegin0(engine, 0) }, "begin filter transaction")?;
        let result = (|| -> Result<()> {
            let mut name: Vec<u16> = "FCAE TUN DNS protection".encode_utf16().chain(Some(0)).collect();
            let mut sublayer = FWPM_SUBLAYER0::default();
            sublayer.subLayerKey = sublayer_key;
            sublayer.displayData.name = name.as_mut_ptr();
            sublayer.weight = u16::MAX;
            checked(unsafe { FwpmSubLayerAdd0(engine, &sublayer, ptr::null_mut()) }, "add filter sublayer")?;

            // ALE rejects new flows; outbound transport also checks each packet,
            // including flows that existed before the filters were installed.
            for (layer, transport) in [
                (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
                (FWPM_LAYER_ALE_AUTH_CONNECT_V6, false),
                (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, true),
                (FWPM_LAYER_OUTBOUND_TRANSPORT_V6, true),
            ] {
                for port in [53u16, 853] {
                    for protocol in [6u8, 17u8] {
                        let mut conditions = [FWPM_FILTER_CONDITION0::default(); 3];
                        conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                        conditions[0].matchType = FWP_MATCH_EQUAL;
                        conditions[0].conditionValue.r#type = FWP_UINT16;
                        conditions[0].conditionValue.Anonymous.uint16 = port;
                        conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                        conditions[1].matchType = FWP_MATCH_EQUAL;
                        conditions[1].conditionValue.r#type = FWP_UINT8;
                        conditions[1].conditionValue.Anonymous.uint8 = protocol;

                        let mut filter = FWPM_FILTER0::default();
                        filter.displayData.name = name.as_mut_ptr();
                        filter.layerKey = layer;
                        filter.subLayerKey = sublayer_key;
                        filter.weight.r#type = FWP_UINT8;
                        filter.weight.Anonymous.uint8 = 0;
                        filter.filterCondition = conditions.as_mut_ptr();
                        filter.numFilterConditions = 2;
                        filter.action.r#type = FWP_ACTION_BLOCK;
                        checked(unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut()) }, "add DNS block filter")?;

                        conditions[2].matchType = FWP_MATCH_EQUAL;
                        if transport {
                            conditions[2].fieldKey = FWPM_CONDITION_INTERFACE_INDEX;
                            conditions[2].conditionValue.r#type = FWP_UINT32;
                            conditions[2].conditionValue.Anonymous.uint32 = interface_index;
                        } else {
                            conditions[2].fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                            conditions[2].conditionValue.r#type = FWP_UINT64;
                            conditions[2].conditionValue.Anonymous.uint64 = &mut interface_luid;
                        }
                        filter.numFilterConditions = 3;
                        filter.weight.Anonymous.uint8 = 15;
                        filter.action.r#type = FWP_ACTION_PERMIT;
                        checked(unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut()) }, "add tunnel DNS permit filter")?;
                    }
                }
            }
            checked(unsafe { FwpmTransactionCommit0(engine) }, "commit DNS filters")?;
            Ok(())
        })();
        if result.is_err() { unsafe { FwpmTransactionAbort0(engine); } }
        result?;
        log::info!("[tun] Windows DNS protection enabled for TCP/UDP ports 53 and 853");
        Ok(guard)
    }
}

impl Drop for DnsFirewall {
    fn drop(&mut self) {
        let code = unsafe { FwpmEngineClose0(self.engine as HANDLE) };
        if code != 0 { log::warn!("[tun] closing Windows DNS protection failed (0x{code:08x})"); }
    }
}
