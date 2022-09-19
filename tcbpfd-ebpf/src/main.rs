#![no_std]
#![no_main]

use core::mem;
use aya_bpf::{
    macros::classifier,
    programs::TcContext,
    bindings::TC_ACT_OK,
};
use aya_log_ebpf::info;
use memoffset::offset_of;

mod bindings;
use bindings::{ethhdr, iphdr};


#[classifier(name="tcbpfd")]
pub fn tcbpfd(ctx: TcContext) -> i32 {
    match try_tcbpfd(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tcbpfd(ctx: TcContext) -> Result<i32, i32> {    
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_OK)?,
    );

    match h_proto {
        ETH_P_IP => {
            let source = u32::from_be(
                ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))
                    .map_err(|_| TC_ACT_OK)?,
            );
            let dest = u32::from_be(
                ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))
                    .map_err(|_| TC_ACT_OK)?,
            );
            info!(&ctx, "source IPv4: {:ipv4}, {:x}, {:X}\ndest IPv4: {:ipv4}, {:x}, {:X}", 
            source, source, source, dest, dest, dest);
        }
        _ => return Ok(TC_ACT_OK),
    }


    Ok(TC_ACT_OK)
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
