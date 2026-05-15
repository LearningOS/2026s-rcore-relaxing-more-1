//! Process management syscalls
use alloc::sync::Arc;

use crate::{
    config::BIG_CONST,
    loader::get_app_data_by_name,
    mm::{MapPermission, VirtAddr, VirtPageNum, translated_byte_buffer, translated_refmut, translated_str},
    task::{
        TaskControlBlock, add_task, current_task, current_user_token, exit_current_and_run_next, suspend_current_and_run_next
    },
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {

    let start = _ts as usize;
    let end = start + core::mem::size_of::<TimeVal>();

    let start_va: VirtAddr = start.into();
    let end_va: VirtAddr = end.into();
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    for vpn in start_vpn.0..end_vpn.0 {
        let vpn = VirtPageNum(vpn);
        if current_task()
            .unwrap()
            .inner_exclusive_access()
            .memory_set
            .translate(vpn)
            .map(|pte| pte.is_valid())
            .unwrap_or(false)
            == false
        {
            return -1;
        }
    }

    let us= crate::timer::get_time_us();
    let sec = us / 1_000_000;
    let usec = us % 1_000_000;

    let usize_bytes = core::mem::size_of::<usize>();
    let mut raw = [0u8; core::mem::size_of::<TimeVal>()];
    raw[..usize_bytes].copy_from_slice(&sec.to_ne_bytes());
    raw[usize_bytes..].copy_from_slice(&usec.to_ne_bytes());

    let mut off = 0usize;
    let bufs = translated_byte_buffer(current_user_token(), _ts as *const u8, core::mem::size_of::<TimeVal>());
    for b in bufs {
        let l =b.len();
        b.copy_from_slice(&raw[off..off + l]);
        off += l;
    }
    0

}

/// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    let _end = _start + _len;
    let _start_va: VirtAddr = _start.into();
    let _end_va: VirtAddr = _end.into();

    if !_start_va.aligned() {
        return -1;
    }

    if _port & !0x07 != 0 {
        return -1;
    }

    if _port & 0x07 == 0 {
        return -1;
    }

    let start_vpn = _start_va.floor();
    let end_vpn = _end_va.ceil();

    // Check for conflicts with existing mappings
    for vpn in start_vpn.0..end_vpn.0 {
        let vpn = VirtPageNum(vpn);
        if current_task()
            .unwrap()
            .inner_exclusive_access()
            .memory_set
            .translate(vpn)
            .map(|pte| pte.is_valid())
            .unwrap_or(false)
        {
            return -1;
        }
    }

    let mut map_perm = MapPermission::U;
    if _port & 0x01 != 0 {
        map_perm |= MapPermission::R;
    }
    if _port & 0x02 != 0 {
        map_perm |= MapPermission::W;
        map_perm |= MapPermission::R; // W requires R in RISC-V
    }
    if _port & 0x04 != 0 {
        map_perm |= MapPermission::X;
    }

    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if inner.memory_set.insert_framed_area_fallible(
        _start.into(),
        _end.into(),
        map_perm,
    ) {
        0
    } else {
        -1
    }
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    let _start_va: VirtAddr = _start.into();
    let _end_va: VirtAddr = (_start + _len).into();

    if !_start_va.aligned() {
        return -1;
    }

    let start_vpn = _start_va.floor();
    let end_vpn = _end_va.ceil();

    for vpn in start_vpn.0..end_vpn.0 {
        let vpn = VirtPageNum(vpn);
        if current_task()
            .unwrap()
            .inner_exclusive_access()
            .memory_set
            .translate(vpn)
            .map(|pte| pte.is_valid())
            .unwrap_or(false)
            == false
        {
            return -1;
        }
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    inner.memory_set.remove_area_with_start_vpn(VirtAddr::from(_start).floor());
    0
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, _path);
    if let Some(elf_data) = get_app_data_by_name(path.as_str()) {
        let current_task = current_task().unwrap();
        let task = Arc::new(TaskControlBlock::new(elf_data));
        let pid = task.pid.0;
        // add child to parent's children list
        current_task.inner_exclusive_access().children.push(task.clone());
        add_task(task.clone());
        task.exec(elf_data);
        pid as isize
    } else {
        -1
    }
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    if _prio <= 1 {
        return -1;
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    inner.priority = _prio as usize;
    inner.pass = (BIG_CONST / inner.priority) as u128;
    _prio
}
