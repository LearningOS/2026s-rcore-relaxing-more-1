//! Types related to task management
use super::TaskContext;
use crate::config::{PAGE_SIZE, TRAP_CONTEXT_BASE};
use crate::mm::{
    kernel_stack_position, MapPermission, MemorySet, PhysPageNum, VirtAddr, KERNEL_SPACE,
};
use crate::trap::{trap_handler, TrapContext};

/// The task control block (TCB) of a task.
pub struct TaskControlBlock {
    /// Save task context
    pub task_cx: TaskContext,

    /// Maintain the execution status of the current process
    pub task_status: TaskStatus,

    /// Application address space
    pub memory_set: MemorySet,

    /// The phys page number of trap context
    pub trap_cx_ppn: PhysPageNum,

    /// The size(top addr) of program which is loaded from elf file
    pub base_size: usize,

    /// Heap bottom
    pub heap_bottom: usize,

    /// Program break
    pub program_brk: usize,
    /// Syscall times
    pub syscall_times: [u32; crate::config::MAX_SYSCALL_NUM],
}

impl TaskControlBlock {
    /// get the trap context
    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }
    /// get the user token
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    /// Based on the elf info in program, build the contents of task in a new address space
    pub fn new(elf_data: &[u8], app_id: usize) -> Self {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT_BASE).into())
            .unwrap()
            .ppn();
        let task_status = TaskStatus::Ready;
        // map a kernel-stack in kernel space
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(app_id);
        KERNEL_SPACE.exclusive_access().insert_framed_area(
            kernel_stack_bottom.into(),
            kernel_stack_top.into(),
            MapPermission::R | MapPermission::W,
        );
        let task_control_block = Self {
            task_status,
            task_cx: TaskContext::goto_trap_return(kernel_stack_top),
            memory_set,
            trap_cx_ppn,
            base_size: user_sp,
            heap_bottom: user_sp,
            program_brk: user_sp,
                    syscall_times: [0; crate::config::MAX_SYSCALL_NUM],
        };
        // prepare TrapContext in user space
        let trap_cx: &mut TrapContext = task_control_block.get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }
    /// change the location of the program break. return None if failed.
    pub fn change_program_brk(&mut self, size: i32) -> Option<usize> {
        let old_break = self.program_brk;
        let new_brk = self.program_brk as isize + size as isize;
        if new_brk < self.heap_bottom as isize {
            return None;
        }
        let result = if size < 0 {
            self.memory_set
                .shrink_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        } else {
            self.memory_set
                .append_to(VirtAddr(self.heap_bottom), VirtAddr(new_brk as usize))
        };
        if result {
            self.program_brk = new_brk as usize;
            Some(old_break)
        } else {
            None
        }
    }

    /// Map anonymous pages with user permissions.
    pub fn mmap(&mut self, start: usize, len: usize, prot: usize) -> bool {
        // Check that start is page-aligned
        if start % PAGE_SIZE != 0 {
            return false;
        }
        // Check prot validity: other bits must be 0
        if prot & !0x7 != 0 {
            return false;
        }
        // Check prot has at least one permission bit set (cannot be all 0)
        if prot & 0x7 == 0 {
            return false;
        }
        // If len is 0, just return success (no-op)
        if len == 0 {
            return true;
        }
        // Calculate end address with page alignment for length
        let end = start + len;
        let aligned_end = (end + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
        // Check for overflow
        if aligned_end < start {
            return false;
        }
        // Check if any page in [start, aligned_end) is already mapped
        if self.memory_set.is_overlapping(start.into(), aligned_end.into()) {
            return false;
        }
        // Convert prot bits to MapPermission
        let mut permission = MapPermission::U;
        if prot & 1 != 0 {
            permission |= MapPermission::R;
        }
        if prot & 2 != 0 {
            permission |= MapPermission::W;
        }
        if prot & 4 != 0 {
            permission |= MapPermission::X;
        }
        self.memory_set
            .insert_framed_area(start.into(), aligned_end.into(), permission);
        true
    }

    /// Remove an anonymous mapping created by `mmap`.
    pub fn munmap(&mut self, start: usize, len: usize) -> bool {
        // Check that start is page-aligned
        if start % PAGE_SIZE != 0 {
            return false;
        }
        // len == 0 should fail for munmap
        if len == 0 {
            return false;
        }
        // Calculate end address with page alignment for length
        let end = start + len;
        let aligned_end = (end + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
        // Check for overflow
        if aligned_end < start {
            return false;
        }
        // Check if any page in [start, aligned_end) is NOT mapped (exists unmapped gap)
        if !self.memory_set.is_fully_mapped(start.into(), aligned_end.into()) {
            return false;
        }
        // Remove the entire mapped area
        self.memory_set.remove_area(start.into(), aligned_end.into())
    }
}

#[derive(Copy, Clone, PartialEq)]
/// task status: UnInit, Ready, Running, Exited
pub enum TaskStatus {
    /// uninitialized
    UnInit,
    /// ready to run
    Ready,
    /// running
    Running,
    /// exited
    Exited,
}
