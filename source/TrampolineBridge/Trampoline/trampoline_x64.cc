#include "platform_detect_macro.h"
#if defined(TARGET_ARCH_X64)

#include "dobby/dobby_internal.h"

#include "core/assembler/assembler-x64.h"
#include "core/codegen/codegen-x64.h"

#include "MemoryAllocator/NearMemoryAllocator.h"
#include "InstructionRelocation/x64/InstructionRelocationX64.h"
#include "InterceptRouting/RoutingPlugin.h"

using namespace zz::x64;

static addr_t allocate_indirect_stub(addr_t jmp_insn_addr) {
  uint32_t jmp_near_range = (uint32_t)2 * 1024 * 1024 * 1024;
  auto blk = gNearMemoryAllocator.allocNearDataBlock(sizeof(void *), jmp_insn_addr, jmp_near_range);
  auto stub_addr = blk.start();
  if (stub_addr == 0) {
    ERROR_LOG("Not found near forward stub");
    return 0;
  }

  DEBUG_LOG("forward stub: %p, offset: %lld", stub_addr, stub_addr - jmp_insn_addr);
  return stub_addr;
}

Trampoline *GenerateNormalTrampolineBuffer(addr_t from, addr_t to) {
  __FUNC_CALL_TRACE__();
  TurboAssembler turbo_assembler_(from);
#undef _
#define _ turbo_assembler_. // NOLINT: clang-tidy

  CodeGen codegen(&turbo_assembler_);

  // allocate forward stub
  auto jump_near_next_insn_addr = from + 6;
  addr_t forward_stub = allocate_indirect_stub(jump_near_next_insn_addr);
  if (forward_stub != 0) {
    *(addr_t *)forward_stub = to;
    codegen.JmpNearIndirect((addr_t)forward_stub);
  } else {
    // No free page within +-2GB of the target: embed the destination after the jump instead,
    // jmp *(rip + 0); .quad to (14 bytes)
    codegen.JmpNearIndirect(from + 6);
    turbo_assembler_.code_buffer()->Emit<int64_t>(to);
  }

  auto tramp_buffer = turbo_assembler_.code_buffer();
  auto tramp_block = tramp_buffer->dup();
  auto tramp = new Trampoline(TRAMPOLINE_X64_JMP, tramp_block);
  DEBUG_LOG("[trampoline] trampoline addr: %p(temp), %p(real), size: %d", tramp->addr(), from, tramp->size());
  debug_hex_log_buffer((uint8_t *)tramp->addr(), tramp->size());
  return tramp;
}

Trampoline *GenerateNearTrampolineBuffer(addr_t src, addr_t dst) {
  DEBUG_LOG("x64 near branch trampoline enable default");
  return nullptr;
}

#endif