#include "platform_detect_macro.h"

#if defined(TARGET_ARCH_IA32) || defined(TARGET_ARCH_X64)

#include "dobby/dobby_internal.h"

#include "InstructionRelocation/x86/InstructionRelocationX86.h"
#include "InstructionRelocation/x86/x86_insn_decode/x86_insn_decode.h"

using namespace zz::x86;

// x64 jmp absolute address
inline void codegen_x64_jmp_absolute_addr(CodeMemBuffer *buffer, addr_t target) {
  // jmp *(rip)
  buffer->Emit<int8_t>(0xFF);
  buffer->Emit<int8_t>(0x25); // ModR/M: 00 100 101
  buffer->Emit<int32_t>(0x00);
  // .long target
  buffer->Emit<int64_t>(target);
}

// simple impl for ReloLabel
inline void emit_rel32_label(CodeMemBuffer *buffer, uint32_t last_offset, addr_t curr_relo_ip, addr_t orig_dst_ip) {
  addr_t curr_offset = buffer->buffer_size;
  uint32_t relo_insn_len = curr_offset + sizeof(uint32_t) - last_offset;
  addr_t relo_ip = curr_relo_ip + relo_insn_len;
  int32_t new_offset = orig_dst_ip - relo_ip;
  buffer->Emit<int32_t>(new_offset);
}

// Offset of the first opcode byte: after the legacy prefixes and the REX prefix.
static int x86_insn_opcode_offset(const uint8_t *insn, int8_t mode, int *rex_offset) {
  int offset = 0;
  for (;; offset++) {
    switch (insn[offset]) {
    case 0xF0: case 0xF2: case 0xF3: case 0x2E: case 0x36:
    case 0x3E: case 0x26: case 0x64: case 0x65: case 0x66: case 0x67:
      continue;
    }
    break;
  }
  *rex_offset = -1;
  if (mode == 64 && insn[offset] >= 0x40 && insn[offset] <= 0x4F) {
    *rex_offset = offset;
    offset++;
  }
  return offset;
}

// x64 jcc to an absolute address: jcc +2; jmp +14; jmp *(rip); .quad dst
inline void codegen_x64_jcc_absolute_addr(CodeMemBuffer *buffer, uint8_t condition, addr_t target) {
  buffer->Emit<int8_t>(0x70 | (condition & 0x0F));
  buffer->Emit<int8_t>(2);
  buffer->Emit<int8_t>(0xEB);
  buffer->Emit<int8_t>(6 + 8);
  codegen_x64_jmp_absolute_addr(buffer, target);
}

// An instruction with a [rip + disp32] operand whose target is out of reach from the relocated code.
// The operand is rewritten to [scratch], with the scratch register holding the absolute target.
// lea/push/pop/mov leave the flags alone, and the red zone below rsp is skipped before touching
// the stack, so the instruction sees the same registers, flags and memory as at its original place.
inline void codegen_x64_rip_insn_absolute(CodeMemBuffer *buffer, const uint8_t *insn, const x86_insn_decode_t &decoded,
                                          addr_t target) {
  static const uint8_t skip_red_zone[] = {0x48, 0x8D, 0x64, 0x24, 0x80};                 // lea rsp, [rsp - 0x80]
  static const uint8_t restore_red_zone[] = {0x48, 0x8D, 0xA4, 0x24, 0x80, 0x00, 0x00, 0x00}; // lea rsp, [rsp + 0x80]

  int rex_offset;
  int opcode_offset = x86_insn_opcode_offset(insn, 64, &rex_offset);
  int modrm_offset = decoded.displacement_offset - 1;
  uint8_t modrm = insn[modrm_offset];
  uint8_t modrm_reg = (modrm >> 3) & 7;
  bool reg_extended = rex_offset >= 0 && (insn[rex_offset] & 0x04);
  bool one_byte_opcode = insn[opcode_offset] != 0x0F;
  int after_disp = decoded.displacement_offset + 4;

  if (one_byte_opcode && insn[opcode_offset] == 0xFF && (modrm_reg == 2 || modrm_reg == 4)) {
    // call/jmp *[rip + disp]: r11 is neither an argument nor preserved across a call, so it is free here.
    buffer->Emit<uint8_t>(0x49); // movabs r11, target
    buffer->Emit<uint8_t>(0xBB);
    buffer->Emit<uint64_t>(target);
    buffer->Emit<uint8_t>(0x41); // call/jmp *[r11]
    buffer->Emit<uint8_t>(0xFF);
    buffer->Emit<uint8_t>(modrm_reg == 2 ? 0x13 : 0x23);
    return;
  }

  if (one_byte_opcode && insn[opcode_offset] == 0xFF && modrm_reg == 6) {
    // push qword [rip + disp]: the value goes into the slot the push would have used.
    static const uint8_t body[] = {
        0x48, 0x8D, 0x64, 0x24, 0xF8,                   // lea rsp, [rsp - 8]      (the pushed slot)
        0x48, 0x8D, 0x64, 0x24, 0x80,                   // lea rsp, [rsp - 0x80]
        0x56,                                           // push rsi
    };
    buffer->EmitBuffer((uint8_t *)body, sizeof(body));
    buffer->Emit<uint8_t>(0x48); // movabs rsi, target
    buffer->Emit<uint8_t>(0xBE);
    buffer->Emit<uint64_t>(target);
    static const uint8_t tail[] = {
        0x48, 0x8B, 0x36,                               // mov rsi, [rsi]
        0x48, 0x89, 0xB4, 0x24, 0x88, 0x00, 0x00, 0x00, // mov [rsp + 0x88], rsi
        0x5E,                                           // pop rsi
        0x48, 0x8D, 0xA4, 0x24, 0x80, 0x00, 0x00, 0x00, // lea rsp, [rsp + 0x80]
    };
    buffer->EmitBuffer((uint8_t *)tail, sizeof(tail));
    return;
  }

  if (one_byte_opcode && insn[opcode_offset] == 0x8F && modrm_reg == 0) {
    // pop qword [rip + disp]
    buffer->EmitBuffer((uint8_t *)skip_red_zone, sizeof(skip_red_zone));
    buffer->Emit<uint8_t>(0x56); // push rsi
    buffer->Emit<uint8_t>(0x57); // push rdi
    buffer->Emit<uint8_t>(0x48); // movabs rsi, target
    buffer->Emit<uint8_t>(0xBE);
    buffer->Emit<uint64_t>(target);
    static const uint8_t tail[] = {
        0x48, 0x8B, 0xBC, 0x24, 0x90, 0x00, 0x00, 0x00, // mov rdi, [rsp + 0x90]   (the value to pop)
        0x48, 0x89, 0x3E,                               // mov [rsi], rdi
        0x5F,                                           // pop rdi
        0x5E,                                           // pop rsi
        0x48, 0x8D, 0xA4, 0x24, 0x88, 0x00, 0x00, 0x00, // lea rsp, [rsp + 0x88]   (red zone + popped slot)
    };
    buffer->EmitBuffer((uint8_t *)tail, sizeof(tail));
    return;
  }

  // Any other instruction: the same encoding with [rsi] (or [rdi] when rsi is the register operand)
  // in place of [rip + disp]. No instruction with a ModRM memory operand uses rsi/rdi implicitly.
  uint8_t scratch = (!reg_extended && modrm_reg == 6) ? 7 : 6;
  buffer->EmitBuffer((uint8_t *)skip_red_zone, sizeof(skip_red_zone));
  buffer->Emit<uint8_t>(0x50 | scratch); // push scratch
  buffer->Emit<uint8_t>(0x48);           // movabs scratch, target
  buffer->Emit<uint8_t>(0xB8 | scratch);
  buffer->Emit<uint64_t>(target);
  for (int i = 0; i < modrm_offset; i++) {
    // REX.B extended the RIP base, which ignores it; with a register base it must be clear.
    buffer->Emit<uint8_t>(i == rex_offset ? (insn[i] & ~0x01) : insn[i]);
  }
  buffer->Emit<uint8_t>((modrm & 0x38) | scratch); // mod 00, rm = scratch
  buffer->EmitBuffer((uint8_t *)insn + after_disp, decoded.length - after_disp);
  buffer->Emit<uint8_t>(0x58 | scratch); // pop scratch
  buffer->EmitBuffer((uint8_t *)restore_red_zone, sizeof(restore_red_zone));
}

int GenRelocateSingleX86Insn(addr_t curr_orig_ip, addr_t curr_relo_ip, uint8_t *buffer_cursor, AssemblerBase *assembler,
                             CodeMemBuffer *code_buffer, x86_insn_decode_t &insn, int8_t mode) {
#define __ code_buffer->

  int relocated_insn_len = -1;

  x86_options_t conf = {0};
  conf.mode = mode;

  // decode x86/x64 insn
  x86_insn_decode(&insn, (uint8_t *)buffer_cursor, &conf);

  // x86 ip register == next instruction address
  curr_orig_ip = curr_orig_ip + insn.length;

  auto last_relo_offset = code_buffer->buffer_size;

  static auto x86_insn_encode_start = 0;
  auto x86_insn_encode_begin = [&] { x86_insn_encode_start = code_buffer->buffer_size; };

  // The decoder reports the second opcode byte as primary_opcode for 0x0F-escaped instructions,
  // so one-byte branch opcodes must be told apart from two-byte ones (0F 70..7F are SSE, not jcc).
  int rex_offset;
  int opcode_offset = x86_insn_opcode_offset(buffer_cursor, mode, &rex_offset);
  bool one_byte_opcode = buffer_cursor[opcode_offset] != 0x0F;

  if (one_byte_opcode && insn.primary_opcode >= 0x70 && insn.primary_opcode <= 0x7F) { // jcc rel8
    DEBUG_LOG("[x86 relo] %p: jc rel8", buffer_cursor);

    int8_t offset = insn.immediate;
    addr_t orig_dst_ip = curr_orig_ip + offset;
#if defined(TARGET_ARCH_IA32)
    uint8_t opcode = 0x80 | (insn.primary_opcode & 0x0f);

    x86_insn_encode_begin();
    __ Emit<int8_t>(0x0F);
    __ Emit<int8_t>(opcode);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    // jcc_true stage 1
    const uint8_t label_jcc_cond_true_stage2 = 2;
    __ Emit<int8_t>(insn.primary_opcode);
    __ Emit<int8_t>(label_jcc_cond_true_stage2);

    // jcc_false
    const uint8_t label_cond_false = 6 + 8;
    __ Emit<int8_t>(0xEB);
    __ Emit<int8_t>(label_cond_false);

    // jcc_true stage 2, jmp to orig dst
    codegen_x64_jmp_absolute_addr(code_buffer, orig_dst_ip);
#endif

  } else if (!one_byte_opcode && insn.primary_opcode >= 0x80 && insn.primary_opcode <= 0x8F) { // jcc rel32
    DEBUG_LOG("[x86 relo] %p: jcc rel32", buffer_cursor);

    int32_t offset;
    memcpy(&offset, buffer_cursor + insn.length - sizeof(offset), sizeof(offset));
    addr_t orig_dst_ip = curr_orig_ip + offset;
#if defined(TARGET_ARCH_IA32)
    x86_insn_encode_begin();
    __ Emit<int8_t>(0x0F);
    __ Emit<int8_t>(insn.primary_opcode);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    codegen_x64_jcc_absolute_addr(code_buffer, insn.primary_opcode, orig_dst_ip);
#endif

  } else if (mode == 64 && (insn.flags & X86_INSN_DECODE_FLAG_IP_RELATIVE)) { // [rip + disp32] operand
    DEBUG_LOG("[x86 relo] %p: rip", buffer_cursor);

    int32_t orig_disp;
    memcpy(&orig_disp, buffer_cursor + insn.displacement_offset, sizeof(orig_disp));
    addr_t orig_dst_ip = curr_orig_ip + orig_disp;

    // Same instruction with the displacement rebased when the target is still within reach,
    // otherwise the operand is rewritten to use the absolute address.
    int64_t new_disp = (int64_t)orig_dst_ip - (int64_t)(curr_relo_ip + insn.length);
    if (new_disp == (int32_t)new_disp) {
      int32_t disp32 = (int32_t)new_disp;
      __ EmitBuffer(buffer_cursor, insn.displacement_offset);
      __ Emit<int32_t>(disp32);
      __ EmitBuffer(buffer_cursor + insn.displacement_offset + sizeof(disp32),
                    insn.length - insn.displacement_offset - sizeof(disp32));
    } else {
      codegen_x64_rip_insn_absolute(code_buffer, buffer_cursor, insn, orig_dst_ip);
    }

  } else if (one_byte_opcode && insn.primary_opcode == 0xEB) { // jmp rel8
    DEBUG_LOG("[x86 relo] %p: jmp rel8", buffer_cursor);

    int8_t offset = insn.immediate;
    addr_t orig_dst_ip = curr_orig_ip + offset;

#if defined(TARGET_ARCH_IA32)
    x86_insn_encode_begin();
    __ Emit<int8_t>(0xE9);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    // jmp *(rip)
    codegen_x64_jmp_absolute_addr(code_buffer, orig_dst_ip);
#endif
  } else if (one_byte_opcode && (insn.primary_opcode == 0xE8 || insn.primary_opcode == 0xE9)) { // call or jmp rel32
    DEBUG_LOG("[x86 relo] %p:jmp or call rel32", buffer_cursor);

    int32_t offset = insn.immediate;
    addr_t orig_dst_ip = curr_orig_ip + offset;

    assert(insn.immediate_offset == 1);

#if defined(TARGET_ARCH_IA32)
    x86_insn_encode_begin();

    __ EmitBuffer(buffer_cursor, insn.immediate_offset);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    __ Emit<int8_t>(0xFF);
    if (insn.primary_opcode == 0xE8) {
      // call *(rip + 2)
      __ Emit<int8_t>(0x15); // ModR/M: 00 010 101
      __ Emit<int32_t>(2);

      // jmp 8
      __ Emit<int8_t>(0xEB);
      __ Emit<int8_t>(0x08);

      // dst
      __ Emit<int64_t>(orig_dst_ip);
    } else {
      // jmp *(rip)
      __ Emit<int8_t>(0x25); // ModR/M: 00 100 101
      __ Emit<int32_t>(0);

      // dst
      __ Emit<int64_t>(orig_dst_ip);
    }
#endif
  } else if (one_byte_opcode && insn.primary_opcode >= 0xE0 && insn.primary_opcode <= 0xE2) { // LOOPNZ/LOOPZ/LOOP
    // LOOP/LOOPcc
    UNIMPLEMENTED();
  } else if (one_byte_opcode && insn.primary_opcode == 0xE3) {
    // JCXZ JCEXZ JCRXZ
    UNIMPLEMENTED();
  } else {
    __ EmitBuffer(buffer_cursor, insn.length);
  }

  // insn -> relocated insn
  {
    int relo_offset = code_buffer->buffer_size;
    int relo_len = relo_offset - last_relo_offset;
    DEBUG_LOG("insn -> relocated insn: %d -> %d", insn.length, relo_len);
  }
  return relocated_insn_len;
}

void GenRelocateCodeX86Shared(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch) {
  int expected_relocated_mem_size = 32;
x86_try_again:
  if (!relocated->addr()) {
    auto blk = gMemoryAllocator.allocExecBlock(expected_relocated_mem_size);
    auto relocated_mem = blk.addr();
    if (relocated_mem == 0) {
      return;
    }
    relocated->reset((addr_t)relocated_mem, expected_relocated_mem_size);
  }

  int ret = GenRelocateCodeFixed(buffer, origin, relocated, branch);
  if (ret != 0) {
    const int step_size = 16;
    expected_relocated_mem_size += step_size;
    relocated->reset(0, 0);

    goto x86_try_again;
  }
}

#endif
