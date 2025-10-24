using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kamek.Commands
{
    class RelocCommand : Command
    {
        private const uint LOW24_MASK = 0x03FFFFFC;
        private const uint LOW14_MASK = 0x0000FFFC;
        private const uint BIT10_MASK = 0x00100000;

        public readonly Word Target;

        public RelocCommand(Word source, Word target, Elf.Reloc reloc)
            : base((Ids)reloc, source)
        {
            Target = target;
        }

        public override void WriteArguments(BinaryWriter bw)
        {
            Target.AssertNotAmbiguous();
            bw.WriteBE(Target.Value);
        }

        public override string PackForRiivolution()
        {
            throw new NotImplementedException();
        }

        public override string PackForDolphin()
        {
            throw new NotImplementedException();
        }

        public override IEnumerable<ulong> PackGeckoCodes()
        {
            throw new NotImplementedException();
        }

        public override IEnumerable<ulong> PackActionReplayCodes()
        {
            throw new NotImplementedException();
        }

        private string GetRelocName()
        {
            return Enum.GetName(typeof(Ids), Id);
        }

        private void EnsureUpperBitsMatch(uint value, int num_bits)
        {
            uint mask = ((1u << num_bits) - 1) << (32 - num_bits);
            if ((value & mask) != 0 && (value & mask) != mask)
                throw new NotImplementedException(string.Format("illegal {0} relocation (0x{1:x} & 0x{2:x})", GetRelocName(), value, mask));
        }

        private void EnsureLowerBitsZero(uint value, int num_bits)
        {
            uint mask = ((1u << num_bits) - 1);
            if ((value & mask) != 0)
                throw new NotImplementedException(string.Format("illegal {0} relocation (0x{1:x} & 0x{2:x})", GetRelocName(), value, mask));
        }

        private void SetBranchPredictionBit(ref uint insn)
        {
            bool neg_disp = (insn & 0x8000) != 0;

            if (Id == Ids.Addr14BrTaken || Id == Ids.Rel14BrTaken)
                insn = (insn & ~BIT10_MASK) & (!neg_disp ? BIT10_MASK : 0);
            else if (Id == Ids.Addr14BrNTaken || Id == Ids.Rel14BrNTaken)
                insn = (insn & ~BIT10_MASK) & (neg_disp ? BIT10_MASK : 0);
        }

        private ushort CalculateHighAdjusted()
        {
            ushort v = (ushort)(Target.Value >> 16);
            if ((Target.Value & 0x8000) == 0x8000)
                v++;
            return v;
        }

        public override void ApplyToCodeFile(CodeFiles.CodeFile file)
        {
            Address.Value.AssertAbsolute();
            Target.AssertAbsolute();
            uint insn, delta;

            switch (Id)
            {
                case Ids.Addr32:
                    file.WriteUInt32(Address.Value.Value, Target.Value);
                    break;

                case Ids.Addr24:
                    EnsureUpperBitsMatch(Target.Value, 7);
                    insn = file.ReadUInt32(Address.Value.Value) & ~LOW24_MASK;
                    insn |= (uint)Target.Value & LOW24_MASK;
                    file.WriteUInt32(Address.Value.Value, insn);
                    break;

                case Ids.Addr16:
                    EnsureUpperBitsMatch(Target.Value, 17);
                    goto case Ids.Addr16Lo;

                case Ids.Addr16Lo:
                    file.WriteUInt16(Address.Value.Value, (ushort)(Target.Value & 0xFFFF));
                    break;

                case Ids.Addr16Hi:
                    file.WriteUInt16(Address.Value.Value, (ushort)(Target.Value >> 16));
                    break;

                case Ids.Addr16Ha:
                    file.WriteUInt16(Address.Value.Value, CalculateHighAdjusted());
                    break;

                case Ids.Addr14:
                case Ids.Addr14BrTaken:
                case Ids.Addr14BrNTaken:
                    EnsureUpperBitsMatch(Target.Value, 17);
                    EnsureLowerBitsZero(Target.Value, 2);

                    insn = file.ReadUInt32(Address.Value.Value) & ~LOW14_MASK;
                    insn |= (uint)Target.Value & LOW14_MASK;
                    SetBranchPredictionBit(ref insn);

                    file.WriteUInt32(Address.Value.Value, insn);
                    break;

                case Ids.Rel24:
                    delta = (uint)(Target - Address.Value);
                    insn = file.ReadUInt32(Address.Value.Value) & ~LOW24_MASK;
                    insn |= delta & LOW24_MASK;
                    file.WriteUInt32(Address.Value.Value, insn);
                    break;

                case Ids.Rel14:
                case Ids.Rel14BrTaken:
                case Ids.Rel14BrNTaken:
                    delta = (uint)(Target - Address.Value);

                    EnsureUpperBitsMatch(delta, 17);
                    EnsureLowerBitsZero(delta, 2);

                    insn = file.ReadUInt32(Address.Value.Value) & ~LOW14_MASK;
                    insn |= delta & LOW14_MASK;
                    SetBranchPredictionBit(ref insn);

                    file.WriteUInt32(Address.Value.Value, insn);
                    break;

                default:
                    throw new NotImplementedException(string.Format("unrecognised relocation type {0}", Id));
            }
        }

        public override bool Apply(KamekFile file)
        {
            if (Address.Value.Type != file.BaseAddress.Type)
                return false;

            switch (Id)
            {
                case Ids.Addr32:
                    if (Target.IsAbsolute)
                    {
                        file.WriteUInt32(Address.Value, Target.Value);
                        return true;
                    }
                    break;

                case Ids.Addr24:
                    if (Target.IsAbsolute)
                    {
                        EnsureUpperBitsMatch(Target.Value, 7);

                        uint insn = file.ReadUInt32(Address.Value) & ~LOW24_MASK;
                        insn |= (uint)Target.Value & LOW24_MASK;

                        file.WriteUInt32(Address.Value, insn);
                        return true;
                    }
                    break;

                case Ids.Addr16:
                    if (Target.IsAbsolute)
                    {
                        EnsureUpperBitsMatch(Target.Value, 17);
                    }
                    goto case Ids.Addr16Lo;

                case Ids.Addr16Lo:
                    if (Target.IsAbsolute)
                    {
                        file.WriteUInt16(Address.Value, (ushort)(Target.Value & 0xFFFF));
                        return true;
                    }
                    break;

                case Ids.Addr16Hi:
                    if (Target.IsAbsolute)
                    {
                        file.WriteUInt16(Address.Value, (ushort)(Target.Value >> 16));
                        return true;
                    }
                    break;

                case Ids.Addr16Ha:
                    if (Target.IsAbsolute)
                    {
                        file.WriteUInt16(Address.Value, CalculateHighAdjusted());
                        return true;
                    }
                    break;

                case Ids.Addr14:
                case Ids.Addr14BrTaken:
                case Ids.Addr14BrNTaken:
                    if (Target.IsAbsolute)
                    {
                        EnsureUpperBitsMatch(Target.Value, 17);
                        EnsureLowerBitsZero(Target.Value, 2);

                        uint insn = file.ReadUInt32(Address.Value) & ~LOW14_MASK;
                        insn |= (uint)Target.Value & LOW14_MASK;
                        SetBranchPredictionBit(ref insn);

                        file.WriteUInt32(Address.Value, insn);
                        return true;
                    }
                    break;

                case Ids.Rel24:
                    if ((Address.Value.IsAbsolute && Target.IsAbsolute) || (Address.Value.IsRelative && Target.IsRelative))
                    {
                        uint delta = (uint)(Target - Address.Value);
                        uint insn = file.ReadUInt32(Address.Value) & ~LOW24_MASK;
                        insn |= delta & LOW24_MASK;
                        file.WriteUInt32(Address.Value, insn);

                        return true;
                    }
                    break;

                case Ids.Rel14:
                case Ids.Rel14BrTaken:
                case Ids.Rel14BrNTaken:
                    if (Target.IsAbsolute)
                    {
                        uint delta = (uint)(Target - Address.Value);

                        EnsureUpperBitsMatch(delta, 17);
                        EnsureLowerBitsZero(delta, 2);

                        uint insn = file.ReadUInt32(Address.Value) & ~LOW14_MASK;
                        insn |= delta & LOW14_MASK;
                        SetBranchPredictionBit(ref insn);

                        file.WriteUInt32(Address.Value, insn);
                        return true;
                    }
                    break;

                default:
                    throw new NotImplementedException(string.Format("unrecognised relocation type {0}", Id));
            }

            return false;
        }
    }
}
