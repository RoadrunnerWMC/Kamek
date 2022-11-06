using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kamek.Commands
{
    class WriteBlobCommand : Command
    {
        public readonly byte[] Value;

        public WriteBlobCommand(Word address, byte[] value)
            : base(Command.Ids.WriteBlob, address)
        {
            Value = value;
        }

        public override void WriteArguments(BinaryWriter bw)
        {
            AssertValue();

            bw.WriteBE((uint)Value.Length);
            bw.Write(Value);

            // Align to 4
            if (Value.Length % 4 == 1)
                bw.Write(new byte[] {0, 0, 0});
            else if (Value.Length % 4 == 2)
                bw.Write(new byte[] {0, 0});
            else if (Value.Length % 4 == 3)
                bw.Write(new byte[] {0});
        }

        public bool IsExplodingBeneficial()
        {
            return Value.Length <= 4;
        }

        public WriteWordCommand[] Explode()
        {
            // We assume that the destination address will be 32-bit aligned

            uint cursor = 0;
            List<WriteWordCommand> cmds = new List<WriteWordCommand>();

            while (cursor + 4 <= Value.Length)
            {
                cmds.Add(new WriteWordCommand(
                    Address.Value + cursor,
                    new Word(WordType.Value, Util.ExtractUInt32(Value, cursor)),
                    WriteWordCommand.Type.Value32,
                    null));
                cursor += 4;
            }

            if (cursor + 2 <= Value.Length)
            {
                cmds.Add(new WriteWordCommand(
                    Address.Value + cursor,
                    new Word(WordType.Value, Util.ExtractUInt16(Value, cursor)),
                    WriteWordCommand.Type.Value16,
                    null));
                cursor += 2;
            }

            if (cursor < Value.Length)
            {
                cmds.Add(new WriteWordCommand(
                    Address.Value + cursor,
                    new Word(WordType.Value, Value[cursor]),
                    WriteWordCommand.Type.Value8,
                    null));
            }

            return cmds.ToArray();
        }

        public override string PackForRiivolution()
        {
            Address.Value.AssertAbsolute();
            AssertValue();

            return Util.PackLargeWriteForRiivolution(Address.Value, Value);
        }

        public override string PackForDolphin()
        {
            Address.Value.AssertAbsolute();
            AssertValue();

            return Util.PackLargeWriteForDolphin(Address.Value, Value);
        }

        public override IEnumerable<ulong> PackGeckoCodes()
        {
            Address.Value.AssertAbsolute();
            AssertValue();

            if (Address.Value.Value >= 0x90000000)
                throw new NotImplementedException("MEM2 writes not yet supported for gecko");

            return Util.PackLargeWriteForGeckoCodes(Address.Value, Value);
        }

        public override void ApplyToDol(Dol dol)
        {
            Address.Value.AssertAbsolute();
            AssertValue();

            for (uint offs = 0; offs < Value.Length; offs++)
                dol.WriteByte(Address.Value.Value + offs, Value[offs]);
        }

        public override bool Apply(KamekFile file)
        {
            return false;
        }

        private void AssertValue()
        {
            if (Value.Length == 0)
                throw new InvalidOperationException("WriteBlobCommand has no data to write");
        }
    }
}
