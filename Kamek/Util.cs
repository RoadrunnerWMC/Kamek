using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kamek
{
    static class Util
    {
        public static ushort ReadBigUInt16(this BinaryReader br)
        {
            byte a = br.ReadByte();
            byte b = br.ReadByte();
            return (ushort)((a << 8) | b);
        }

        public static uint ReadBigUInt32(this BinaryReader br)
        {
            ushort a = br.ReadBigUInt16();
            ushort b = br.ReadBigUInt16();
            return (uint)((a << 16) | b);
        }

        public static int ReadBigInt32(this BinaryReader br)
        {
            ushort a = br.ReadBigUInt16();
            ushort b = br.ReadBigUInt16();
            return (int)((a << 16) | b);
        }

        public static void WriteBE(this BinaryWriter bw, ushort value)
        {
            bw.Write((byte)(value >> 8));
            bw.Write((byte)(value & 0xFF));
        }

        public static void WriteBE(this BinaryWriter bw, uint value)
        {
            bw.WriteBE((ushort)(value >> 16));
            bw.WriteBE((ushort)(value & 0xFFFF));
        }


        public static ushort ExtractUInt16(byte[] array, long offset)
        {
            return (ushort)((array[offset] << 8) | array[offset + 1]);
        }
        public static uint ExtractUInt32(byte[] array, long offset)
        {
            return (uint)((array[offset] << 24) | (array[offset + 1] << 16) |
                (array[offset + 2] << 8) | array[offset + 3]);
        }
        public static void InjectUInt16(byte[] array, long offset, ushort value)
        {
            array[offset] = (byte)((value >> 8) & 0xFF);
            array[offset + 1] = (byte)(value & 0xFF);
        }
        public static void InjectUInt32(byte[] array, long offset, uint value)
        {
            array[offset] = (byte)((value >> 24) & 0xFF);
            array[offset + 1] = (byte)((value >> 16) & 0xFF);
            array[offset + 2] = (byte)((value >> 8) & 0xFF);
            array[offset + 3] = (byte)(value & 0xFF);
        }


        public static string ExtractNullTerminatedString(byte[] table, int offset)
        {
            if (offset >= 0 && offset < table.Length)
            {
                // find where it ends
                for (int i = offset; i < table.Length; i++)
                {
                    if (table[i] == 0)
                    {
                        return Encoding.ASCII.GetString(table, offset, i - offset);
                    }
                }
            }

            return null;
        }


        public static void DumpToConsole(byte[] array)
        {
            int lines = array.Length / 16;

            for (int offset = 0; offset < array.Length; offset += 0x10)
            {
                Console.Write("{0:X8} | ", offset);

                for (int pos = offset; pos < (offset + 0x10) && pos < array.Length; pos++)
                {
                    Console.Write("{0:X2} ", array[pos]);
                }

                Console.Write("| ");

                for (int pos = offset; pos < (offset + 0x10) && pos < array.Length; pos++)
                {
                    if (array[pos] >= ' ' && array[pos] <= 0x7F)
                        Console.Write("{0}", (char)array[pos]);
                    else
                        Console.Write(".");
                }

                Console.WriteLine();
            }
        }

        public static string PackLargeWriteForRiivolution(Word address, byte[] data)
        {
            if (address.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked data blob as a Riivolution patch");

            var sb = new StringBuilder(data.Length * 2);
            for (int i = 0; i < data.Length; i++)
                sb.AppendFormat("{0:X2}", data[i]);

            return string.Format("<memory offset='0x{0:X8}' value='{1}' />", address.Value, sb.ToString());
        }

        public static string PackLargeWriteForDolphin(Word address, byte[] data)
        {
            if (address.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked data blob as a Dolphin patch");

            var elements = new List<string>();

            int i = 0;
            while (i < data.Length)
            {
                var sb = new StringBuilder(27);
                sb.AppendFormat("0x{0:X8}:", address.Value + i);

                int lineLength;
                switch (data.Length - i)
                {
                    case 1:
                        lineLength = 1;
                        sb.Append("byte:0x000000");
                        break;
                    case 2:
                    case 3:
                        lineLength = 2;
                        sb.Append("word:0x0000");
                        break;
                    default:
                        lineLength = 4;
                        sb.Append("dword:0x");
                        break;
                }

                for (int j = 0; j < lineLength; j++, i++)
                    sb.AppendFormat("{0:X2}", data[i]);

                elements.Add(sb.ToString());
            }

            return string.Join("\n", elements);
        }

        public static IEnumerable<ulong> PackLargeWriteForGeckoCodes(Word address, byte[] data)
        {
            if (address.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked data blob as a Gecko code");

            var codes = new List<ulong>();

            long paddingSize = 0;
            if ((data.Length % 8) != 0)
                paddingSize = 8 - (data.Length % 8);

            ulong header = 0x06000000UL << 32;
            header |= (ulong)(address.Value & 0x1FFFFFF) << 32;
            header |= (ulong)(data.Length + paddingSize) & 0xFFFFFFFF;
            codes.Add(header);

            for (int i = 0; i < data.Length; i += 8)
            {
                ulong bits = 0;
                if (i < data.Length) bits |= (ulong)data[i] << 56;
                if ((i + 1) < data.Length) bits |= (ulong)data[i + 1] << 48;
                if ((i + 2) < data.Length) bits |= (ulong)data[i + 2] << 40;
                if ((i + 3) < data.Length) bits |= (ulong)data[i + 3] << 32;
                if ((i + 4) < data.Length) bits |= (ulong)data[i + 4] << 24;
                if ((i + 5) < data.Length) bits |= (ulong)data[i + 5] << 16;
                if ((i + 6) < data.Length) bits |= (ulong)data[i + 6] << 8;
                if ((i + 7) < data.Length) bits |= (ulong)data[i + 7];
                codes.Add(bits);
            }

            return codes;
        }
    }
}
