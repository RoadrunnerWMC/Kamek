using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Kamek
{
    class KamekFile
    {
        public static byte[] PackFrom(Linker linker)
        {
            var kf = new KamekFile();
            kf.LoadFromLinker(linker);
            return kf.Pack();
        }



        private Word _baseAddress;
        private byte[] _codeBlob;
        private long _bssSize;
        private long _ctorStart;
        private long _ctorEnd;

        public Word BaseAddress { get { return _baseAddress; } }
        public byte[] CodeBlob { get { return _codeBlob; } }

        #region Result Binary Manipulation
        public ushort ReadUInt16(Word addr)
        {
            return Util.ExtractUInt16(_codeBlob, addr - _baseAddress);
        }
        public uint ReadUInt32(Word addr)
        {
            return Util.ExtractUInt32(_codeBlob, addr - _baseAddress);
        }
        public void WriteUInt16(Word addr, ushort value)
        {
            Util.InjectUInt16(_codeBlob, addr - _baseAddress, value);
        }
        public void WriteUInt32(Word addr, uint value)
        {
            Util.InjectUInt32(_codeBlob, addr - _baseAddress, value);
        }

        public bool Contains(Word addr)
        {
            return (addr >= _baseAddress && addr < (_baseAddress + _codeBlob.Length));
        }

        public uint QuerySymbolSize(Word addr)
        {
            return _symbolSizes[addr];
        }
        #endregion

        private Dictionary<Word, Commands.Command> _injectionCommands;
        private Dictionary<Word, Commands.Command> _otherCommands;
        // note: injection commands have to come first, since relocations are applied on top of them
        public IEnumerable<KeyValuePair<Word, Commands.Command>> _commands { get { return _injectionCommands.Concat(_otherCommands); } }

        private List<Hooks.Hook> _hooks;
        private Dictionary<Word, uint> _symbolSizes;
        private AddressMapper _mapper;

        public void LoadFromLinker(Linker linker)
        {
            if (_codeBlob != null)
                throw new InvalidOperationException("this KamekFile already has stuff in it");

            _mapper = linker.Mapper;

            // Extract _just_ the code/data sections
            _codeBlob = new byte[linker.OutputEnd - linker.OutputStart];
            Array.Copy(linker.Memory, linker.OutputStart - linker.BaseAddress, _codeBlob, 0, _codeBlob.Length);

            _baseAddress = linker.BaseAddress;
            _bssSize = linker.BssSize;
            _ctorStart = linker.CtorStart - linker.OutputStart;
            _ctorEnd = linker.CtorEnd - linker.OutputStart;

            _hooks = new List<Hooks.Hook>();
            _injectionCommands = new Dictionary<Word, Commands.Command>();
            _otherCommands = new Dictionary<Word, Commands.Command>();

            _symbolSizes = new Dictionary<Word, uint>();
            foreach (var pair in linker.SymbolSizes)
                _symbolSizes.Add(pair.Key, pair.Value);

            AddInjectionCommands(linker.SectionInjections);

            AddRelocsAsCommands(linker.Fixups);

            foreach (var cmd in linker.Hooks)
                ApplyHook(cmd);
            ApplyStaticCommands();
        }

        private void AddInjectionCommands(IReadOnlyList<Linker.SectionInjection> injections)
        {
            foreach (var injection in injections)
            {
                var data = injection.section.data;
                if (data.Length < injection.size)
                {
                    Array.Resize(ref data, (int)injection.size);
                    for (uint offs = (uint)data.Length; offs < injection.size; offs += 4)
                        Util.InjectUInt32(data, offs, 0x60000000);  // nop
                }

                Commands.WriteBlobCommand blobCmd = new Commands.WriteBlobCommand(injection.address, data);

                Commands.Command[] cmds;
                if (blobCmd.IsExplodingBeneficial())
                    cmds = blobCmd.Explode();
                else
                    cmds = new [] {blobCmd};

                foreach (Commands.Command cmd in cmds)
                {
                    cmd.CalculateAddress(this);
                    cmd.AssertAddressNonNull();
                    _injectionCommands[injection.address] = cmd;
                }
            }
        }


        private void AddRelocsAsCommands(IReadOnlyList<Linker.Fixup> relocs)
        {
            foreach (var rel in relocs)
            {
                if (_otherCommands.ContainsKey(rel.source))
                    throw new InvalidOperationException(string.Format("duplicate commands for address {0}", rel.source));
                Commands.Command cmd = new Commands.RelocCommand(rel.source, rel.dest, rel.type);
                cmd.CalculateAddress(this);
                cmd.AssertAddressNonNull();
                _otherCommands[rel.source] = cmd;
            }
        }


        private void ApplyHook(Linker.HookData hookData)
        {
            var hook = Hooks.Hook.Create(hookData, _mapper);
            foreach (var cmd in hook.Commands)
            {
                cmd.CalculateAddress(this);
                cmd.AssertAddressNonNull();
                if (_otherCommands.ContainsKey(cmd.Address.Value))
                    throw new InvalidOperationException(string.Format("duplicate commands for address {0}", cmd.Address.Value));
                _otherCommands[cmd.Address.Value] = cmd;
            }
            _hooks.Add(hook);
        }


        private void ApplyStaticCommands()
        {
            // leave _commands containing just the ones we couldn't apply here
            foreach (var cmdsDict in new[] {_injectionCommands, _otherCommands})
            {
                var original = new Dictionary<Word, Commands.Command>(cmdsDict);
                cmdsDict.Clear();

                foreach (var cmd in original.Values)
                {
                    if (!cmd.Apply(this)) {
                        cmd.AssertAddressNonNull();
                        cmdsDict[cmd.Address.Value] = cmd;
                    }
                }
            }
        }



        public byte[] Pack()
        {
            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms))
                {
                    bw.WriteBE((uint)0x4B616D65); // 'Kamek\0\0\3'
                    bw.WriteBE((uint)0x6B000003);
                    bw.WriteBE((uint)_bssSize);
                    bw.WriteBE((uint)_codeBlob.Length);
                    bw.WriteBE((uint)_ctorStart);
                    bw.WriteBE((uint)_ctorEnd);
                    bw.WriteBE((uint)0);
                    bw.WriteBE((uint)0);

                    bw.Write(_codeBlob);

                    foreach (var pair in _commands)
                    {
                        pair.Value.AssertAddressNonNull();
                        uint cmdID = (uint)pair.Value.Id << 24;
                        if (pair.Value.Address.Value.IsRelative)
                        {
                            if (pair.Value.Address.Value.Value > 0xFFFFFF)
                                throw new InvalidOperationException("Address too high for packed command");

                            cmdID |= pair.Value.Address.Value.Value;
                            bw.WriteBE(cmdID);
                        }
                        else
                        {
                            cmdID |= 0xFFFFFE;
                            bw.WriteBE(cmdID);
                            bw.WriteBE(pair.Value.Address.Value.Value);
                        }
                        pair.Value.WriteArguments(bw);
                    }
                }

                return ms.ToArray();
            }
        }

        public string PackRiivolution()
        {
            if (_baseAddress.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked binary as a Riivolution patch");

            var elements = new List<string>();

            if (_codeBlob.Length > 0)
            {
                // add the big patch
                // (todo: valuefile support)
                elements.Add(Util.PackLargeWriteForRiivolution(_baseAddress, _codeBlob));
            }

            // add individual patches
            foreach (var pair in _commands)
                elements.Add(pair.Value.PackForRiivolution());

            return string.Join("\n", elements);
        }

        public string PackDolphin()
        {
            if (_baseAddress.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked binary as a Dolphin patch");

            var elements = new List<string>();

            // add the big patch
            elements.Add(Util.PackLargeWriteForDolphin(_baseAddress, _codeBlob));

            // add individual patches
            foreach (var pair in _commands)
                elements.Add(pair.Value.PackForDolphin());

            return string.Join("\n", elements);
        }

        public string PackGeckoCodes()
        {
            if (_baseAddress.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked binary as a Gecko code");

            var codes = new List<ulong>();

            if (_codeBlob.Length > 0)
            {
                // add the big patch
                codes.AddRange(Util.PackLargeWriteForGeckoCodes(_baseAddress, _codeBlob));
            }

            // add individual patches
            foreach (var pair in _commands)
                codes.AddRange(pair.Value.PackGeckoCodes());

            // convert everything
            var elements = new string[codes.Count];
            for (int i = 0; i < codes.Count; i++)
                elements[i] = string.Format("{0:X8} {1:X8}", codes[i] >> 32, codes[i] & 0xFFFFFFFF);

            return string.Join("\n", elements);
        }

        public string PackActionReplayCodes()
        {
            if (_baseAddress.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked binary as an Action Replay code");

            var codes = new List<ulong>();

            if (_codeBlob.Length > 0)
            {
                // add the big patch
                codes.AddRange(Util.PackLargeWriteForActionReplayCodes(_baseAddress, _codeBlob));
            }

            // add individual patches
            foreach (var pair in _commands)
                codes.AddRange(pair.Value.PackActionReplayCodes());

            // convert everything
            var elements = new string[codes.Count];
            for (int i = 0; i < codes.Count; i++)
                elements[i] = string.Format("{0:X8} {1:X8}", codes[i] >> 32, codes[i] & 0xFFFFFFFF);

            return string.Join("\n", elements);
        }

        public void InjectIntoDol(Dol dol)
        {
            if (_baseAddress.Type == WordType.RelativeAddr)
                throw new InvalidOperationException("cannot pack a dynamically linked binary into a DOL");

            if (_codeBlob.Length > 0)
            {
                // find an empty text section
                int victimSection = -1;
                for (int i = dol.Sections.Length - 1; i >= 0; i--)
                {
                    if (dol.Sections[i].Data.Length == 0)
                    {
                        victimSection = i;
                        break;
                    }
                }

                if (victimSection == -1)
                    throw new InvalidOperationException("cannot find an empty text section in the DOL");

                // throw the code blob into it
                dol.Sections[victimSection].LoadAddress = _baseAddress.Value;
                dol.Sections[victimSection].Data = _codeBlob;
            }

            // apply all patches
            foreach (var pair in _commands)
                pair.Value.ApplyToDol(dol);
        }
    }
}
