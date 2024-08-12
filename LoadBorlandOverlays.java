// Loads overlays from a Borland-compiled executable, appends them to the program, and wires them up.
//@author Amir Grozki
//@category Borland
//@keybinding
//@menupath
//@toolbar


import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.datastruct.IntIntHashtable;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/* offset,segment pair */;
//class FarPtr {
//    short ofs;
//    short seq;
//}

class MzHeader {
    // 00 Magic number MZ_MAGIC
    short magic;

    // 02 Bytes of last page
    //   If it is 4, it should be treated as 0,
    //   since pre-1.10 versions of the MS linker
    //   set it that way.
    short cblp;

    // 04 Pages in file
    short cp;

    // 06 Number of relocation entries
    short crlc;

    // 08 Size of header in paragraphs
    short cparhdr;

    // 0A Minimum extra paragraphs needed
    short minalloc;

    // 0C Maximum extra paragraphs needed
    // if 0 DOS loads as high as possible, else above PSP
    // The maximum allocation is set to FFFFh by default.
    short maxalloc;

    // 0E Initial (relative) SS value
    short ss;

    // 10 Initial SP value
    short sp;

    // 12 Checksum (0 = no checksum)
    short csum;

    // 14 Initial IP value
    short ip;

    // 16 Initial (relative) CS value
    short cs;

    // 18 File address of relocation table
    short lfarlc;

    // 1A Microsoft Overlay number
    //    MS LINK can create single EXE containing multiple
    //    overlays (up to 63) which are simply numbered in
    //    sequence.
    //    The 0 one is loaded by DOS
    //    Each overlay within the file is essentially an
    //    EXE file (structure) with its own MZ header.
    short ovno;
}

//typedef struct {
//uint16_t seg;
//uint16_t size;
//int refs;       //number of references;
//int trefs;      //number of references by the targets of relocations
//int ofs;        //flat offset
//} mz_uniq_seg_t;

//borland MZ header extension
class BorlandMzExtension {
    // always 0x0001?
    short unk0;

    // 0xFB
    byte id;

    // major nybl, minor is low nybl
    byte version;

    // euther 0x726A (v3.0+) or 0x6A72 (prior to v3.0)
    short unk1;

    // always 0?
    byte[/*34*/] unk2 = new byte[34];
}

//class BorlandStartupTable { // Entry in the Borlands's startup's table of init functions
//    byte calltype; // 0=near,1=far,ff=not used
//    byte priority; // 0=highest,ff=lowest
//    FarPtr addr;
//}

class BorlandFileHeader { //Borland file header
    public static final int SIZE = 4 + 4 + 4 + 4;

    public static final short FB_FB = 0x4246;
    public static final short FB_OV = 0x564F;

    // magic id FBOV_MAGIC ('FB','OV')
    short[/*2*/] id = new short[2];

    // size in bytes of the FBOV section excluding its header
    int size;

    // offset to the boseg_t array from the start of MZ header
    // OVERLAY.LIB names it _SEGTABLE_ or TSegMap
    int stofs;

    // number of the boseg_t entries at stofs
    int nsegs;
}

class BorlandSegmentEntry { //borland overlay segment entry
    public static final int SIZE = 2 + 2 + 2 + 2;

    public static final short FBOV_CODE = 1;
    public static final short FBOV_OVR = 2;
    public static final short FBOV_DATA = 4;

    // Segment (coincides with the MZ reloc table segments)
    short seg;

    // Maximum offset inside that segment
    // 0xFFFF - Ignored by the linker's OvrCodeReloc
    short maxoff;

    // FBOV_CODE,FBOV_OVR,FBOV_DATA
    short flags;

    // Minimum offset inside that segment,
    // I.e. when the data/code doesn't begin on the paragrapsh
    short minoff;
}

class BorlandTrap { //trapped jmp, which overlay manager turns into a normal one
    public static final short SIZE = 2 + 2 + 1;

    //on the first entry
    //int 3Fh (0xCD 0x3F)
    byte[/*2*/] code = new byte[2];

    //offset inside the overlay
    short ofs;

    // unused
    byte pad;
}

// Overlay header record, defined in RTL/INC/SE.ASM
class BorlandOverlayHeaderRecord {
    public static final int SIZE = 2 + 4 + 10 * 2 + 6;

    // 00 int 3Fh (0xCD 0x3F) overlay manager interrupt
    //   OvrMan replaces stack returns from overlayed
    //   functions by calls to this address
    //   when the calling overlay gets unladed
    //   ot it can be restored on return.
    //   OvrMan actually walks the stack frames.
    byte[/*2*/] code = new byte[2];

    // 02 offest of the actual function return address
    //   which gets returned to after OvrMan
    //   restores it's overlay
    short saveret;

    // 04 offset inside the EXE file
    //   retative the end of bofh_t
    int fileofs;

    // 08 size of the overlay
    short codesz;

    // 0A size in bytes of the table of pointers to data
    //   which we must relocate after loading the overlay
    //   In EXE the table is located just after the code.
    //   The pointers are relative to the bufseg,
    //   and each is short.
    short fixupsz;

    // 0C number of fbov_trmp_t to update on load
    //   the jumps are located just after this header
    short jmpcnt;

    // Following are the OvrMan houskeeping fields.

    // 0E backlink?
    short link;

    // 10 Buffer segment (0 = overlay is not loaded)
    //   location of the overlay inside memory
    short bufseg;

    // 12 used to track number of calls to the overlay
    //   also holds next segment for OVRINIT
    short retrycnt;

    // 14 next loaded overlay
    short next;

    // 16 location of the overlay inside expanded memory
    short ems_page;

    // 18 ofset of the function loading the overlay
    short ems_ofs;

    // 1A Runtime data about the users of this segment
    // 1A user[0] flags:
    //  2=???, 4=out of probation, 8=loaded
    // 1B user[1] nrefs number of references to this seg
    //   decremented in the __OvrAllocateSpace
    // 1C user[2:3] __OvrLoadList, points to next heap segh
    // 1E user[4:5] also a segment
    byte[/*6*/] user = new byte[6];

    // switch table
    //fbov_trap_t dispatch[];

    BorlandTrap[] traps;
    ByteBuffer program;
    short[] fixups;
}

public class LoadBorlandOverlays extends GhidraScript {
    static final byte FIXUP_FUNREF = 0x1;
    static final byte X86_JMP = (byte) 0xEA;

    static final short MZ_MAGIC = 0x5A4D;
    static final short MZ_HDR_SZ = 0x1C;
    static final short MZ_PGSZ = 512;

    public static short LE(short value) {
        return Short.reverseBytes(value);
    }

    public static int LE(int value) {
        return Integer.reverseBytes(value);
    }

    @Override
    protected void run() throws Exception {
        File file = askFile("Select executable...", "OK");
        print(file.toString());

        short base = (short)askInt("Program base segment", "Please enter base segment");

        try (RandomAccessFile reader = new RandomAccessFile(file, "r")) {
            MzHeader header = readMzHeader(reader);

            int mzextsz = header.lfarlc - MZ_HDR_SZ;
            assert mzextsz > 0;

            BorlandMzExtension be = readBorlandMzExtension(reader);

            printf("Has Borland header (TLINK v%d.%d)\n", be.version >>> 4, be.version & 0xf);

            int fullPagesCount = header.cblp != 0 ? header.cp - 1 : header.cp;
            int loadedSize = fullPagesCount * MZ_PGSZ + header.cblp;

            int startOffset = header.cparhdr * 0x10;

            long extraSize = reader.getChannel().size() - loadedSize;

            int fbovHeaderOffset = (loadedSize + 15) / 16 * 16;

            BorlandFileHeader fbov = readBorlandFileHeaderAt(reader, fbovHeaderOffset);

            assert BorlandFileHeader.SIZE < extraSize && fbov.id[0] == BorlandFileHeader.FB_FB && fbov.id[1] == BorlandFileHeader.FB_OV;

            fbov.size += 16;

            printf("Size of Borland FBOV extra: %dB\n", fbov.size);
            printf("Number of segments: %d\n", fbov.nsegs);
            printf("The __SEGTABLE__ is at 0x%X\n", fbov.stofs);

            BorlandSegmentEntry[] entries = readBorlandSegmentEntriesAt(reader, fbov.stofs, fbov.nsegs);

            BorlandOverlayHeaderRecord[] overlays = new BorlandOverlayHeaderRecord[entries.length];

            for (int i = 0; i < entries.length; i++) {
                BorlandSegmentEntry entry = entries[i];

                if ((entry.flags & BorlandSegmentEntry.FBOV_OVR) == 0) {
                    continue;
                }

                int offset = startOffset + entry.seg * 16;

                overlays[i] = readBorlandOverlayHeaderRecordAt(reader, offset, fbovHeaderOffset);
            }

            Memory memory = currentProgram.getMemory();

            //relocate
            int destSeg = 0x5000; // TODO: Pick better base segment based on used memory.

            for (int i = 0; i < entries.length; i++) {
                BorlandSegmentEntry entry = entries[i];
                BorlandOverlayHeaderRecord overlay = overlays[i];

                if ((entry.flags & BorlandSegmentEntry.FBOV_OVR) == 0) {
                    continue;
                }

                int srcSeg = entry.seg + base + 2; // TODO: Not sure why this +2 offset is necessary.

                printf("Overlay %04x\n", srcSeg);

                ByteBuffer program = overlay.program;

                println("Rebasing FBOV fixups...");

                printf("Fixups: %d\n", overlay.fixups.length);
                for (int j = 0; j < overlay.fixups.length; j++) {
                    short fixup = overlay.fixups[j];

                    int sf = LE(program.getShort(fixup));
                    int flags = sf & 7; //fixup flags
                    short rseg = (short) (entries[sf >> 3].seg + base);

                    program.putShort(fixup, LE(rseg));

//                    printf("- program[%x]: %04x => %04x\n", fixup, sf, rseg);

                    if ((flags & FIXUP_FUNREF) != 0) {
                        println("FIXME: merge function reference reloc!!!");
                        //__OvrFixupFunref(rseg,*(uint8_t*)&p[q[i]]);
                    }
                }

                IntIntHashtable segmentMap = new IntIntHashtable();

                try (ByteArrayInputStream input = new ByteArrayInputStream(program.array())) {
                    MemoryBlock block = memory.createInitializedBlock(
                            String.format("ovr_%04x_%04x", srcSeg, destSeg),
                            toAddr(destSeg << 4),
                            input,
                            overlay.codesz,
                            monitor,
                            false
                    );
                    block.setWrite(true);
                    block.setExecute(true);

                    segmentMap.put(srcSeg, destSeg);
                }

                destSeg += (overlay.codesz + 15) / 16;

                println("Untrapping the FBOV stub headers...");

                FunctionManager functionManager = currentProgram.getFunctionManager();
                Namespace globalNS = currentProgram.getGlobalNamespace();
                List<DisassembleCommand> cmds = new ArrayList<>(overlay.traps.length * 2);

                printf("Traps: %d\n", overlay.traps.length);
                //untrap trampoulines
                for (int j = 0; j < overlay.traps.length; j++) {
                    BorlandTrap trap = overlay.traps[j];

                    int overlaySeg = segmentMap.get(srcSeg);
//                    printf("- %04x:%04x => %04x:%04x\n", srcSeg, j * 5, overlaySeg, trap.ofs);

                    byte[] b = new byte[]{
                            X86_JMP,
                            (byte) trap.ofs,
                            (byte) (trap.ofs >> 8),
                            (byte) overlaySeg,
                            (byte) (overlaySeg >> 8),
                    };

                    Address start = toAddr((srcSeg << 4) + j * 5);

                    AddressSet addressSet = new AddressSet(start, start.add(4));
                    clearListing(addressSet);
                    setBytes(addressSet.getMinAddress(), b);

                    // Create function at the new segment.
                    Address fnAddress = toAddr((overlaySeg << 4) + trap.ofs);
                    Function fn = createFunction(fnAddress, String.format("FUN_%04x_%04x", overlaySeg, trap.ofs));

                    // Remove existing thunk function.
                    removeFunctionAt(addressSet.getMinAddress());

                    // Create new thunk function.
                    functionManager.createThunkFunction(
                            String.format("thunk_%s", fn.getName()),
                            globalNS,
                            addressSet.getMinAddress(),
                            addressSet,
                            fn,
                            SourceType.USER_DEFINED
                    );

                    cmds.add(new DisassembleCommand(addressSet, addressSet, true));
                    cmds.add(new DisassembleCommand(fnAddress, null, true));
                }

                for (DisassembleCommand cmd : cmds) {
                    cmd.applyTo(currentProgram, monitor);
                }
            }
        }
    }

    private static BorlandOverlayHeaderRecord readBorlandOverlayHeaderRecordAt(RandomAccessFile reader, int offset, int fbovHeaderOffset) throws IOException {
        reader.seek(offset);

        BorlandOverlayHeaderRecord overlay = new BorlandOverlayHeaderRecord();

        overlay.code[0] = reader.readByte();
        overlay.code[1] = reader.readByte();
        overlay.saveret = LE(reader.readShort());
        overlay.fileofs = LE(reader.readInt());
        overlay.codesz = LE(reader.readShort());
        overlay.fixupsz = LE(reader.readShort());
        overlay.jmpcnt = LE(reader.readShort());
        overlay.link = LE(reader.readShort());
        overlay.bufseg = LE(reader.readShort());
        overlay.retrycnt = LE(reader.readShort());
        overlay.next = LE(reader.readShort());
        overlay.ems_page = LE(reader.readShort());
        overlay.ems_ofs = LE(reader.readShort());
        reader.read(overlay.user);

        overlay.traps = new BorlandTrap[overlay.jmpcnt];

        int cofs32 = fbovHeaderOffset + 16 + overlay.fileofs;

        byte[] codeBuf = new byte[overlay.codesz];
        reader.seek(cofs32);
        reader.read(codeBuf);

        overlay.program = ByteBuffer.wrap(codeBuf);

        overlay.fixups = new short[overlay.fixupsz / 2];
        //FBOV fixups are stored after the segment's code
        for (int i = 0; i < overlay.fixupsz / 2; i++) {
            overlay.fixups[i] = LE(reader.readShort());
        }

        for (int i = 0; i < overlay.traps.length; i++) {
            BorlandTrap trap = overlay.traps[i] = new BorlandTrap();

            long trapOfs = offset + BorlandOverlayHeaderRecord.SIZE + (long) i * BorlandTrap.SIZE;
            reader.seek(trapOfs);

            trap.code[0] = reader.readByte();
            trap.code[1] = reader.readByte();
            trap.ofs = LE(reader.readShort());
            trap.pad = reader.readByte();
        }

        return overlay;
    }

    private static BorlandSegmentEntry[] readBorlandSegmentEntriesAt(RandomAccessFile reader, int offset, int count) throws IOException {
        reader.seek(offset);

        BorlandSegmentEntry[] entries = new BorlandSegmentEntry[count];

        for (int i = 0; i < entries.length; i++) {
            BorlandSegmentEntry entry = entries[i] = new BorlandSegmentEntry();

            entry.seg = LE(reader.readShort());
            entry.maxoff = LE(reader.readShort());
            entry.flags = LE(reader.readShort());
            entry.minoff = LE(reader.readShort());
        }

        return entries;
    }

    private static BorlandFileHeader readBorlandFileHeaderAt(RandomAccessFile reader, int offset) throws IOException {
        reader.seek(offset);

        BorlandFileHeader fbov = new BorlandFileHeader();

        fbov.id[0] = reader.readShort();
        fbov.id[1] = reader.readShort();
        fbov.size = LE(reader.readInt());
        fbov.stofs = LE(reader.readInt());
        fbov.nsegs = LE(reader.readInt());

        return fbov;
    }

    private static BorlandMzExtension readBorlandMzExtension(RandomAccessFile reader) throws IOException {
        BorlandMzExtension be = new BorlandMzExtension();

        be.unk0 = reader.readShort();
        be.id = reader.readByte();
        be.version = reader.readByte();
        be.unk1 = reader.readShort();
        reader.read(be.unk2);

        assert be.unk0 == 0x0001 && be.id == 0xFB && (be.unk1 == 0x726A || be.unk1 == 0x6A72);

        return be;
    }

    private static MzHeader readMzHeader(RandomAccessFile reader) throws IOException {
        MzHeader header = new MzHeader();

        header.magic = reader.readShort();
        assert header.magic == MZ_MAGIC;

        header.cblp = LE(reader.readShort());
        header.cp = LE(reader.readShort());
        header.crlc = LE(reader.readShort());
        header.cparhdr = LE(reader.readShort());
        header.minalloc = LE(reader.readShort());
        header.maxalloc = LE(reader.readShort());
        header.ss = LE(reader.readShort());
        header.sp = LE(reader.readShort());
        header.csum = LE(reader.readShort());
        header.ip = LE(reader.readShort());
        header.cs = LE(reader.readShort());
        header.lfarlc = LE(reader.readShort());
        header.ovno = LE(reader.readShort());

        return header;
    }
}
