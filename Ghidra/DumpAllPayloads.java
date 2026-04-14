// Dump all embedded payloads from memory automatically.
//
// Useful for extracting embedded payloads, unpacked code, or shellcode.
//
// Url: https://github.com/iss4cf0ng/issac-reverse-toolbox/blob/main/Ghidra/DumpAllPayloads.java
//@author iss4cf0ng/ISSAC
//@category Memory
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

import java.io.*;
import java.util.zip.Inflater;

public class DumpAllPayloads extends GhidraScript {

    @Override
    public void run() throws Exception {

        println("[*] Scanning .rsrc for zlib...");

        MemoryBlock rsrc = null;

        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.getName().toLowerCase().contains("rsrc")) {
                rsrc = b;
                break;
            }
        }

        if (rsrc == null) {
            println("[-] .rsrc not found");
            return;
        }

        byte[] data = new byte[(int) rsrc.getSize()];
        rsrc.getBytes(rsrc.getStart(), data);

        println("[+] .rsrc size = " + data.length);

        int count = 0;

        for (int i = 0; i < data.length - 2; i++) {

            // 找 zlib header
            if ((data[i] == 0x78) &&
                (data[i+1] == (byte)0xDA || data[i+1] == (byte)0x9C)) {

                println("[+] Found zlib at offset: " + i);

                byte[] out = decompress(data, i);

                if (out == null || out.length == 0) {
                    println("[-] Decompress failed");
                    continue;
                }

                boolean isPE = out.length > 2 &&
                               out[0] == 'M' &&
                               out[1] == 'Z';

                String name = "dump_" + count + (isPE ? ".pe_file" : ".bin");

                File f = askFile("Save " + name, "Save");

                FileOutputStream fos = new FileOutputStream(f);
                fos.write(out);
                fos.close();

                println("[+] Saved: " + name);

                count++;
            }
        }

        println("[*] Done. Found " + count + " zlib streams.");
    }

    private byte[] decompress(byte[] data, int offset) {
        try {
            Inflater inflater = new Inflater();
            inflater.setInput(data, offset, data.length - offset);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];

            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0) break;
                bos.write(buf, 0, n);
            }

            inflater.end();
            return bos.toByteArray();

        } catch (Exception e) {
            return null;
        }
    }
}