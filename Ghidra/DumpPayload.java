//Dump payload with known address + size
//Url: https://github.com/iss4cf0ng/issac-reverse-toolbox/Ghidra/DumpPayload.java
//@author iss4cf0ng/ISSAC
//@category Memory
//@keybinding
//@menupath
//@toolbar 
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.sourcemap.*;
import ghidra.program.model.lang.protorules.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.ISF.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.File;
import java.io.FileOutputStream;

public class DumpPayload extends GhidraScript {

    @Override
    public void run() throws Exception {

        Address startAddr = askAddress("Payload dumper", "Address (e.g. 0x00400000): ");
        int size = askInt("Payload dumper", "Size (bytes): ");
        File output = askFile("Save payload", "Save");

        byte[] payload;

        try {
            payload = getBytes(startAddr, size);
        } catch (Exception e) {
            printerr("[-] Read memory failed: " + e.getMessage());
            return;
        }

        try (FileOutputStream fs = new FileOutputStream(output)) {
            fs.write(payload);
            println("[+] Saved payload: " + output.getAbsolutePath());
        } catch (Exception e) {
            printerr("[-] Write file failed: " + e.getMessage());
        }
    }
}