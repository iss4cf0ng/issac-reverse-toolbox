// Dump a payload from memory using a known start address.
// Supports manual size input or automatic size detection (0 = auto).
// Auto mode dumps until the end of the current memory block.
//
// Useful for extracting embedded payloads, unpacked code, or shellcode.
//
// Url: https://github.com/iss4cf0ng/issac-reverse-toolbox/blob/main/Ghidra/DumpPayload.java
//@author iss4cf0ng/ISSAC
//@category Memory
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.io.File;
import java.io.FileOutputStream;

public class DumpPayload extends GhidraScript {

    @Override
    public void run() throws Exception {

        Address startAddr = askAddress(
            "Payload Dumper",
            "Start address (e.g. 0x00400000): "
        );

        int size = askInt(
            "Payload Dumper",
            "Size in bytes (0 = auto to end of block): "
        );

        File output = askFile("Save payload", "Save");

        Memory mem = currentProgram.getMemory();

        //Auto size
        if (size == 0) {
            MemoryBlock block = mem.getBlock(startAddr);

            if (block == null) {
                printerr("[-] Address is not inside any memory block.");
                return;
            }

            size = (int)(block.getEnd().subtract(startAddr) + 1);

            println("[*] Auto size detected: " + size + " bytes");
        } else {
            Address endAddr = startAddr.add(size - 1);
            println("[*] Dump range: " + startAddr + " - " + endAddr);
        }

	    //Read memory
        byte[] payload;

        try {
            payload = getBytes(startAddr, size);
        } catch (Exception e) {
            printerr("[-] Failed to read memory: " + e.getMessage());
            return;
        }

        //Write file
        try (FileOutputStream fs = new FileOutputStream(output)) {
            fs.write(payload);
            println("[+] Saved payload: " + output.getAbsolutePath());
        } catch (Exception e) {
            printerr("[-] Failed to write file: " + e.getMessage());
        }
    }
}