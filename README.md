# e2-kobo-flasher

Make a **HANLinyue E2 Control** Bluetooth page turner work with a **Kobo** e-reader, from a **Mac**, over the USB cable. No Windows PC, no opening the remote.

Many E2 Control remotes ship with a firmware that behaves like a mouse and volume keys. On a Kobo they pair but do not turn pages. The vendor publishes an official **KOBO firmware**, but their updater only runs on Windows. This is a small, free command-line tool that writes the vendor's own official firmware from macOS.

Tested on one E2 Control with a **Kobo Libra Colour**: after flashing, the middle key turns to the next page and the top key to the previous page. The bottom key does nothing on that Kobo.

> **Use at your own risk.** This is an unofficial tool, not made or supported by HANLinyue or Kobo. It has been tested on one remote. It refuses to write to anything that does not look like an E2 Control, and an interrupted update can be resumed, but no tool can promise a remote will never be damaged.

## What you need

- A Mac with `python3` (type `python3 --version` in Terminal; if macOS offers to install the command line developer tools, accept).
- A USB **data** cable for the remote (some charge-only cables will not work).
- The remote switched on (side switch in any position except OFF).

Nothing else to install: the tool uses only Python's standard library.

## Steps

1. Download the tool and open Terminal in the same folder:

   ```sh
   curl -LO https://raw.githubusercontent.com/ptbandeira/e2-kobo-flasher/main/e2flash.py
   ```

2. Connect the remote with the cable and check that it is found:

   ```sh
   python3 e2flash.py info
   ```

3. Optional, read-only: see which firmware is installed now. The remote restarts in update mode for a moment and comes back.

   ```sh
   python3 e2flash.py check
   ```

4. Write the KOBO firmware. It asks you to type `YES` first. Keep the cable connected until it says `update ok`.

   ```sh
   python3 e2flash.py flash kobo
   ```

5. Unplug the remote, then:
   - push the side switch to **Up and Down mode** (the top position, with the up/down arrows symbol);
   - if the remote was paired before (to your Mac, phone or the Kobo), remove it from that device's Bluetooth list;
   - hold the **Home** key for 15 seconds: this clears old pairings;
   - on the Kobo, turn on Bluetooth, choose **E2 Control** and pair.

The vendor notes that the **Kobo Libra 2** needs a plugin before pages turn. If pages do not turn on your model, see [kobo-btpt](https://github.com/tsowell/kobo-btpt), which maps Bluetooth keys to page turns.

## Going back

The vendor's other official builds can be written the same way:

```sh
python3 e2flash.py flash touch    # Android e-readers / "Entertainment"
python3 e2flash.py flash scaled   # phones, tablets, PPT, short video, music
```

The exact firmware your remote shipped with cannot be backed up (the remote has no command to read its memory), and older builds are not always still on the vendor's server. `check` tells you how close the installed firmware is to each official build.

## If something goes wrong

- **The update stopped half way** (cable pulled, Mac asleep): run the same `flash` command again. The remote waits in update mode and the tool picks it up.
- **The remote is stuck in update mode** and you do not want to write: `python3 e2flash.py reboot`.
- **"No E2 Control found"**: try another cable or USB port, and make sure the side switch is not on OFF.
- **"SHA-512 mismatch"**: the vendor changed a file on their server. Nothing was written. Please open an issue.

## Safety checks

Before writing anything the tool:

- downloads the firmware from the vendor's own server and checks it against a SHA-512 hash pinned in the tool;
- checks that the bootloader reports the E2 Control memory layout;
- checks that the installed firmware matches a known E2 Control build;
- asks you to type `YES`.

While writing it follows the vendor updater's order: the loader is never touched, the header block is written last, and every 4 KB block is read back and compared. If any block differs, the remote stays in update mode so you can run it again.

## How it works

In normal mode the remote is a USB serial port that speaks JSON. The command `{"o":"JUMPBOOT"}` restarts it into update mode, where it becomes a USB HID device with 64-byte reports. The update protocol (init, block CRC read, erase, write, reboot, with a small XOR and CRC-16/XMODEM framing) is documented at the top of [`e2flash.py`](e2flash.py). It was worked out from the vendor's Windows updater for interoperability; no vendor code or firmware is included in this repository.

Windows users can simply use the vendor's own app.

## License

MIT. HANLinyue, E2 Control and Kobo are trademarks of their owners; this project is not affiliated with them.
