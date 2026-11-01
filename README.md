# Gadget Probe

A phone app for fault-finding small gadgets — smart lamps, LED controllers, Bluetooth toys, speakers, dev boards.

**Open / install:** https://m9r1u5.github.io/My/ (Android: Chrome → Install. iPhone: use the Bluefy browser for Bluetooth.)

## What it does
- **Bluetooth:** scan, connect, list every service and characteristic, read, write (hex or text), watch notifications, save working commands as buttons, and sweep a byte through 00–FF to discover unknown commands.
- **App / File:** open an old gadget app (.apk/.xapk/.apks) or firmware .bin on the phone. Pulls out Bluetooth UUIDs, possible hex commands, web/MQTT addresses and chip/platform clues. Nothing is uploaded.
- **USB Serial:** serial monitor for Arduino/ESP32/CH340/CP2102 boards over an OTG cable (Chrome).
- **Tools:** hex/text/decimal/base64 converter, checksum and CRC finder, colour-to-RGB bytes.
- **Log:** everything sent and received, with copy and share.

Works offline once opened. Single file app: `index.html`, `manifest.json`, `sw.js`, icons.
