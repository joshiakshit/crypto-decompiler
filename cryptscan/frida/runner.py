from __future__ import annotations

from pathlib import Path

_HOOKS = Path(__file__).parent / "hooks.js"


def verify(package: str, device: str | None = None) -> None:
    try:
        import frida
    except ImportError as exc:
        raise RuntimeError(
            "Frida is not installed. Install it with: pip install cryptscan[dynamic]"
        ) from exc

    dev = frida.get_device(device) if device else frida.get_usb_device()
    pid = dev.spawn([package])
    session = dev.attach(pid)
    script = session.create_script(_HOOKS.read_text())
    script.on("message", lambda message, data: print(message.get("payload")))
    script.load()
    dev.resume(pid)
    input("Hooking Cipher and MessageDigest. Press Enter to stop.\n")
    session.detach()
